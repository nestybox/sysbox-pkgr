#!/bin/bash -x

#
# Copyright 2019-2021 Nestybox, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Script to configure the kubelet with the CRI-O runtime on a host
#

set -o errexit
set -o pipefail
set -o nounset

run_crio_deploy_k8s="/run/crio-deploy-k8s"
runtime=""

kubelet_bin="/usr/bin/kubelet"
crictl_bin="/usr/local/bin/crio-deploy-k8s-crictl"

function die() {
   msg="$*"
   echo "ERROR: $msg" >&2
   exit 1
}

function get_kubelet_bin() {
	local tmp=$(systemctl show kubelet | grep "ExecStart=" | cut -d ";" -f1)
	kubelet_bin=${tmp#"ExecStart={ path="}
}

function replace_cmd_option {
	cmd_opts=$1
	opt=$2
	want_val=$3

	read -a curr_args <<< ${cmd_opts}
	declare -a new_args

	found_opt=false

	for arg in "${curr_args[@]}"; do

		new_arg=$arg

		if [[ "$arg" == "$opt="* ]]; then
			found_opt=true
			val=${arg#"$opt="}
			if [[ "$val" != "$want_val" ]]; then
				new_arg="$opt=$want_val"
			fi
		fi

		new_args+=($new_arg)
	done

	result=$(printf "%s " "${new_args[@]}")

	if ! $found_opt; then
		result="$result $opt=$want_val"
	fi

	echo $result
}

function get_kubelet_env_files() {
	systemctl show kubelet | grep EnvironmentFile | awk '{ print $1 }' | cut -d"=" -f2 | tr "\n" " "
}

function get_kubelet_env_var() {
	local env_var=$(systemctl show kubelet | grep ExecStart= | cut -d ";" -f2 | sed -e 's@argv\[\]=${kubelet_bin}@@g' | awk '{print $NF}')
	env_var=${env_var#"$"}
	echo $env_var
}

function get_kubelet_service_file() {
	systemctl show kubelet | grep "^FragmentPath" | cut -d "=" -f2
}

# Creates a systemd service unit "drop-in" file for the kubelet, configured to
# use the $env_var from the given $env_file.
function add_systemd_dropin_file() {
	local env_file=$1
	local env_var=$2

	local kubelet_service_file=$(get_kubelet_service_file)
	local exec_start=$(grep "^ExecStart=" $kubelet_service_file)

	mkdir -p "/etc/systemd/system/kubelet.service.d"

	cat > "/etc/systemd/system/kubelet.service.d/01-kubelet.conf" << EOF
[service]
EnvironmentFile=-$env_file
ExecStart=
$exec_start \$$env_var
EOF

	echo "Created systemd drop-in file for kubelet (/etc/systemd/system/kubelet.service.d/01-kubelet.conf)"
}

# Adds the kubelet config in the given file; the given $env_file may or may not
# exist. If it does not exist, this function will create it and add or replace
# a definiton for $env_var
function add_kubelet_env_var() {
	local env_file=$1
	local env_var=$2

	# If the extra args file does not have the extra args/opts, add them as needed
	if [ ! -f "$env_file" ]; then
		mkdir -p $(dirname "$env_file")
		touch "$env_file"
		echo "Created kubelet env file $env_file"
	fi

	if ! grep -q "$env_var" "$env_file"; then
		echo "$env_var=\"\"" >> "$env_file"
	fi

	replace_kubelet_env_var "$env_file" "$env_var"
}

# Replaces the kubelet config in the given file; the given $env_file is assumed
# to exist and have a definition for $env_var in it already.
function replace_kubelet_env_var() {
	local env_file=$1
	local env_var=$2

	readarray -t opts < ${run_crio_deploy_k8s}/crio-kubelet-options

	# add newline at end of $env_file if not present
	sed -i '$a\' "$env_file"

	touch tmp.txt

	while read -r line; do
		new_line=$line

		# ignore comment lines
		if [[ "$line" == "#*" ]]; then
			continue
		fi

		# replace the options in the line(s) starting with $env_var
		if [[ "$line" == "$env_var="* ]]; then

			line_prefix="$env_var"

			# Handle quoted or unquoted variable definitions ($env_var="..." or $env_var=...)
			if [[ "$line" == "$line_prefix=\""* ]]; then
				line_opts=$(echo $line | cut -d'"' -f2)
			else
				line_opts=${line#"$line_prefix"}
			fi

			for opt in "${opts[@]}"; do
				opt_name=$(echo $opt | cut -d"=" -f1)
				opt_val=$(echo $opt | cut -d"=" -f2)
				if [[ "$opt_name" != "" ]] && [[ "$opt_val" != "" ]]; then
					line_opts=$(replace_cmd_option "$line_opts" "$opt_name" "$opt_val")
				fi
			done

			new_line="$line_prefix=\"$line_opts\""
		fi

		echo $new_line >> tmp.txt

	done < "$env_file"
	mv tmp.txt "$env_file"

	echo "Modified kubelet env var $env_var in $env_file"
}

function backup_orig_config() {
	local env_file=$1
	local config_file="${run_crio_deploy_k8s}/config"

	mkdir -p "$run_crio_deploy_k8s"
	echo "kubelet_env_file=${env_file}" > "$config_file"
	cp "$env_file" "${run_crio_deploy_k8s}/kubelet.orig"
}

# Configures the kubelet to use CRI-O, by modifying the systemd unit files that
# contain the arguments passed to kubelet.
function config_kubelet() {

	local kubelet_env_files=$(get_kubelet_env_files)

	# If systemd shows no kubelet environment files, let's create one
	if [[ "$kubelet_env_files" == "" ]]; then
		kubelet_env_file="/etc/default/kubelet"
		kubelet_env_var="KUBELET_EXTRA_ARGS"
		backup_orig_config "$kubelet_env_file"
		add_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"
		add_systemd_dropin_file "$kubelet_env_file" "$kubelet_env_var"
		return
	fi

	# If no kubelet env var was found, let's use our default one
	local kubelet_env_var=$(get_kubelet_env_var)
	if [[ "$kubelet_env_var" == "" ]]; then
		kubelet_env_var="KUBELET_EXTRA_ARGS"
	fi

	# If systemd shows kubelet environment files, let's check if they exist and
	# if so replace the env variable ($kubelet_env_var)
	for kubelet_env_file in $kubelet_env_files; do
		if [ -f "$kubelet_env_file" ]; then
			if grep -q "$kubelet_env_var" "$kubelet_env_file"; then
				backup_orig_config "$kubelet_env_file"
				replace_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"
				return
			fi
		fi
	done

	# Either the kubelet env file does not exist, or it exists but does not
	# contain the $kubelet_env_var; lets create the file and/or add the
	# $kubelet_env_var to it.
	kubelet_env_file=$(echo "$kubelet_env_files" | awk '{print $NF}')

	if [ ! -f "$kubelet_env_file" ]; then
		touch "$kubelet_env_file"
	fi

	backup_orig_config "$kubelet_env_file"
	add_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"

	# Ask systemd to reload it's config
	systemctl daemon-reload
}

function restart_kubelet() {
	echo "Restarting Kubelet ..."
	systemctl restart kubelet
}

function stop_kubelet() {
	echo "Stopping Kubelet ..."
	systemctl stop kubelet
}

function get_runtime() {
	set +e
	runtime=$(systemctl status kubelet | egrep ${kubelet_bin} | egrep -o "container-runtime-endpoint=\S*" | cut -d '=' -f2)
	set -e

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

# Wipe out all the pods managed by the given container runtime (dockershi, containerd, etc.)
function clean_runtime_state() {
	local runtime=$1

	# Collect all the existing podIds as seen by crictl.
	podList=$($crictl_bin --runtime-endpoint ${runtime} ps | awk 'NR>1 {print $NF}')

   # Cleanup the pods; turn off errexit in these steps as we don't want to
	# interrupt the process if any of the instructions fail for a particular
	# pod.
	set +e
	for pod in ${podList}; do
		ret=$($crictl_bin --runtime-endpoint "${runtime}" stopp ${pod})
		if [ $? -ne 0 ]; then
			echo "Failed to stop pod ${pod}: $ret"
		fi

		ret=$($crictl_bin --runtime-endpoint "${runtime}" rmp ${pod})
		if [ $? -ne 0 ]; then
			echo "Failed to remove pod ${pod}: $ret"
		fi
	done
	set -e
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
	   die "This script must be run as root"
	fi

	get_runtime

	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	get_kubelet_bin

	# The ideal sequence is to stop the kubelet, cleanup all pods with the
	# existing runtime, reconfig the kubelet, and restart it. But if the runtime
	# is dockershim this does not work well because after stopping the kubelet
	# the dockershim also stops. Thus for dockershim we use a slightly different
	# sequence which is less ideal because it cleans up pods while kubelet still
	# runs, meaning that the cleanup pods can be replaced by kubelet, still using
	# the old runtime. However, the cleanup is immediately followed by a kubelet
	# restart, so chances are kubelet will reset before it's had a chance to
	# restore pods using the old runtime.

	if [[ ${runtime} =~ "dockershim" ]]; then
		clean_runtime_state $runtime
		config_kubelet
		restart_kubelet
	else
		stop_kubelet
		clean_runtime_state $runtime
		config_kubelet
		restart_kubelet
	fi

}

main "$@"
