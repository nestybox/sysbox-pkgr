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

var_lib_sysbox_deploy_k8s="/var/lib/sysbox-deploy-k8s"
crictl_bin="/usr/local/bin/sysbox-deploy-k8s-crictl"
crio_conf_file="/etc/crio/crio.conf"
crio_socket="/var/run/crio/crio.sock"
crio_runtime="unix://${crio_socket}"
kubelet_bin=""
runtime=""

# Container's default restart-policy mode (i.e. no restart).
kubelet_ctr_restart_mode="no"

function die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function get_kubelet_bin() {
	local tmp=$(systemctl show kubelet | grep "ExecStart=" | cut -d ";" -f1)
	tmp=${tmp#"ExecStart={ path="}
	echo "$tmp" | xargs
}

function replace_cmd_option {
	cmd_opts=$1
	opt=$2
	want_val=$3

	read -a curr_args <<<${cmd_opts}
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

	if ! echo ${env_var} | grep -q "^\\$"; then
		echo ""
		return
	fi

	env_var=${env_var#"$"}
	echo ${env_var}
}

function get_kubelet_env_var_all() {
	systemctl show kubelet.service | egrep "ExecStart=" |
		cut -d ";" -f2 | sed -e 's@argv\[\]=${kubelet_bin}@@g' |
		sed 's/ /\n/g' | egrep "^\\$"
}

# Notice the contrast with the above function. Here we return ExecStart
# 'attributes' (or parameters) and not 'env-vars' as it's the case above.
#
# TODO: Fix this function: description doesn't match implementation. Also,
# it's not being used.
function get_kubelet_exec_attrib_all() {
	local attr=$1

	systemctl show kubelet.service | egrep "ExecStart=" |
		sed -e 's@argv\[\]=${kubelet_bin}@@g' | sed 's/ /\n/g' |
		egrep "^--${attr}" | cut -d"=" -f2
}

function get_kubelet_exec_attr_val() {
	local attr=$1

	local exec_line=$(get_kubelet_exec_line)
	if [ -z "$exec_line" ]; then
		return
	fi

	echo "$exec_line" | sed 's/ /\n/g' | egrep "^--${attr}" | cut -d"=" -f2
}

function get_kubelet_service_file() {
	systemctl show kubelet | grep "^FragmentPath" | cut -d "=" -f2
}

function get_kubelet_service_dropin_file() {
	systemctl show kubelet | grep "^DropInPaths" | cut -d "=" -f2
}

function get_kubelet_service_execstart() {
	# Note that "no-pager" attribute is necessary to prevent systemctl's output
	# from being truncated in cases with a long set of command attributes.
	systemctl show kubelet.service -p ExecStart --no-pager | cut -d";" -f2 | sed 's@argv\[\]=@@' | sed 's@^ @@'
}

# Creates a systemd service unit "drop-in" file for the kubelet, configured to
# use the $env_var from the given $env_file.
function add_systemd_dropin_file() {
	local env_file=$1
	local env_var=$2

	local kubelet_sysbox_dropin="/etc/systemd/system/kubelet.service.d/01-kubelet-sysbox-dropin.conf"
	local kubelet_service_file=$(get_kubelet_service_file)
	local exec_start=$(get_kubelet_service_execstart)

	mkdir -p "/etc/systemd/system/kubelet.service.d"

	cat >"${kubelet_sysbox_dropin}" <<EOF
[Service]
EnvironmentFile=-$env_file
ExecStart=
ExecStart=$exec_start \$$env_var
EOF

	# Ask systemd to reload it's config.
	systemctl daemon-reload

	echo "Created systemd drop-in file for kubelet ($kubelet_sysbox_dropin)"
}

# Adds a new env-var to kubelet's service drop-in file. This function is useful
# in scenarios where no env-var is found as the last element in the list of
# ExecStart attributes within the kubelet service file. This is the case when
# kubelet's execution attributes are explicitly defined as part of the ExecStart
# unit component (e.g. terraform k8s cluster deployments).
function add_systemd_kubelet_env_var() {
	local env_file=$1
	local env_var=$2
	local kubelet_systemd_dropin="${var_lib_sysbox_deploy_k8s}/kubelet_systemd_dropin"

	# Find kubelet's drop-in file (if any), create it otherwise.
	local dropin_file=$(get_kubelet_service_dropin_file)
	if [[ "${dropin_file}" == "" ]]; then
		add_systemd_dropin_file "$env_file" "$env_var"
		return
	fi

	# Skip if the env_var is already being referenced in kubelet's drop-in file.
	if grep -q "^ExecStart=${kubelet_bin}.*${kubelet_env_var}" $dropin_file; then
		return
	fi

	# Backup original service file.
	mkdir -p "$var_lib_sysbox_deploy_k8s"
	cp "$dropin_file" "${kubelet_systemd_dropin}"

	# Append env_var to dropin-file.
	sed -i "s@^ExecStart=${kubelet_bin}.*@& \$${env_var}@" "$dropin_file"

	# Ask systemd to reload it's config.
	systemctl daemon-reload

	echo "Appended $env_var to kubelet's systemd drop-in file ($dropin_file)"
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
		echo "$env_var=\"\"" >>"$env_file"
	fi

	replace_kubelet_env_var "$env_file" "$env_var"
}

# Replaces the kubelet config in the given file; the given $env_file is assumed
# to exist and have a definition for $env_var in it already.
function replace_kubelet_env_var() {
	local env_file=$1
	local env_var=$2

	readarray -t opts <${var_lib_sysbox_deploy_k8s}/crio-kubelet-options

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
				line_opts=${line#"$line_prefix="}
			fi

			set +e
			for opt in "${opts[@]}"; do
				opt_name=$(echo $opt | cut -d"=" -f1)
				opt_val=$(echo $opt | cut -d"=" -f2)
				if [[ "$opt_name" != "" ]] && [[ "$opt_val" != "" ]]; then
					if [[ $line_opts != "" ]]; then
						line_opts=$(replace_cmd_option "$line_opts" "$opt_name" "$opt_val")
					else
						# If there are no existing kubelet-config attrs to replace, then
						# simply take the crio-kubelet options being provided.
						line_opts="${opt_name}=${opt_val}"
					fi
				fi
			done
			set -e

			new_line="$line_prefix=\"$line_opts\""
		fi

		echo $new_line >>tmp.txt

	done <"$env_file"
	mv tmp.txt "$env_file"

	echo "Modified kubelet env var $env_var in $env_file"
}

function backup_orig_config() {
	local env_file=$1
	local config_file="${var_lib_sysbox_deploy_k8s}/config"

	mkdir -p "$var_lib_sysbox_deploy_k8s"

	if [ -f $env_file ]; then
		echo "kubelet_env_file=${env_file}" >"$config_file"
		cp "$env_file" "${var_lib_sysbox_deploy_k8s}/kubelet.orig"
	fi
}

# Configures the kubelet to use CRI-O, by modifying the systemd unit files that
# contain the arguments passed to kubelet.
function config_kubelet() {

	local kubelet_env_files=$(get_kubelet_env_files)

	# If systemd shows no kubelet environment files, let's create one.
	if [[ "$kubelet_env_files" == "" ]]; then
		local kubelet_env_file="/etc/default/kubelet"
		local kubelet_env_var="KUBELET_EXTRA_ARGS"
		backup_orig_config "$kubelet_env_file"
		add_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"
		add_systemd_dropin_file "$kubelet_env_file" "$kubelet_env_var"
		return
	fi

	# If no kubelet env var was found, let's use our default one.
	local kubelet_env_var=$(get_kubelet_env_var)
	if [[ "$kubelet_env_var" == "" ]]; then
		kubelet_env_var="KUBELET_EXTRA_ARGS"
		local kubelet_env_file=$(echo "$kubelet_env_files" | awk '{print $NF}')
		add_systemd_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"
	fi

	# If systemd shows kubelet environment files, let's check if they exist and
	# if so replace the env variable ($kubelet_env_var).
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
	local kubelet_env_file=$(echo "$kubelet_env_files" | awk '{print $NF}')

	if [ ! -f "$kubelet_env_file" ]; then
		touch "$kubelet_env_file"
	fi

	backup_orig_config "$kubelet_env_file"
	add_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"

	# Ask systemd to reload it's config
	systemctl daemon-reload
}

function get_flat_file() {
	local file=$1

	local flat_file=$(sed ':x; /\\$/ { N; s/\\\n//; tx }' $file | tr -s ' ')
	echo "$flat_file"
}

function get_kubelet_exec_line_docker() {

	local execstart_pre_line=$(systemctl show kubelet.service -p ExecStartPre --no-pager | egrep "docker run.*--name=kubelet" | cut -d";" -f2 | sed 's@argv\[\]=@@' | sed 's@^ @@' | xargs)
	if [ ! -z "$execstart_pre_line" ]; then
		echo "$execstart_pre_line"
		return
	fi

	local execstart_line=$(systemctl show kubelet.service -p ExecStart --no-pager | egrep "docker run.*--name=kubelet" | cut -d";" -f2 | sed 's@argv\[\]=@@' | sed 's@^ @@' | xargs)
	if [ ! -z "$execstart_line" ]; then
		echo "$execstart_line"
		return
	fi
}

function get_kubelet_exec_line_regular() {

	local execstart_pre_line=$(systemctl show kubelet.service -p ExecStartPre --no-pager | egrep "$kubelet_bin" | cut -d";" -f2 | sed 's@argv\[\]=@@' | sed 's@^ @@' | xargs)
	if [ ! -z "$execstart_pre_line" ]; then
		echo "$execstart_pre_line"
		return
	fi

	local execstart_line=$(systemctl show kubelet.service -p ExecStart --no-pager | egrep "$kubelet_bin" | cut -d";" -f2 | sed 's@argv\[\]=@@' | sed 's@^ @@' | xargs)
	if [ ! -z "$execstart_line" ]; then
		echo "$execstart_line"
		return
	fi
}

function get_kubelet_exec_line() {

	local execstart_line=$(get_kubelet_exec_line_docker)
	if [ ! -z "$execstart_line" ]; then
		echo "$execstart_line"
		return
	fi

	local execstart_line=$(get_kubelet_exec_line_regular)
	if [ ! -z "$execstart_line" ]; then
		echo "$execstart_line"
		return
	fi
}

# Our purpose in this function is to identify the kubelet systemd file that
# contains the ExecStart line matching the "exec_line" parameter being passed
# by the caller.
#
# Note that for this comparison logic to succeed we must take into account
# that the attributes displayed by "systemctl show" command, which serve to
# extract the "exec_line", are massaged by systemd and shown attending to this:
#
#  * Duplicated space characters are eliminated. That is, a single space char is
#    displayed between the ExecStart attributes.
#  * Single and double quote characters are also eliminated.
#
function get_kubelet_systemd_file_per_exec() {
	local exec_line=$1

	# Let's look first at the drop-in file first as it has more preference.
	#
	# TODO: What about scenarios with multiple dropin-files?
	local dropin_file=$(get_kubelet_service_dropin_file)
	if [ ! -z "$dropin_file" ]; then
		local flat_dropin_str=$(sed ':x; /\\$/ { N; s/\\\n//; tx }' $dropin_file | tr -s ' ' | tr -d \'\")
		if [[ "$flat_dropin_str" =~ "$exec_line" ]]; then
			echo "$dropin_file"
			return
		fi
	fi

	local service_file=$(get_kubelet_service_file)
	if [ ! -z "$service_file" ]; then
		local flat_service_str=$(sed ':x; /\\$/ { N; s/\\\n//; tx }' $service_file | tr -s ' ' | tr -d \'\")
		if [[ "$flat_service_str" =~ "$exec_line" ]]; then
			echo "$service_file"
			return
		fi
	fi
}

# Function adjusts the kubelet configuration to satisfy the demands of a docker
# based kubelet container managed by a systemd service.
#
# Two changes are needed in the exec instruction:
#
# * We must add /var/lib/containers bind-mount as kubelet interacts with files
#   in this path. For doing this we rely on the presence of /var/lib/docker as
#   a reference to the location where the /var/lib/containers mount must be
#   appended.
# * Also, We must append the passed env-var to the end of the exec instruction.
#   This env-var is epxected to hold all the crio-specific config parameters.
#
function adjust_kubelet_exec_docker_systemd() {
	local systemd_file=$1
	local env_var=$2

	local search_mode="on"
	local new_line

	# Let's make a backup copy of the original file.
	backup_config "$systemd_file" "kubelet_systemd_file"

	touch tmp.txt

	# Set IFS to nil to prevent file lines from being split (by default IFS is
	# set to \sp\t\n).
	IFS=''

	while read -r line; do
		new_line=$line

		if [[ "$search_mode" == "on" ]]; then
			if echo "$new_line" | egrep -q "^ExecStart.*=\S*kubelet " ||
				echo "$new_line" | egrep -q "^ExecStart.*=docker run"; then
				search_mode="found"
			fi
		fi

		# If the search pattern was already found, look for the different sections
		# of the exec instruction that we want to edit:
		#
		# * Multi-line /var/lib/docker: Append /var/lib/containers bind-mount.
		# * Single-line /var/lib/docker: Append /var/lib/containers bind-mount.
		# * Exec's last line: Append crio's env-var.
		if [[ "$search_mode" == "found" ]]; then

			if echo "$new_line" | egrep -q "\-v /var/lib/docker:/var/lib/docker:rw.*\\\\ *$"; then
				new_line=$(printf '%s\n  -v /var/lib/containers:/var/lib/containers:rw \\\n' "$new_line")

			elif echo "$new_line" | egrep -q "\-v /var/lib/docker:/var/lib/docker:rw.*$"; then
				new_line=$(echo $new_line | sed 's@-v /var/lib/docker:/var/lib/docker:rw@& -v /var/lib/containers:/var/lib/containers:rw@')

			elif ! echo "$new_line" | egrep -q "\\\\ *$"; then
				new_line=$(printf '%s \\\n  $%s' $new_line $env_var)
				search_mode="off"
			fi
		fi

		echo $new_line >>tmp.txt

	done <"$systemd_file"

	# Remember to unset IFS to avoid headaches down the road.
	unset IFS

	mv tmp.txt "$systemd_file"

	echo "Adjusted exec instruction in kubelet's service file \"$systemd_file\"."
}

function backup_config() {
	local file=$1
	local type=$2

	local config_file="${var_lib_sysbox_deploy_k8s}/config"

	mkdir -p "$var_lib_sysbox_deploy_k8s"

	if [ ! -f "$file" ]; then
		return
	fi

	if [[ "$type" == "kubelet_systemd_file" ]]; then
		echo "kubelet_systemd_file=${file}" >>"$config_file"
	elif [[ "$type" == "kubelet_env_file" ]]; then
		echo "kubelet_env_file=${file}" >>"$config_file"
	else
		return
	fi

	cp "$file" "${var_lib_sysbox_deploy_k8s}"/"${type}.orig"
}

# Configures the kubelet to use CRI-O, by modifying the systemd unit files that
# contain the arguments passed to kubelet.
function config_kubelet_docker_systemd() {

	local kubelet_env_var="KUBELET_CRIO_ARGS"

	# Identify the exec-line.
	local exec_line=$(get_kubelet_exec_line)
	if [ -z "$exec_line" ]; then
		die "No Kubelet execution instruction could be identified."
	fi

	# Identify the systemd file where the exec-line lives.
	local systemd_file=$(get_kubelet_systemd_file_per_exec "$exec_line")
	if [ -z "$systemd_file" ]; then
		die "No Kubelet systemd file could be identified for exec-line."
	fi

	# Adjust the ExecStart instruction to satisfy this setup.
	adjust_kubelet_exec_docker_systemd "$systemd_file" "$kubelet_env_var"

	# If systemd shows no kubelet environment files, let's create one.
	local kubelet_env_files=$(get_kubelet_env_files)
	local kubelet_env_file

	if [[ "$kubelet_env_files" == "" ]]; then
		kubelet_env_file="/etc/default/kubelet"
		touch "$kubelet_env_file"
	else
		kubelet_env_file=$(echo "$kubelet_env_files" | awk '{print $NF}')
	fi

	backup_config "$kubelet_env_file" "kubelet_env_file"

	# Append the new env-var content to one of the env-files.
	add_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"

	# Ask systemd to reload it's config.
	systemctl daemon-reload
}

# Function iterates through all the kubelet environment-files and all the
# environment-vars to search for the passed attribute and, if found, returns
# its associated value.
function get_crio_config_dependency() {
	local exec_attr=$1

	if [ -z "$exec_attr" ]; then
		echo ""
		return
	fi

	# Let's first look directly into the list of ExecStart attributes used
	# within the kubelet service file.
	local exec_attr_val=$(get_kubelet_exec_attr_val "$exec_attr")
	if [ ! -z "$exec_attr_val" ]; then
		echo "$exec_attr_val"
		return
	fi

	local env_files=$(get_kubelet_env_files)
	local env_vars=$(get_kubelet_env_var_all)

	# Let's now iterate through the matrix formed by all env-files and env-vars
	# to look for the exec attribute we are after. If found, return its value.
	for file in $env_files; do
		for var in $env_vars; do
			if [ ! -f "$file" ]; then
				continue
			fi

			var=${var#"$"}

			if grep -q "$var" "$file"; then
				local exec_attr_val=$(sed 's/ /\n/g' "$file" | egrep "^--${exec_attr}" | cut -d"=" -f2)
				echo "$exec_attr_val"
				return
			fi
		done
	done
}

# Function takes care of reconciliating operational attributes that can
# potentially overlap between 'kubelet' and 'crio' components. In this scenario
# we want to translate kubelet's overlapping attribute to the one understood by
# crio's config-parser, so that both components operate in-sync. For lack of a
# better word, we refer to these potentially-overlapped attributes as crio's
# 'config-dependencies'.
#
# The following config-dependencies have been identified so far:
#
# * --pod-infra-container-image: Initially conceived for dockershim consumption
#   to allow user to define the "pause" image to utilize. This attribute's
#   semantic has been expanded now to offer kubelet a mechanism to prevent this
#   special image from being pruned by K8s GC. In CRI-O's case, there's an
#   equivalent attribute for this purpose, which must reflect the value set by
#   kubelet in dockershim scenarios.
#
# TODO: Review the list of kubelet attributes to identify other 'overlapping'
# parameters (if any).
function adjust_crio_config_dependencies() {
	local crio_sighup=false
	local crio_restart=false

	# If kubelet is currently running with an explicit "infra" (pause) image, then
	# adjust crio.conf to honor that request.
	local pause_image=$(get_crio_config_dependency "pod-infra-container-image")
	if [ ! -z "$pause_image" ]; then
		sed -i "s@pause_image =.*@pause_image = \"${pause_image}\"@" $crio_conf_file
		crio_sighup=true
	fi

	local cni_conf_dir=$(get_crio_config_dependency "cni-conf-dir")
	if [ ! -z "$cni_conf_dir" ] && [[ $cni_conf_dir != "/etc/cni/net.d" ]]; then
		sed -i "s@network_dir =.*@network_dir = \"${cni_conf_dir}\"@" $crio_conf_file
		crio_restart=true
	fi

	if [[ "$crio_sighup" == "true" ]]; then
		pkill -HUP crio
	fi

	if [[ "$crio_restart" == "true" ]]; then
		echo "Restarting CRI-O due to unmet Kubelet's config dependencies ..."
		systemctl restart crio
	fi
}

function start_kubelet() {
	echo "Starting Kubelet ..."
	systemctl start kubelet
}

function restart_kubelet() {
	echo "Restarting Kubelet ..."
	systemctl restart kubelet
}

function stop_kubelet() {
	echo "Stopping Kubelet ..."
	systemctl stop kubelet
}

function start_containerd() {
	echo "Starting containerd on the host ..."
	systemctl start containerd.service
}

function stop_containerd() {
	echo "Stopping containerd on the host ..."
	systemctl stop containerd.service
}

function config_kubelet_snap() {
	snap set $kubelet_snap container-runtime=remote
	snap set $kubelet_snap container-runtime-endpoint=unix:///var/run/crio/crio.sock
}

function restart_kubelet_snap() {
	snap restart $kubelet_snap
}

function stop_kubelet_snap() {
	snap stop $kubelet_snap
}

# Sets the restart-policy mode for any given docker container.
function set_ctr_restart_policy() {
	local cntr=$1
	local mode=$2

	# Docker's supported restart-policy modes.
	if [[ $mode != "no" ]] &&
		[[ $mode != "always" ]] &&
		[[ $mode != "on-failure" ]] &&
		[[ $mode != "unless-stopped" ]]; then
		echo "Unsupported restart-policy mode: $mode"
		return
	fi

	if ! docker update --restart=$mode $cntr; then
		echo "Unable to modify container $cntr restart mode to $mode."
		return
	fi

	echo "Successfully modified $cntr container's restart-policy to mode: $mode."
}

# Sets the restart-policy mode for the kubelet docker container.
function set_kubelet_ctr_restart_policy() {
	local mode=$1

	kubelet_ctr_restart_mode=$(docker inspect --format='{{.HostConfig.RestartPolicy.Name}}' kubelet)

	set_ctr_restart_policy "kubelet" $mode
}

# Reverts the restart-policy mode previously stored in a global-variable.
function revert_kubelet_ctr_restart_policy() {
	set_ctr_restart_policy "kubelet" $kubelet_ctr_restart_mode
}

# Updates the entrypoint script corresponding to the kubelet container present
# in rke setups.
function config_kubelet_rke_update() {
	local env_file=$1

	local kubelet_entrypoint=$(docker inspect --format='{{index .Config.Entrypoint 0}}' kubelet)

	# Backup original entrypoint file -- to be utilized by kubelet-unconfig-helper
	# script to revert configuration.
	docker exec kubelet bash -c "cp ${kubelet_entrypoint} ${kubelet_entrypoint}.orig"

	# Extract the kubelet attributes to execute with.
	local kubelet_attribs=$(cat $env_file | cut -d'"' -f 2)

	# Adjust kubelet's container entrypoint to incorporate the new exec attributes.
	docker exec kubelet bash -c "sed -i 's@exec .*@exec kubelet ${kubelet_attribs}@' ${kubelet_entrypoint}"

	echo "Kubelet config updated within container's entrypoint: ${kubelet_entrypoint}"
}

# Configures the kubelet to use cri-o in rke setups.
function config_kubelet_rke() {

	# Temp variables to hold kubelet's config file and its config attributes.
	local kubelet_tmp_file="/etc/default/kubelet-rke"
	local kubelet_tmp_var="KUBELET_EXTRA_ARGS"

	# Extract kubelet's current execution attributes and store them in a temp file.
	local cur_kubelet_attr=$(docker exec kubelet bash -c "ps -e -o command | egrep \^kubelet | cut -d\" \" -f2-")
	echo "${kubelet_tmp_var}=\"${cur_kubelet_attr}\"" >"${kubelet_tmp_file}"

	# Add crio-specific config attributes to the temporary kubelet config file.
	replace_kubelet_env_var "$kubelet_tmp_file" "$kubelet_tmp_var"

	# Modify the actual kubelet's config file (container entrypoint) to reflect
	# the new attributes obtained above.
	config_kubelet_rke_update "$kubelet_tmp_file"

	rm -rf "$kubelet_tmp_file"
}

function restart_kubelet_container() {
	docker restart kubelet
}

function stop_kubelet_container() {
	docker stop kubelet
}

function get_runtime_kubelet_systemctl {
	set +e
	runtime=$(ps -e -o command | egrep kubelet | egrep -o "container-runtime-endpoint=\S*" | cut -d '=' -f2)
	set -e

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function get_runtime_kubelet_snap() {

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi

	local ctr_runtime_type=$(snap get $kubelet_snap container-runtime)
	if [[ "$ctr_runtime_type" == "remote" ]]; then
		runtime=$(snap get $kubelet_snap container-runtime-endpoint)
	fi
}

function get_runtime_kubelet_docker() {
	set +e
	runtime=$(docker exec kubelet bash -c "ps -e -o command | egrep \^kubelet | egrep -o \"container-runtime-endpoint=\S*\" | cut -d '=' -f2")
	set -e

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function clean_runtime_state_containerd() {
	local runtime=$1
	local runtime_path=$(echo $runtime | sed 's@unix://@@' | cut -d" " -f1)

	# Collect all the existing podIds as seen by crictl.
	podList=$($crictl_bin --runtime-endpoint "$runtime" ps | awk 'NR>1 {print $NF}')

	# Cleanup the pods; turn off errexit in these steps as we don't want to
	# interrupt the process if any of the instructions fail for a particular
	# pod.
	set +e

	for pod in ${podList}; do
		ret=$($crictl_bin --runtime-endpoint "$runtime" stopp "$pod")
		if [ $? -ne 0 ]; then
			echo "Failed to stop pod ${pod}: $ret"
		fi

		ret=$($crictl_bin --runtime-endpoint "$runtime" rmp --force "$pod")
		if [ $? -ne 0 ]; then
			echo "Failed to remove pod ${pod}: $ret"
		fi
	done

	set -e

	# Create a soft link from the containerd socket to the crio socket
	# (some pods are designed to talk to containerd (e.g., gke-metadata-server)).
	echo "Soft-linking containerd socket to CRI-O socket on the host ..."
	rm -rf "$runtime_path"
	ln -s "$crio_socket" "$runtime_path"
}

function clean_runtime_state_dockershim() {

	set +e
	docker stop -t0 $(docker ps -a -q)
	docker rm $(docker ps -a -q)
	set -e

	echo "Done eliminating all existing docker containers."

	# Create a soft link from the dockershim socket to the crio socket
	# (some pods are designed to talk to dockershim (e.g., aws-node)).
	echo "Soft-linking dockershim socket to CRI-O socket on the host ..."
	rm -f /var/run/dockershim.sock
	ln -s /var/run/crio/crio.sock /var/run/dockershim.sock
}

# Wipe out all the pods managed by the given container runtime (dockershim, containerd, etc.)
function clean_runtime_state() {
	local runtime=$1

	if [[ "$runtime" =~ "containerd" ]]; then
		clean_runtime_state_containerd "$runtime"
	elif [[ "$runtime" =~ "dockershim" ]]; then
		clean_runtime_state_dockershim
	else
		echo "Container runtime not supported: ${runtime}"
		return
	fi

	# Store info about the prior runtime on the host so the
	# kubelet-unconfig-helper service can revert it if/when the crio-cleanup-k8s
	# daemonset runs.
	mkdir -p "$var_lib_sysbox_deploy_k8s"
	echo $runtime >${var_lib_sysbox_deploy_k8s}/prior_runtime
}

function get_pods_uids() {
	$crictl_bin --runtime-endpoint ${runtime} pods -v | egrep ^UID | cut -d" " -f2
}

function do_config_kubelet() {

	# Obtain kubelet path.
	kubelet_bin=$(get_kubelet_bin)
	if [ -z "$kubelet_bin" ]; then
		die "Kubelet binary not identified."
	fi

	# Obtain current runtime.
	get_runtime_kubelet_systemctl
	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	# The ideal sequence is to stop the kubelet, cleanup all pods with the
	# existing runtime, reconfig the kubelet, and restart it. But if the runtime
	# is dockershim this logic does not work well by itself, because after stopping
	# the kubelet the dockershim also stops. Thus, for dockershim we must complement
	# this logic with an extra step: we obtain all the existing pods before
	# stopping kubelet (A), and later on, once that kubelet is stopped (B), we
	# eliminate these pods through the docker-cli interface (C). Technically,
	# there's room for a race-condition scenario in which new pods could be deployed
	# right between (A) and (B), but being the time-window so small, we can safely
	# ignore this case in most setups; in the worst case scenario we would simply
	# end up with a duplicated/stale ("non-ready") pod instantiation, but this
	# wouldn't affect the proper operation of the primary ("ready") one.

	if [[ ${runtime} =~ "dockershim" ]]; then
		stop_kubelet
		clean_runtime_state "$runtime"
		config_kubelet
		adjust_crio_config_dependencies
		restart_kubelet
	else
		stop_kubelet
		clean_runtime_state "$runtime"
		stop_containerd
		config_kubelet
		adjust_crio_config_dependencies
		restart_kubelet
	fi
}

function do_config_kubelet_snap() {
	echo "Detected kubelet snap package on host."

	kubelet_snap=$(snap list | grep kubelet | awk '{print $1}')

	get_runtime_kubelet_snap

	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	if [[ ${runtime} =~ "dockershim" ]]; then
		stop_kubelet_snap
		clean_runtime_state "$runtime"
		config_kubelet_snap
		restart_kubelet_snap
	else
		stop_kubelet_snap
		clean_runtime_state "$runtime"
		stop_containerd
		config_kubelet_snap
		restart_kubelet_snap
	fi
}

function do_config_kubelet_rke() {
	echo "Detected kubelet in docker RKE deployment on host."

	# Obtain current runtime.
	get_runtime_kubelet_docker
	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	# No runtime other than dockershim, and obviously crio, is expected in an
	# rke deployment.
	if [[ ! ${runtime} =~ "dockershim" ]]; then
		echo "Unsupported runtime for RKE scenario: $runtime"
		return
	fi

	# RKE bind-mounts /sys into its kubelet container to be able to write directly
	# into the hosts /sys/fs/cgroup path. With that goal in mind, RKE's kubelet
	# container entrypoint does a RW remount of /sys/fs/cgroup mountpoint. However,
	# this doesn't help host-based processes that require RW access to the cgroups
	# path (such as cri-o), that's why here we explicitly remount /sys/fs/cgroup as
	# RW within the init mount-ns.
	if mount | grep -q "/sys/fs/cgroup .*ro,"; then
		mount -o rw,remount /sys/fs/cgroup
	fi

	# In RKE's case we must add a few steps to the typical logic utilized in other
	# dockershim setups. In this case, as kubelet executes as the 'init' process
	# of a docker container, we must do the following:
	#
	# * Modify kubelet's container restart-policy to prevent this one from being
	#   re-spawned by docker once that we temporarily shut it down.
	# * Configurate the kubelet's container entrypoint to meet cri-o requirements.
	# * Once the usual kubelet's "stop + clean + restart" cycle is completed, we
	#   must revert the changes made to the kubelet's container restart-policy.

	set_kubelet_ctr_restart_policy "no"
	config_kubelet_rke
	stop_kubelet_container
	clean_runtime_state "$runtime"
	restart_kubelet_container
	revert_kubelet_ctr_restart_policy
}

function get_runtime_kubelet_rke2() {
	set +e
	runtime=$(ps -e -o command | egrep kubelet | egrep -o "container-runtime-endpoint=\S*" | cut -d '=' -f2)
	set -e

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function start_rke2() {
	echo "Starting RKE2 agent ..."
	systemctl start rke2-agent
}

function stop_rke2() {
	echo "Stopping RKE2 agent ..."
	systemctl stop rke2-agent
}

function config_kubelet_rke2() {
	echo "Executing Kubelet RKE2 configuration function ..."

	local rancher_config="/etc/rancher/rke2/config.yaml"

	if egrep -q "container-runtime-endpoint:.*crio.sock" "$rancher_config"; then
		echo "RKE2's kubelet is already using CRI-O; no action will be taken."
		return
	fi

	if egrep -q "container-runtime-endpoint:" "$rancher_config"; then
		sed -i "s@container-runtime-endpoint:.*@container-runtime-endpoint: /var/run/crio/crio.sock@" "$rancher_config"
	else
		echo "container-runtime-endpoint: /var/run/crio/crio.sock" >>"$rancher_config"
	fi
}

function do_config_kubelet_rke2() {

	# Obtain current runtime.
	get_runtime_kubelet_rke2
	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	# No runtime other than containerd, and obviously crio, is expected in an
	# rke2 deployment.
	if [[ ! ${runtime} =~ "containerd" ]]; then
		echo "Unsupported runtime for RKE2 scenario: $runtime"
		return
	fi

	clean_runtime_state "$runtime"
	stop_rke2
	config_kubelet_rke2
	start_rke2
}

function do_config_kubelet_docker_systemd() {
	echo "Detected kubelet in docker + systemd deployment on host."

	# Obtain current runtime.
	get_runtime_kubelet_systemctl
	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	# No runtime other than dockershim, and obviously crio, is expected in an
	# systemd-managed docker-based deployment.
	if [[ ! ${runtime} =~ "dockershim" ]]; then
		echo "Unsupported runtime for docker-based scenario: $runtime"
		return
	fi

	# RKE bind-mounts /sys into its kubelet container to be able to write directly
	# into the hosts /sys/fs/cgroup path. With that goal in mind, RKE's kubelet
	# container entrypoint does a RW remount of /sys/fs/cgroup mountpoint. However,
	# this doesn't help host-based processes that require RW access to the cgroups
	# path (such as cri-o), that's why here we explicitly remount /sys/fs/cgroup as
	# RW within the init mount-ns.
	if mount | grep -q "/sys/fs/cgroup .*ro,"; then
		mount -o rw,remount /sys/fs/cgroup
	fi

	# In RKE's case we must add a few steps to the typical logic utilized in other
	# dockershim setups. In this case, as kubelet executes as the 'init' process
	# of a docker container, we must do the following:
	#
	# * Modify kubelet's container restart-policy to prevent this one from being
	#   re-spawned by docker once that we temporarily shut it down.
	# * Configurate the kubelet's container entrypoint to meet cri-o requirements.
	# * Once the usual kubelet's "stop + clean + restart" cycle is completed, we
	#   must revert the changes made to the kubelet's container restart-policy.

	config_kubelet_docker_systemd
	adjust_crio_config_dependencies
	stop_kubelet
	clean_runtime_state "$runtime"
	start_kubelet
}

function kubelet_snap_deployment() {
	snap list 2>&1 | grep -q kubelet
}

function kubelet_rke_deployment() {

	# Docker presence is a must-have in rke setups. As we are enforcing this
	# requirement at the very beginning of the execution path, no other rke
	# related routine will check for docker's presence.
	if ! command -v docker >/dev/null 2>&1; then
		return 1
	fi

	docker inspect --format='{{.Config.Labels}}' kubelet |
		egrep -q "rke.container.name:kubelet"
}

function kubelet_rke2_deployment() {

	# Worker nodes in RKE2 setups rely on rke2-agent's systemd service.
	if systemctl is-active --quiet rke2-agent; then
		return
	fi

	false
}

function kubelet_docker_systemd_deployment() {

	# Docker presence is a must-have requirement in these setups (obviously). As
	# we are enforcing this requirement at the very beginning of the execution
	# path, no other systemd-docker related routine will check for docker's
	# presence.
	if ! command -v docker >/dev/null 2>&1; then
		return 1
	fi

	# Ensure that a container named 'kubelet' exists (typical de-facto standard).
	if ! systemctl show kubelet.service | egrep -q "^ExecStart.*=docker run"; then
		return 1
	fi

	# Ensure that the entrypoint of this kubelet container is executing 'kubelet'
	# itself.
	if ! docker inspect --format='{{index .Config.Entrypoint 0}}' kubelet |
		awk -F "/" '{print $NF}' | egrep -q "kubelet"; then
		return 1
	fi
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root."
	fi

	# Verify that /sys is mounted as read-write; otherwise remount it.
	if mount | grep -q "/sys .*ro,"; then
		mount -o rw,remount /sys
	fi

	#
	# The following kubelet deployment scenarios are currently supported:
	#
	# * Snap: Kubelet deployed via a snap service (as in Ubuntu-based AWS EKS nodes).
	# * RKE: Kubelet deployed as part of a docker container (Rancher's RKE approach).
	# * RKE2: Kubelet deployed as part of containerd container and managed through
	#         rke2-agent's systemd service (Rancher's RKE2 approach).
	# * Systemd: Kubelet deployed via a systemd service (most common approach).
	#
	if kubelet_snap_deployment; then
		do_config_kubelet_snap
	elif kubelet_rke_deployment; then
		do_config_kubelet_rke
	elif kubelet_rke2_deployment; then
		do_config_kubelet_rke2
	elif kubelet_docker_systemd_deployment; then
		do_config_kubelet_docker_systemd
	else
		do_config_kubelet
	fi
}

main "$@"
