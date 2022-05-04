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

function get_pods_uids() {
	$crictl_bin --runtime-endpoint ${runtime} pods -v | egrep ^UID | cut -d" " -f2
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

# Extract kubelet's execution attribute-value associated to a given attribute from
# the exec-line passed by caller.
function parse_kubelet_exec_attr_val() {
	local exec_line=$1
	local exec_attr=$2

	# Attempt to extract attribute assuming "equal" (i.e. "=") based format being
	# used (most common case). Example: --config=/home/kubernetes/kubelet-config.yaml.
	# A full match between 'exec_attr' string and 'exec_attr_val' one indicates that
	# no valid 'exec_attr_val' has been found.
	local exec_attr_val=$(echo "$exec_line" | sed 's/ /\n/g' | egrep "^--${exec_attr}" | cut -d"=" -f2)
	if [[ ! "$exec_attr_val" == "--${exec_attr}" ]]; then
		echo "$exec_attr_val"
		return
	fi

	# Attempt to extract attribute assuming "space" based format being used
	# (most common case). Example: --config /home/kubernetes/kubelet-config.yaml.
	local exec_attr_val=$(echo "$exec_line" | sed 's/ /\n/g' | egrep -C1 "^--${exec_attr}" | tail -1)
	if [[ ! "$exec_attr_val" == "--${exec_attr}" ]]; then
		echo "$exec_attr_val"
		return
	fi

	echo ""
}

function get_kubelet_env_var_all() {
	systemctl show kubelet.service | egrep "ExecStart=" |
		cut -d ";" -f2 | sed -e 's@argv\[\]=${kubelet_bin}@@g' |
		sed 's/ /\n/g' | egrep "^\\$"
}

function get_kubelet_exec_attr_val() {
	local exec_attr=$1

	local exec_line=$(get_kubelet_exec_line)
	if [ -z "$exec_line" ]; then
		return
	fi

	local exec_attr_val=$(parse_kubelet_exec_attr_val "$exec_line" "$exec_attr")
	echo "$exec_attr_val"
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

# Function adjusts the kubelet exec instruction to satisfy the crio requirements.
#
# The following changes are required:
#
# * In docker-based kubelet setups we must add /var/lib/containers bind-mount as
#   kubelet interacts with files in this path. For doing this we rely on the
#   presence of /var/lib/docker as a reference to the location where the
#   /var/lib/containers mount entry must be appended.
#
# * Also, we must append the passed env-var to the end of the exec instruction.
#   This env-var is expected to hold all the crio-specific config parameters.
#
function adjust_kubelet_exec_instruction() {
	local systemd_file=$1
	local env_var=$2
	local kubelet_mode=$3

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

			if [[ "$kubelet_mode" == "docker-based" ]]; then
				if echo "$new_line" | egrep -q "\-v /var/lib/docker:/var/lib/docker:rw.*\\\\ *$"; then
					new_line=$(printf '%s\n  -v /var/lib/containers:/var/lib/containers:rw \\\n' "$new_line")

				elif echo "$new_line" | egrep -q "\-v /var/lib/docker:/var/lib/docker:rw.*$"; then
					new_line=$(echo $new_line | sed 's@-v /var/lib/docker:/var/lib/docker:rw@& -v /var/lib/containers:/var/lib/containers:rw@')
				fi
			fi

			if ! echo "$new_line" | egrep -q "\\\\ *$"; then
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

# As its name implies, this function's goal is to carry out all the steps that
# are necessary to configure kubelet to use cri-o in systemd-managed deployments.
#
# The relative complexity of this function and its helper routines is simply a
# consequence of the multiple variables to account for due to the various ways
# in which systemd-managed apps can be configured.
#
# This function addresses all the combinations that derive from mixing these
# variables:
#
#  * Kubelet can be configured through a systemd service file or through an
#    associated drop-in file.
#  * Kubelet can be launched through either an 'ExecStart' instruction or through
#    any of the multiple instructions within a 'ExecStartPre' clauses.
#  * Kubelet can be directly managed through a systemd service, or indirectly
#    through a systemd-managed docker container.
#  * Kubelet can be instantiated through a single-line instruction or from a
#    multi-line one.
#
# Once that the proper file/line where to inject the new config state is
# identified, this function will simply append an env-var holding the cri-o
# config attributes. The content of this variable will be stored in any of the
# pre-existing env-files within the kubelet service, or a new file if none is
# found.
function config_kubelet() {
	local kubelet_mode=$1

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
	adjust_kubelet_exec_instruction "$systemd_file" "$kubelet_env_var" "$kubelet_mode"

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

# Function iterates through all the kubelet environment-files and all the
# environment-vars to search for the passed attribute and, if found, returns
# its associated value.
function get_kubelet_config_attr_from_systemd() {
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
				local exec_line=$(cat "$file")
				local exec_attr_val=$(parse_kubelet_exec_attr_val "$exec_line" "$exec_attr")
				echo "$exec_attr_val"
				return
			fi
		done
	done
}

# Function obtains the kubelet config file and then search for the passed
# config attribute.
function get_kubelet_config_attr() {
	local config_attr=$1

	if [ -z "$config_attr" ]; then
		echo ""
		return
	fi

	# Let's start by identifying the kubelet config file.
	# TODO: What if there's no explicit one defined? Is there a default one?
	local kubelet_cfg_file=$(get_kubelet_config_attr_from_systemd "config")

	# Check if there's a matching config_attr in the kubelet config file and return
	# its associated value if present.
	if [ ! -z "$kubelet_cfg_file" ]; then
		local config_attr_val=$(egrep "$config_attr" "$kubelet_cfg_file" | cut -d":" -f2 | tr -d ',"')
		echo "$config_attr_val"
		return
	fi
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
# * --cni-conf-dir: Path utilized by kubelet to find the CNI configuration
#   attributes (defaults to /etc/cni/net.d).
#
# * --cgroup-driver: Driver utilized by kubelet to manipulate cgroups on the
#   host.
#
# TODO: Review the list of kubelet attributes to identify other 'overlapping'
# parameters (if any).
function adjust_crio_config_dependencies() {
	local crio_sighup=false
	local crio_restart=false

	# If kubelet is currently running with an explicit "infra" (pause) image, then
	# adjust crio.conf to honor that request.
	local pause_image=$(get_kubelet_config_attr_from_systemd "pod-infra-container-image")
	if [ ! -z "$pause_image" ]; then
		if egrep -q "pause_image =" $crio_conf_file; then
			sed -i "s@pause_image =.*@pause_image = \"${pause_image}\"@" $crio_conf_file
		else
			sed -i "/\[crio.image\]/a \    pause_image = \"${pause_image}\"" $crio_conf_file
		fi
		crio_sighup=true
	fi

	#
	# Adjust crio.conf with kubelet's view of 'cni-conf-dir'.
	#
	local cni_conf_dir=$(get_kubelet_config_attr_from_systemd "cni-conf-dir")
	if [ ! -z "$cni_conf_dir" ] && [[ $cni_conf_dir != "/etc/cni/net.d" ]]; then
		if egrep -q "network_dir =" $crio_conf_file; then
			sed -i "s@network_dir =.*@network_dir = \"${cni_conf_dir}\"@" $crio_conf_file
		else
			sed -i "/\[crio.network\]/a \    network_dir = \"${cni_conf_dir}\"" $crio_conf_file
		fi
		crio_restart=true
	fi

	#
	# Adjust crio.conf with the cgroup driver configured by kubelet. Notice that as of
	# Kubelet <= 1.21, the default cgroup-driver is 'cgroupfs'.
	#
	local cgroup_driver_kubelet_systemd=$(get_kubelet_config_attr_from_systemd "cgroup-driver")
	local cgroup_driver_kubelet_config=$(get_kubelet_config_attr "cgroupDriver")
	local cgroup_driver
	if [ ! -z "$cgroup_driver_kubelet_config" ]; then
		cgroup_driver=$cgroup_driver_kubelet_config
	elif [ ! -z "$cgroup_driver_kubelet_systemd" ]; then
		cgroup_driver=$cgroup_driver_kubelet_systemd
	else
		cgroup_driver="cgroupfs"
	fi

	# Cri-o defaults to "systemd" cgroup driver, so we must only deal with scenarios where
	# kubelet is operating in "cgroupfs" mode.
	if [[ $cgroup_driver == "cgroupfs" ]]; then
		if egrep -q "cgroup_manager =" $crio_conf_file; then
			sed -i "s@cgroup_manager =.*@cgroup_manager = \"${cgroup_driver}\"@" $crio_conf_file
		else
			sed -i "/\[crio.runtime\]/a \    cgroup_manager = \"${cgroup_driver}\"" $crio_conf_file
		fi

		# In 'cgroupfs' mode, the conmon-group value must be defined as below.
		if egrep -q "conmon_cgroup =" $crio_conf_file; then
			sed -i "s@conmon_cgroup =.*@conmon_cgroup = \"pod\"@" $crio_conf_file
		else
			sed -i "/\[crio.runtime\]/a \    conmon_cgroup = \"pod\"" $crio_conf_file
		fi
		crio_restart=true
	fi

	# Process crio changes.
	if [[ "$crio_sighup" == "true" ]]; then
		pkill -HUP crio
	fi

	if [[ "$crio_restart" == "true" ]]; then
		echo "Restarting CRI-O due to unmet Kubelet's config dependencies ..."
		systemctl restart crio
	fi
}

function clean_runtime_state_containerd() {
	local runtime=$1
	local runtime_path=$(echo $runtime | sed 's@unix://@@' | cut -d" " -f1)

	# Collect all the existing podIds as seen by crictl.
	podList=$($crictl_bin --runtime-endpoint "$runtime" pods | awk 'NR>1 {print $1}')

	# Turn off errexit in these steps as we don't want to interrupt the process
	# if any of the instructions fail for a particular pod / container.
	set +e

	# Stop / remove all the existing pods.
	for pod in ${podList}; do
		ret=$($crictl_bin --runtime-endpoint "$runtime" stopp "$pod")
		if [ $? -ne 0 ]; then
			echo "Failed to stop pod ${pod}: ${ret}"
		fi

		ret=$($crictl_bin --runtime-endpoint "$runtime" rmp --force "$pod")
		if [ $? -ne 0 ]; then
			echo "Failed to remove pod ${pod}: ${ret}"
		fi
	done

	# At this point all the pre-existing containers may be stopped and eliminated,
	# but there may be inactive containers that we want to eliminate too as these may
	# cause issues when flipping back to the original (non-crio) scenario.
	cntrList=$($crictl_bin --runtime-endpoint "$runtime" ps -a | awk 'NR>1 {print $1}')

	for cntr in ${cntrList}; do
		ret=$($crictl_bin --runtime-endpoint "$runtime" stop --timeout 0 "$cntr")
		if [ $? -ne 0 ]; then
			echo "Failed to stop container ${cntr}: ${ret}"
		fi

		ret=$($crictl_bin --runtime-endpoint "$runtime" rm --force "$cntr")
		if [ $? -ne 0 ]; then
			echo "Failed to remove container ${cntr}: ${ret}"
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
	local runtime=$1
	shift
	local podUids=("$@")

	# Cleanup the pods; turn off errexit in these steps as we don't want to
	# interrupt the process if any of the instructions fail for a particular
	# pod / container.
	set +e

	# If no list of pre-existing pods is provided then proceed to eliminate all
	# the present containers. Otherwise, eliminate only the containers associated
	# with the provided pods.
	if [ -z "${podUids-}" ]; then
		docker stop -t0 $(docker ps -a -q)
		docker rm $(docker ps -a -q)
	else
		# Collect all the existing containers as seen by docker.
		local cntrList=$(docker ps | awk 'NR>1 {print $1}')

		for podUid in ${podUids}; do
			for cntr in ${cntrList}; do
				ret=$(docker inspect --format='{{index .Config.Labels "io.kubernetes.pod.uid"}}' $cntr 2>/dev/null | grep -q $podUid)
				if [ $? -ne 0 ]; then
					continue
				fi

				ret=$(docker stop -t0 $cntr)
				if [ $? -ne 0 ]; then
					echo "Failed to stop cntr $cntr from pod $podUid: $ret"
				fi

				ret=$(docker rm $cntr)
				if [ $? -ne 0 ]; then
					echo "Failed to remove cntr $cntr from pod $podUid: $ret"
				fi
			done
		done
	fi

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
	shift
	local podUids=("$@")

	if [[ "$runtime" =~ "containerd" ]]; then
		clean_runtime_state_containerd "$runtime"
	elif [[ "$runtime" =~ "dockershim" ]]; then
		if [ -n "${podUids-}" ]; then
			clean_runtime_state_dockershim "$runtime" "$podUids"
		else
			clean_runtime_state_dockershim "$runtime"
		fi
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

# QoS cgroups are created as transient systemd slices when making use of the systemd
# cgroup driver. In these scenarios, kubelet won't be able to initialize if there are
# pre-existing kubepod cgroup entries corresponding to previous kubelet instantiations.
# This function ensures that these entries are eliminated.
function clean_cgroups_kubepods() {

	# We eliminate all the cgroup kubepod entries by simply stopping their associated
	# systemd service.
	echo "Stopping/eliminating kubelet QoS cgroup kubepod entries..."
	for i in $(systemctl list-unit-files --no-legend --no-pager -l | grep --color=never -o .*.slice | grep kubepod); do
		systemctl stop $i
	done
}

###############################################################################
# Scenario 1: Snap setup -- Snap-based kubelet
###############################################################################

function start_kubelet_snap() {
	snap start $kubelet_snap
}

function stop_kubelet_snap() {
	snap stop $kubelet_snap
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

function config_kubelet_snap() {
	snap set $kubelet_snap container-runtime=remote
	snap set $kubelet_snap container-runtime-endpoint=unix:///var/run/crio/crio.sock
}

function do_config_kubelet_snap() {
	echo "Detected snap-based kubelet deployment on host."

	kubelet_snap=$(snap list | grep kubelet | awk '{print $1}')

	get_runtime_kubelet_snap

	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	if [[ ${runtime} =~ "dockershim" ]]; then
		stop_kubelet_snap
		clean_runtime_state "$runtime"
		clean_cgroups_kubepods
		config_kubelet_snap
		start_kubelet_snap
	else
		stop_kubelet_snap
		clean_runtime_state "$runtime"
		clean_cgroups_kubepods
		stop_containerd
		config_kubelet_snap
		start_kubelet_snap
	fi
}

function kubelet_snap_deployment() {
	snap list 2>&1 | grep -q kubelet
}

###############################################################################
# Scenario 2: RKE setup -- Docker-based kubelet created by rke tool
###############################################################################

function start_kubelet_container() {
	docker start kubelet
}

function restart_kubelet_container() {
	docker restart kubelet
}

function stop_kubelet_container() {
	docker stop kubelet
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

# Updates the entrypoint script of the kubelet container present in rke setups.
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

function do_config_kubelet_rke() {
	echo "Detected RKE's docker-based kubelet deployment on host."

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
	# * Obtain the list of pre-existing pods that need to be deleted during the
	#   'cleanup' phase -- see that we must provide an explicit list as we want
	#   to leave the 'kubelet' container untouched.
	# * Once the usual kubelet's "stop + clean + start" cycle is completed, we
	#   must revert the changes made to the kubelet's container restart-policy.

	set_kubelet_ctr_restart_policy "no"
	config_kubelet_rke
	local podUids=$(get_pods_uids)
	stop_kubelet_container
	clean_runtime_state "$runtime" "$podUids"
	start_kubelet_container
	revert_kubelet_ctr_restart_policy
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

###############################################################################
# Scenario 3: RKE2 setup -- Host-based kubelet managed by rke2-agent's systemd
# service
###############################################################################

function start_rke2() {
	echo "Starting RKE2 agent ..."
	systemctl start rke2-agent
}

function stop_rke2() {
	echo "Stopping RKE2 agent ..."
	systemctl stop rke2-agent
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

function config_kubelet_rke2() {
	echo "Executing Kubelet RKE2 configuration function ..."

	local rancher_config="/etc/rancher/rke2/config.yaml"

	# TODO: Currently we only support RKE2 setups that are configured through
	# the default RKE2's config.yaml file; meaning that we are not looking at
	# custom config attributes that could be potentially passed by the user
	# through the rke2-agent cli.

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
	echo "Detected RKE2's host-based kubelet deployment on host."

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

	# Ideally, we should stop containerd first and do the clean-up right after,
	# but that's not an option in RKE2 setups as it directly manages the
	# live-cycle of the K8s components through its rke2-agent daemon. That's
	# why we must first clean all the state, and stop rke2-agent afterwards.
	# This could theoretically open up the possibility for race-conditions, but
	# that's something that we haven't observed yet given the short interval
	# between the 'clean' and the 'stop' events.

	clean_runtime_state "$runtime"
	stop_rke2
	config_kubelet_rke2
	start_rke2
}

function kubelet_rke2_deployment() {

	# Worker nodes in RKE2 setups rely on rke2-agent's systemd service.
	if systemctl is-active --quiet rke2-agent; then
		return
	fi

	false
}

###############################################################################
# Scenario 4: Docker-based kubelet managed through a systemd service
###############################################################################

function get_runtime_kubelet_systemctl {
	set +e
	runtime=$(ps -e -o command | egrep kubelet | egrep -o "container-runtime-endpoint=\S*" | cut -d '=' -f2)
	set -e

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function do_config_kubelet_docker_systemd() {
	echo "Detected systemd-managed docker-based kubelet deployment on host."

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

	# See comment above in rke's equivalent function.
	if mount | grep -q "/sys/fs/cgroup .*ro,"; then
		mount -o rw,remount /sys/fs/cgroup
	fi

	config_kubelet "docker-based"
	adjust_crio_config_dependencies
	stop_kubelet
	clean_runtime_state "$runtime"
	clean_cgroups_kubepods
	start_kubelet
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

###############################################################################
# Scenario 5: Host-based kubelet managed through a systemd service
###############################################################################

function get_kubelet_bin() {
	local tmp=$(systemctl show kubelet | grep "ExecStart=" | cut -d ";" -f1)
	tmp=${tmp#"ExecStart={ path="}
	echo "$tmp" | xargs
}

function do_config_kubelet() {
	echo "Detected systemd-managed host-based kubelet deployment on host."

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
		clean_cgroups_kubepods
		config_kubelet "host-based"
		adjust_crio_config_dependencies
		restart_kubelet
	else
		stop_kubelet
		clean_runtime_state "$runtime"
		clean_cgroups_kubepods
		stop_containerd
		config_kubelet "host-based"
		adjust_crio_config_dependencies
		restart_kubelet
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
	# * Snap: Snap-based kubelet (as in Ubuntu-based AWS EKS nodes).
	# * RKE: Docker-based kubelet created as a static-pod (Rancher's RKE approach).
	# * RKE2: Host-based kubelet managed by rke2-agent's systemd service (Rancher's RKE2 approach).
	# * Systemd+Docker: Docker-based kubelet managed by a systemd service (Lokomotive's approach).
	# * Systemd: Host-based kubelet managed by a systemd service (most common approach).
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
