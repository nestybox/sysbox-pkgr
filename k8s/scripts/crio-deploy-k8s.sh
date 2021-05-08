#!/bin/bash

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
# Script to install or remove CRI-O on a Kubernetes node. The script is meant to
# run inside the crio-deploy daemonset container, and assumes that several host
# directories are mounted onto the container.
#
# For CRI-O installation, the script drops a crio installer systemd service on
# the host and starts this service. The crio installer service performs the
# installation of CRI-O at host level (e.g., downloads the packages, installs
# them, configures kubelet, etc.) When completed the crio installer service
# is removed.
#
# For CRI-O removal, the scripts drops a crio removal systemd service on
# the host and starts this service. The crio removal service removes CRI-O
# at host level (e.g., removes the packages, configures kubelet, etc.).
# When completed the crio removal service is removed.
#
# This script requires elevated privileges on the host.
#

set -o errexit
set -o pipefail

artifacts="/opt/crio-deploy"

# The daemonset spec will set up these mounts
# TODO: use a different dir for systemd services (reduces chance of messing up host).
host_lib_systemd="/mnt/host/lib/systemd/system"
host_usr_local_bin="/mnt/host/usr/local/bin"
host_etc="/mnt/host/etc"
host_crio_conf_file="${host_etc}/crio/crio.conf"
host_crio_conf_file_backup="${host_crio_conf_file}.orig"
host_run="/mnt/host/run"
host_run_crio_deploy_k8s="${host_run}/crio-deploy-k8s"
orig_kubelet_options="${host_run_crio_deploy_k8s}/orig-kubelet-options"

# K8s label for nodes that have CRI-O installed
k8s_node_label="crio-runtime"

# Installation flags
skip_install="false"
skip_cleanup="false"

# Subid defaults
subid_alloc_min_start=100000
subid_alloc_min_range=65536
subid_alloc_max_end=4294967295
subid_user="containers"
subid_def_file="${host_etc}/login.defs"
subuid_file="${host_etc}/subuid"
subgid_file="${host_etc}/subgid"

function die() {
   msg="$*"
   echo "ERROR: $msg" >&2
   exit 1
}

function print_usage() {
	echo "Usage: $0 [install|precleanup|cleanup]"
}

function get_container_runtime() {
	local runtime=$(kubectl get node $NODE_NAME -o jsonpath='{.status.nodeInfo.containerRuntimeVersion}')

	if [ "$?" -ne 0 ]; then
      die "invalid node name"
	fi
	if echo "$runtime" | grep -qE 'containerd.*-k3s'; then
		if systemctl is-active --quiet k3s-agent; then
			echo "k3s-agent"
		else
			echo "k3s"
		fi
	else
		echo "$runtime" | awk -F '[:]' '{print $1}'
	fi
}

function deploy_crio_installer_service() {
	echo "Deploying CRI-O installer agent on the host ..."
	cp ${artifacts}/scripts/crio-installer.sh ${host_usr_local_bin}/crio-installer.sh
	cp ${artifacts}/systemd/crio-installer.service ${host_lib_systemd}/crio-installer.service
	systemctl daemon-reload
	echo "Running CRI-O installer agent on the host (may take several seconds) ..."
	systemctl restart crio-installer.service
}

function remove_crio_installer_service() {
	echo "Stopping the CRI-O installer agent on the host ..."
	systemctl stop crio-installer.service
	systemctl disable crio-installer.service
	echo "Removing CRI-O installer agent from the host ..."
	rm ${host_usr_local_bin}/crio-installer.sh
	rm ${host_lib_systemd}/crio-installer.service
	systemctl daemon-reload
}

function deploy_crio_removal_service() {
	echo "Deploying CRI-O uninstaller ..."
	cp ${artifacts}/scripts/crio-removal.sh ${host_usr_local_bin}/crio-removal.sh
	cp ${artifacts}/systemd/crio-removal.service ${host_lib_systemd}/crio-removal.service
	systemctl daemon-reload
	systemctl restart crio-removal.service
}

function remove_crio_removal_service() {
	echo "Removing the CRI-O uninstaller ..."
	systemctl stop crio-removal.service
	systemctl disable crio-removal.service
	rm ${host_usr_local_bin}/crio-removal.sh
	rm ${host_lib_systemd}/crio-removal.service
	systemctl daemon-reload
}

function replace_cmd_option() {
	cmd_opts=$1
	opt=$2
	want_val=$3

	read -a curr_args <<< ${cmd_opts}
	declare -a new_args

	found_opt=false

	for arg in "${curr_args[@]}"; do
		new_arg="$arg"

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

function remove_cmd_option() {
   cmd_opts=$1
   opt=$2

   read -a curr_args <<< ${cmd_opts}
   declare -a new_args

   for arg in "${curr_args[@]}"; do
      if [[ "$arg" != "$opt="* ]]; then
         new_args+=($arg)
      fi
   done

   result=$(printf "%s " "${new_args[@]}")
   echo $result
}

function get_cmd_option() {
	cmd_opts=$1
	opt=$2

	read -a curr_args <<< ${cmd_opts}
	declare -a new_args

	found_opt=false

	for arg in "${curr_args[@]}"; do
		if [[ "$arg" == "$opt="* ]]; then
			val=${arg#"$opt="}
			echo $val
			return
		fi
	done

	echo ""
}

function apply_kubelet_config() {
   opts=$1
   kubelet_extra_args_file=$2

   set +e
   kubelet_extra_args=$(grep -s "^KUBELET_EXTRA_ARGS=" ${kubelet_extra_args_file})
   kubelet_extra_args=${kubelet_extra_args#"KUBELET_EXTRA_ARGS="}
   set -e

   new_cmd_line="$kubelet_extra_args"
   for opt in "${opts[@]}"; do
      opt_name=$(echo $opt | cut -d"=" -f1)
      opt_val=$(echo $opt | cut -d"=" -f2)

      if [[ "$opt_name" != "" ]] && [[ "$opt_val" != "" ]]; then
         new_cmd_line=$(replace_cmd_option "$new_cmd_line" "$opt_name" "$opt_val")
      elif [[ "$opt_name" != "" ]]; then
         new_cmd_line=$(remove_cmd_option "$new_cmd_line" "$opt_name")
      fi
   done

   if [[ "$new_cmd_line" != "" ]]; then
      echo "KUBELET_EXTRA_ARGS=$new_cmd_line" > $kubelet_extra_args_file
   else
      cat /dev/null > $kubelet_extra_args_file
   fi
}

function config_kubelet() {
   readarray -t opts < ${artifacts}/config/crio-kubelet-options

   # save the current options (so we can revert them during cleanup)
   kubelet_extra_args_file="${host_etc}/default/kubelet"

   set +e
   kubelet_extra_args=$(grep -s "^KUBELET_EXTRA_ARGS=" ${kubelet_extra_args_file})
   kubelet_extra_args=${kubelet_extra_args#"KUBELET_EXTRA_ARGS="}
   set -e

	mkdir -p "$host_run_crio_deploy_k8s"
   cat /dev/null > "$orig_kubelet_options"

   for opt in "${opts[@]}"; do
      opt_name=$(echo $opt | cut -d"=" -f1)
      opt_val=$(echo $opt | cut -d"=" -f2)

      # Save the value of the old option
      old_opt_val=$(get_cmd_option "$kubelet_extra_args" "$opt_name")
      old_opt="$opt_name=$old_opt_val"
      echo "$old_opt" >> "$orig_kubelet_options"
   done

   # modify the current options to the desired value
   apply_kubelet_config "$opts" "$kubelet_extra_args_file"
}

function revert_kubelet_config() {

	declare -a opts

	if [ -f $orig_kubelet_options ]; then
		readarray -t opts < ${orig_kubelet_options}
		kubelet_extra_args_file="${host_etc}/default/kubelet"
		apply_kubelet_config "$opts" "$kubelet_extra_args_file"
	else
		echo "Warning: file /run/crio-deploy/orig-kubelet-options expected to be present on the host but"
		echo "         it's not there. The host's /etc/default/kubelet file won't be reverted; you'll need"
		echo "         to revert it manually by editing the file and changing  the --container-runtime,"
		echo "         --container-runtime-endpoint, --image-service-endpoint, and --runtime-cgroups options"
		echo "         as they were prior to running the crio-deploy-k8s daemonset. Then restart the kubelet"
		echo "         (e.g., sudo sytemctl restart kubelet)."
	fi

}

function restart_kubelet() {
	# NOTE: this will cause this daemonset script to die and be restarted once
	# the kubelet comes up.
	echo "Restarting Kubelet ..."
	systemctl restart kubelet
}

function get_subid_limits() {

	# Get subid defaults from /etc/login.defs

	subuid_min=$subid_alloc_min_start
	subuid_max=$subid_alloc_max_end
	subgid_min=$subid_alloc_min_start
	subgid_max=$subid_alloc_max_end

	if [ ! -f $subid_def_file ]; then
		return
	fi

	set +e
	res=$(grep "^SUB_UID_MIN" $subid_def_file)
	if [ $? -eq 0 ]; then
		subuid_min=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_UID_MAX" $subid_def_file)
	if [ $? -eq 0 ]; then
		subuid_max=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_GID_MIN" $subid_def_file)
	if [ $? -eq 0 ]; then
		subgid_min=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_GID_MAX" $subid_def_file)
	if [ $? -eq 0 ]; then
		subgid_max=$(echo $res | cut -d " " -f2)
	fi
	set -e
}

function config_subid_range() {
	local subid_file=$1
	local subid_size=$2
	local subid_min=$3
	local subid_max=$4

	if [ ! -f $subid_file ]; then
		touch $subid_file
	fi

	readarray -t subid_entries < "$subid_file"

	# if a large enough subid config already exists for user $subid_user, there
	# is nothing to do.
	for entry in "${subid_entries[@]}"; do
		user=$(echo $entry | cut -d ":" -f1)
		start=$(echo $entry | cut -d ":" -f2)
		size=$(echo $entry | cut -d ":" -f3)

		if [[ "$user" == "$subid_user" ]] && [ "$size" -ge "$subid_size" ]; then
			return
		fi
	done

	# Sort subid entries by start range
	readarray -t sorted_subids < <(echo "${subid_entries[@]}" | tr " " "\n" | tr ":" " " | sort -n -k 2)

	# allocate a range of subid_alloc_range size
	hole_start=$subid_min
	allocated=false

	for entry in "${sorted_subids[@]}"; do
		start=$(echo $entry | cut -d " " -f2)
		size=$(echo $entry | cut -d " " -f3)

		hole_end=$start

		if [ $hole_end -ge $hole_start ] && [ $((hole_end - hole_start)) -ge $subid_size ]; then
			echo "$subid_user:$hole_start:$subid_size" >> $subid_file
			return
		fi

		hole_start=$((start+size))
	done

	if ! $allocated; then
		hole_end=$subid_max

		if [ $((hole_end - hole_start)) -lt $subid_size ]; then
			echo "failed to allocate $subid_size sub ids in range $subid_min:$subid_max"
			return
		else
			echo "$subid_user:$hole_start:$subid_size" >> $subid_file
			return
		fi
	fi
}

function config_crio() {
	echo "Configuring CRI-O ..."

	if [ ! -f ${host_crio_conf_file_backup} ]; then
		cp ${host_crio_conf_file} ${host_crio_conf_file_backup}
	fi

	# Configure CRI-O with the cgroupfs driver
	# TODO: do this only when K8s is configured without systemd cgroups
	dasel put string -f ${host_crio_conf_file} -p toml "crio.runtime.cgroup_manager" "cgroupfs"
	dasel put string -f ${host_crio_conf_file} -p toml "crio.runtime.conmon_cgroup" "pod"

	# Add user "containers" to the /etc/subuid and /etc/subgid files
	get_subid_limits
	config_subid_range "$subuid_file" "$subid_alloc_min_range" "$subuid_min" "$subuid_max"
	config_subid_range "$subgid_file" "$subid_alloc_min_range" "$subgid_min" "$subgid_max"
}

function restart_crio() {
	echo "Restarting CRI-O ..."
	systemctl restart crio
}

function add_label_to_node() {
	label=$1
	echo "Adding K8s label \"$label\" to node"
	kubectl label node "$NODE_NAME" --overwrite "${label}"
}

function rm_label_from_node() {
	label=$1
	echo "Removing K8s label \"$label\" from node"
	kubectl label node "$NODE_NAME" "${label}-"
}

function host_install_precheck() {
	local runtime=$1

	# TODO: ensure this is not a K8s master node; must be a worker node as
	# otherwise the Kubelet restart will kill K8s.

	if [[ $runtime == "crio" ]]; then
		# We get here if CRI-O was running on the host already, or if after we
		# installed CRI-O and this daemonset gets restarted.
		echo "CRI-O is running on the node."
		skip_install="true"
	fi
}

function host_cleanup_precheck() {
	local runtime=$1

	if [[ $runtime == "crio" ]]; then
		# During cleanup, CRI-O should no longer be the kubelet's runtime (because
		# during precleanup we switched the kubelet away from CRI-O). If the kubelet
		# is still using CRI-O, skip the CRI-O cleanup steps.
		echo "CRI-O is running on the node."
		skip_cleanup="true"
	fi
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
	   die "This script must be run as root"
	fi

	runtime=$(get_container_runtime)

	if [[ $runtime == "" ]]; then
		die "Failed to detect K8s node runtime."
	elif [ "$runtime" == "cri-o" ]; then
		runtime="crio"
	fi

	action=${1:-}
	if [ -z "$action" ]; then
		print_usage
		die "invalid arguments"
	fi

	case "$action" in
		install)
			host_install_precheck "$runtime"
			if [[ "$skip_install" == "false" ]]; then
				deploy_crio_installer_service
				remove_crio_installer_service
				config_crio
				restart_crio
				config_kubelet
				restart_kubelet
			fi
			add_label_to_node "${k8s_node_label}=running"
			;;
		precleanup)
			revert_kubelet_config
			add_label_to_node "${k8s_node_label}=disabled"
			restart_kubelet
			;;
		cleanup)
			host_cleanup_precheck "$runtime"
			if [[ "$skip_cleanup" == "false" ]]; then
				add_label_to_node "${k8s_node_label}=removing"
				deploy_crio_removal_service
				remove_crio_removal_service
				rm ${orig_kubelet_options}
				rmdir ${host_run_crio_deploy_k8s}
			fi
			rm_label_from_node "${k8s_node_label}"
			;;
		*)
			echo invalid arguments
			print_usage
			;;
	esac

	# This script will be called as a daemonset. Do not return, otherwise the
   # daemon will restart and rexecute the script.
	echo "Done."
	sleep infinity
}

main "$@"
