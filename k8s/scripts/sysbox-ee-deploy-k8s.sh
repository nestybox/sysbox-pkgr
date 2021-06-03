#!/bin/bash

#
# Copyright 2019-2020 Nestybox, Inc.
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
# Script to install or remove Sysbox on a Kubernetes node. The script assumes it
# will run inside the sysbox deploy daemonset container, and that several host
# directories are mounted onto the container. The script requires full root
# privileges on the host (e.g., CAP_SYS_ADMIN + write access to /proc) in order
# to install Sysbox on it.
#
# Note: inspired by kata-deploy (github.com/kata-containers/packaging/tree/master/kata-deploy)
#

set -o errexit
set -o pipefail
set -o nounset

# The daemonset Dockerfile places sysbox artifacts here
sysbox_artifacts="/opt/sysbox"

# The daemonset spec will set up these mounts
host_lib_systemd="/mnt/host/lib/systemd/system"
host_lib_sysctl="/mnt/host/lib/sysctl.d"
host_usr_bin="/mnt/host/usr/bin"
host_usr_lib_mod="/mnt/host/usr/lib/modules-load.d"
host_usr_local_bin="/mnt/host/usr/local/bin"
host_etc="/mnt/host/etc"
host_crio_conf_file="${host_etc}/crio/crio.conf"
host_crio_conf_file_backup="${host_crio_conf_file}.orig"
host_os_release="/mnt/host/os-release"
host_run="/mnt/host/run"

# Subid defaults (Sysbox-EE supports up to 4K sys containers, each with 64k uids(gids))
subid_alloc_min_start=100000
subid_alloc_min_range=268435456
subid_alloc_max_end=4294967295
subid_user="containers"
subid_def_file="${host_etc}/login.defs"
subuid_file="${host_etc}/subuid"
subgid_file="${host_etc}/subgid"

# Shiftfs
shiftfs_min_kernel_ver=5.4

# K8s label for nodes that have Sysbox installed
k8s_node_label="sysbox-runtime"

skip_install="false"

function die() {
   msg="$*"
   echo "ERROR: $msg" >&2
   exit 1
}

function print_usage() {
	echo "Usage: $0 [install|cleanup]"
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

function get_host_distro() {
	local distro_name=$(grep -w "^ID" "$host_os_release" | cut -d "=" -f2)
	local version_id=$(grep -w "^VERSION_ID" "$host_os_release" | cut -d "=" -f2 | tr -d '"')
	echo "${distro_name}_${version_id}"
}

function get_host_kernel() {
	cat /proc/version | cut -d" " -f3 | cut -d "." -f1-2
}

function copy_sysbox_to_host() {

	# TODO: add sysbox binaries for all supported distros

	distro=$(get_host_distro)

	echo "Detected host distro: $distro"

	if [[ "$distro" == "ubuntu_20.04" ]]; then
		artifact_dir="$sysbox_artifacts/bin/ubuntu-focal"
	elif [[ "$distro" == "ubuntu_18.04" ]]; then
		artifact_dir="$sysbox_artifacts/bin/ubuntu-bionic"
	else
		die "Sysbox is not supported on this host's distro ($distro)".
	fi

	cp "$artifact_dir/sysbox-mgr" "$host_usr_bin/sysbox-mgr"
	cp "$artifact_dir/sysbox-fs" "$host_usr_bin/sysbox-fs"
	cp "$artifact_dir/sysbox-runc" "$host_usr_bin/sysbox-runc"
}

function rm_sysbox_from_host() {
	rm -f "$host_usr_bin/sysbox-mgr"
	rm -f "$host_usr_bin/sysbox-fs"
	rm -f "$host_usr_bin/sysbox-runc"
}

function copy_conf_to_host() {
	cp "$sysbox_artifacts/systemd/99-sysbox-sysctl.conf" "$host_lib_sysctl/99-sysbox-sysctl.conf"
	cp "$sysbox_artifacts/systemd/50-sysbox-mod.conf" "$host_usr_lib_mod/50-sysbox-mod.conf"
}

function rm_conf_from_host() {
	rm -f "$host_lib_sysctl/99-sysbox-sysctl.conf"
	rm -f "$host_usr_lib_mod/50-sysbox-mod.conf"
}

function copy_systemd_units_to_host() {
	cp "$sysbox_artifacts/systemd/sysbox.service" "$host_lib_systemd/sysbox.service"
	cp "$sysbox_artifacts/systemd/sysbox-mgr.service" "$host_lib_systemd/sysbox-mgr.service"
	cp "$sysbox_artifacts/systemd/sysbox-fs.service" "$host_lib_systemd/sysbox-fs.service"
	systemctl daemon-reload
}

function rm_systemd_units_from_host() {
	rm -f "$host_lib_systemd/sysbox.service"
	rm -f "$host_lib_systemd/sysbox-mgr.service"
	rm -f "$host_lib_systemd/sysbox-fs.service"
	systemctl daemon-reload
}

function apply_conf() {

	# Note: this requires CAP_SYS_ADMIN on the host
	echo "Configuring host sysctls"
	sysctl -p "$host_lib_sysctl/99-sysbox-sysctl.conf"
}

function start_sysbox() {
	echo "Starting Sysbox-EE"
	systemctl restart sysbox
   systemctl is-active --quiet sysbox
}

function stop_sysbox() {
   if systemctl is-active --quiet sysbox; then
		echo "Stopping Sysbox-EE"
		systemctl stop sysbox
	fi
}

function install_sysbox() {
	echo "Installing Sysbox-EE on host"
	copy_sysbox_to_host
	copy_conf_to_host
	copy_systemd_units_to_host
	apply_conf
	start_sysbox
}

function remove_sysbox() {
	echo "Removing Sysbox-EE from host"
	stop_sysbox
	rm_systemd_units_from_host
	rm_conf_from_host
	rm_sysbox_from_host
}

function deploy_sysbox_installer_helper() {
	echo "Deploying Sysbox-EE installer helper on the host ..."
	cp ${sysbox_artifacts}/scripts/sysbox-installer-helper.sh ${host_usr_local_bin}/sysbox-installer-helper.sh
	cp ${sysbox_artifacts}/systemd/sysbox-installer-helper.service ${host_lib_systemd}/sysbox-installer-helper.service
	systemctl daemon-reload
	echo "Running Sysbox-EE installer helper on the host (may take several seconds) ..."
	systemctl restart sysbox-installer-helper.service
}

function remove_sysbox_installer_helper() {
	echo "Stopping the Sysbox-EE installer helper on the host ..."
	systemctl stop sysbox-installer-helper.service
	systemctl disable sysbox-installer-helper.service
	echo "Removing Sysbox-EE installer helper from the host ..."
	rm ${host_usr_local_bin}/sysbox-installer-helper.sh
	rm ${host_lib_systemd}/sysbox-installer-helper.service
	systemctl daemon-reload
}

function deploy_sysbox_removal_helper() {
	echo "Deploying Sysbox-EE removal helper on the host..."
	cp ${sysbox_artifacts}/scripts/sysbox-removal-helper.sh ${host_usr_local_bin}/sysbox-removal-helper.sh
	cp ${sysbox_artifacts}/systemd/sysbox-removal-helper.service ${host_lib_systemd}/sysbox-removal-helper.service
	systemctl daemon-reload
	systemctl restart sysbox-removal-helper.service
}

function remove_sysbox_removal_helper() {
	echo "Removing the Sysbox-EE removal helper ..."
	systemctl stop sysbox-removal-helper.service
	systemctl disable sysbox-removal-helper.service
	rm ${host_usr_local_bin}/sysbox-removal-helper.sh
	rm ${host_lib_systemd}/sysbox-removal-helper.service
	systemctl daemon-reload
}

function	install_sysbox_deps() {

	# The installation of sysbox dependencies on the host is done via the
	# sysbox-installer-helper agent, which is a systemd service that we drop on
	# the host and request systemd to start. This way the agent can install
	# packages on the host as needed. One of those dependencies is shiftfs, which
	# unlike the other dependencies needs to be built from source on the host
	# machine (with the corresponding kernel headers, etc). The shiftfs sources
	# are included in the sysbox-deploy-k8s container image, and here we copy
	# them to the host machine (in dir /run/shiftfs_dkms). The
	# sysbox-installer-helper agent will build those sources on the host and
	# install shiftfs on the host kernel via dkms.

	echo "Installing sysbox dependencies on host"

	local version=$(get_host_kernel)
	if (( $(echo "$version < 5.4" | bc -l) )); then
		echo "Kernel has version $version, which is below the min required for shiftfs ($shiftfs_min_kernel_ver); skipping shiftfs installation."
		return
	fi

	echo "Copying shiftfs sources to host"
	if (( $(echo "$version >= 5.4" | bc -l) )) && (( $(echo "$version < 5.8" | bc -l) )); then
		cp -r "/opt/shiftfs-k5.4" "$host_run/shiftfs-dkms"
	elif (( $(echo "$version >= 5.8" | bc -l) )) && (( $(echo "$version < 5.11" | bc -l) )); then
		cp -r "/opt/shiftfs-k5.8" "$host_run/shiftfs-dkms"
	else
		cp -r "/opt/shiftfs-k5.11" "$host_run/shiftfs-dkms"
	fi

	deploy_sysbox_installer_helper
	remove_sysbox_installer_helper
}

function remove_sysbox_deps() {
	echo "Removing sysbox dependencies from host"

	deploy_sysbox_removal_helper
	remove_sysbox_removal_helper
	rm -rf "$host_run/shiftfs-dkms"
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
	res=$(grep "^SUB_UID_MIN" $subid_def_file > /dev/null 2>&1)
	if [ $? -eq 0 ]; then
		subuid_min=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_UID_MAX" $subid_def_file > /dev/null 2>&1)
	if [ $? -eq 0 ]; then
		subuid_max=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_GID_MIN" $subid_def_file > /dev/null 2>&1)
	if [ $? -eq 0 ]; then
		subgid_min=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_GID_MAX" $subid_def_file > /dev/null 2>&1)
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
	declare -a sorted_subids
	if [ ${#subid_entries[@]} -gt 0 ]; then
		readarray -t sorted_subids < <(echo "${subid_entries[@]}" | tr " " "\n" | tr ":" " " | sort -n -k 2)
	fi

	# allocate a range of subid_alloc_range size
	hole_start=$subid_min

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

	hole_end=$subid_max
	if [ $((hole_end - hole_start)) -lt $subid_size ]; then
		echo "failed to allocate $subid_size sub ids in range $subid_min:$subid_max"
		return
	else
		echo "$subid_user:$hole_start:$subid_size" >> $subid_file
		return
	fi
}

function configure_crio() {
	echo "Adding Sysbox to CRI-O config"

	if [ ! -f ${host_crio_conf_file_backup} ]; then
		cp ${host_crio_conf_file} ${host_crio_conf_file_backup}
	fi

	# overlayfs with metacopy=on improves startup time of CRI-O rootless containers significantly
	if ! dasel -n get string -f "${host_crio_conf_file}" -p toml -s 'crio.storage_option' | grep -q "metacopy=on"; then
		dasel put string -f "${host_crio_conf_file}" -p toml -m 'crio.storage_driver' "overlay"
		dasel put string -f "${host_crio_conf_file}" -p toml -m 'crio.storage_option.[]' "overlay.mountopt=metacopy=on"
	fi

	# Add Sysbox to CRI-O's runtime list
	dasel put object -f "${host_crio_conf_file}" -p toml -t string -t string "crio.runtime.runtimes.sysbox-runc" \
			"runtime_path=/usr/bin/sysbox-runc" "runtime_type=oci"

	dasel put string -f "${host_crio_conf_file}" -p toml "crio.runtime.runtimes.sysbox-runc.allowed_annotations.[0]" \
			"io.kubernetes.cri-o.userns-mode"

	# Increase the subid range of user "containers" in /etc/subuid and /etc/subgid
	get_subid_limits
	config_subid_range "$subuid_file" "$subid_alloc_min_range" "$subuid_min" "$subuid_max"
	config_subid_range "$subgid_file" "$subid_alloc_min_range" "$subgid_min" "$subgid_max"
}

function cleanup_crio() {
	echo "Removing Sysbox from CRI-O config"

	# Note: dasel does not yet have a proper delete command, so we need the "sed" below.
	dasel put document -f "${host_crio_conf_file}" -p toml  '.crio.runtime.runtimes.sysbox-runc' ''
	sed -i "s/\[crio.runtime.runtimes.sysbox-runc\]//g" "${host_crio_conf_file}"
}

function configure_cri_runtime() {
	configure_crio
}

function cleanup_cri_runtime() {
	cleanup_crio
}

function reset_runtime() {

	# Note: this will disrupt pods on the K8s node (including the pod where this
	# script is running); thus it must not be done on the K8s control-plane
	# nodes.

	echo "Restarting CRI-O (this will temporarily disrupt all pods on the K8s node (for up to 1 minute))."
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

function host_precheck() {
	local action=$1
	local runtime=$2

	# TODO: ensure this is not a K8s master node; must be a worker node as
	# otherwise the CRI-O restart will kill K8s.

	if [[ $action == "install" ]] && [[ $runtime != "crio" ]]; then
		die "This K8s node uses the \"$runtime\" runtime. \
Sysbox requires that K8s be configured with CRI-O; \
please install CRI-O and configure K8s to use it \
before deploying Sysbox."
	fi

   if systemctl is-active --quiet sysbox; then
		# We get here is sysbox was running on the host already, or if after we
		# installed it and restarted CRI-O, this daemonset gets restarted.
		echo "Sysbox-EE is running on the node."
		kubectl label node "$NODE_NAME" --overwrite "${k8s_node_label}=running" > /dev/null 2>&1
		skip_install="true"
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
			host_precheck "$action" "$runtime"
			if [[ "$skip_install" == "false" ]]; then
				install_sysbox_deps
				install_sysbox
				configure_cri_runtime "$runtime"
				add_label_to_node "${k8s_node_label}=running"
				echo "Sysbox-EE installation completed."
				reset_runtime "$runtime"
			fi
			;;
		cleanup)
			host_precheck "$action" "$runtime"
			add_label_to_node "${k8s_node_label}=cleanup"
			cleanup_cri_runtime "$runtime"
			remove_sysbox
			remove_sysbox_deps
			rm_label_from_node "${k8s_node_label}"
			echo "Sysbox-EE removal completed."
			reset_runtime "$runtime"
			;;
		*)
			echo invalid arguments
			print_usage
			;;
	esac

	# This script will be called as a daemonset. Do not return, otherwise the
   # daemon will restart and rexecute the script
	echo "Done."

	sleep infinity
}

main "$@"
