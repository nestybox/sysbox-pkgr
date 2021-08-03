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
# Script to install or remove Sysbox Enterprise (Sysbox-EE) on a Kubernetes
# node. The script assumes it will run inside the sysbox deploy daemonset
# container, and that several host directories are mounted onto the
# container. The script requires full root privileges on the host (e.g.,
# CAP_SYS_ADMIN + write access to /proc) in order to install Sysbox on it.
#
# Note: inspired by kata-deploy (github.com/kata-containers/packaging/tree/master/kata-deploy)
#

set -o errexit
set -o pipefail
set -o nounset

# The daemonset Dockerfile places sysbox artifacts here
sysbox_artifacts="/opt/sysbox"
crio_artifacts="/opt/crio-deploy"

# The daemonset spec will set up these mounts
host_lib_systemd="/mnt/host/lib/systemd/system"
host_lib_sysctl="/mnt/host/lib/sysctl.d"
host_usr_bin="/mnt/host/usr/bin"
host_usr_lib_mod="/mnt/host/usr/lib/modules-load.d"
host_usr_local_bin="/mnt/host/usr/local/bin"
host_etc="/mnt/host/etc"
host_os_release="/mnt/host/os-release"
host_crio_conf_file="${host_etc}/crio/crio.conf"
host_crio_conf_file_backup="${host_crio_conf_file}.orig"
host_run="/mnt/host/run"
host_run_sysbox_deploy_k8s="${host_run}/sysbox-deploy-k8s"

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

# Installation flags
do_sysbox_install="true"
do_crio_install="true"

#
# CRI-O Installation Functions
#

function deploy_crio_installer_service() {
	echo "Deploying CRI-O installer agent on the host ..."
	cp ${crio_artifacts}/scripts/crio-installer.sh ${host_usr_local_bin}/crio-installer.sh
	cp ${crio_artifacts}/systemd/crio-installer.service ${host_lib_systemd}/crio-installer.service

	systemctl daemon-reload
	echo "Running CRI-O installer agent on the host (may take several seconds) ..."
	systemctl restart crio-installer.service
}

function remove_crio_installer_service() {
	echo "Removing CRI-O installer agent from the host ..."
	systemctl stop crio-installer.service
	systemctl disable crio-installer.service
	rm ${host_usr_local_bin}/crio-installer.sh
	rm ${host_lib_systemd}/crio-installer.service
	systemctl daemon-reload
}

function deploy_crio_removal_service() {
	echo "Deploying CRI-O uninstaller ..."
	cp ${crio_artifacts}/scripts/crio-removal.sh ${host_usr_local_bin}/crio-removal.sh
	cp ${crio_artifacts}/systemd/crio-removal.service ${host_lib_systemd}/crio-removal.service
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

function deploy_kubelet_config_service() {
	echo "Deploying Kubelet config agent on the host ..."
	mkdir -p ${host_run_sysbox_deploy_k8s}
	cp ${crio_artifacts}/scripts/kubelet-config-helper.sh ${host_usr_local_bin}/kubelet-config-helper.sh
	cp ${crio_artifacts}/systemd/kubelet-config-helper.service ${host_lib_systemd}/kubelet-config-helper.service
	cp ${crio_artifacts}/config/crio-kubelet-options ${host_run_sysbox_deploy_k8s}/crio-kubelet-options
	cp /usr/local/bin/crictl ${host_usr_local_bin}/sysbox-deploy-k8s-crictl

	echo "Running Kubelet config agent on the host (will restart Kubelet and temporary bring down all pods on this node for ~1 min) ..."
	systemctl daemon-reload
	systemctl restart kubelet-config-helper.service
}

function remove_kubelet_config_service() {
	echo "Stopping the Kubelet config agent on the host ..."
	systemctl stop kubelet-config-helper.service
	systemctl disable kubelet-config-helper.service

	echo "Removing Kubelet config agent from the host ..."
	rm ${host_usr_local_bin}/kubelet-config-helper.sh
	rm ${host_lib_systemd}/kubelet-config-helper.service
	rm ${host_usr_local_bin}/sysbox-deploy-k8s-crictl
	systemctl daemon-reload
}

function deploy_kubelet_unconfig_service() {
	echo "Deploying Kubelet unconfig agent on the host ..."
	cp ${crio_artifacts}/scripts/kubelet-unconfig-helper.sh ${host_usr_local_bin}/kubelet-unconfig-helper.sh
	cp ${crio_artifacts}/systemd/kubelet-unconfig-helper.service ${host_lib_systemd}/kubelet-unconfig-helper.service
	cp /usr/local/bin/crictl ${host_usr_local_bin}/sysbox-deploy-k8s-crictl

	echo "Running Kubelet unconfig agent on the host (will restart Kubelet and temporary bring down all pods on this node for ~1 min) ..."
	systemctl daemon-reload
	systemctl restart kubelet-unconfig-helper.service
}

function remove_kubelet_unconfig_service() {
	echo "Stopping the Kubelet unconfig agent on the host ..."
	systemctl stop kubelet-unconfig-helper.service
	systemctl disable kubelet-unconfig-helper.service

	echo "Removing Kubelet unconfig agent from the host ..."
	rm ${host_usr_local_bin}/kubelet-unconfig-helper.sh
	rm ${host_lib_systemd}/kubelet-unconfig-helper.service
	rm ${host_usr_local_bin}/sysbox-deploy-k8s-crictl
	systemctl daemon-reload
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

	# In GKE, the CNIs are not in the usual "/opt/cni/bin/" dir, but under "/home/kubernetes/bin"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.network.plugin_dirs.[]' "/home/kubernetes/bin"

	# Add user "containers" to the /etc/subuid and /etc/subgid files
	get_subid_limits
	config_subid_range "$subuid_file" "$subid_alloc_min_range" "$subuid_min" "$subuid_max"
	config_subid_range "$subgid_file" "$subid_alloc_min_range" "$subgid_min" "$subgid_max"
}

function restart_crio() {
	echo "Restarting CRI-O ..."
	systemctl restart crio
}

#
# Sysbox Installation Functions
#

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

	echo "Installing Sysbox dependencies on host"

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

function config_crio_for_sysbox() {
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

function unconfig_crio_for_sysbox() {
	echo "Removing Sysbox from CRI-O config"

	# Note: dasel does not yet have a proper delete command, so we need the "sed" below.
	dasel put document -f "${host_crio_conf_file}" -p toml  '.crio.runtime.runtimes.sysbox-runc' ''
	sed -i "s/\[crio.runtime.runtimes.sysbox-runc\]//g" "${host_crio_conf_file}"
}

#
# General Helper Functions
#

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

function install_precheck() {
	if systemctl is-active --quiet crio; then
	   do_crio_install="false"
	fi

   if systemctl is-active --quiet sysbox; then
		do_sysbox_install="false"
	fi
}

#
# Main Function
#

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
	   die "This script must be run as root"
	fi

	local k8s_runtime=$(get_container_runtime)

	if [[ $k8s_runtime == "" ]]; then
		die "Failed to detect K8s node runtime."
	elif [ "$k8s_runtime" == "cri-o" ]; then
		k8s_runtime="crio"
	fi

	action=${1:-}
	if [ -z "$action" ]; then
		print_usage
		die "invalid arguments"
	fi

	local crio_restart_pending=false

	case "$action" in
		install)
			mkdir -p ${host_run_sysbox_deploy_k8s}
			install_precheck

			# Install CRI-O
			if [[ "$do_crio_install" == "true" ]]; then
				add_label_to_node "crio-runtime=installing"
				deploy_crio_installer_service
				remove_crio_installer_service
				config_crio
				crio_restart_pending=true
				echo "yes" > ${host_run_sysbox_deploy_k8s}/crio_installed
			fi

			# Install Sysbox
			if [[ "$do_sysbox_install" == "true" ]]; then
				add_label_to_node "sysbox-runtime=installing"
				install_sysbox_deps
				install_sysbox
				config_crio_for_sysbox
				crio_restart_pending=true
				echo "yes" > ${host_run_sysbox_deploy_k8s}/sysbox_installed
			fi

			if [[ "$crio_restart_pending" == "true" ]]; then
				restart_crio
			fi

			# Switch the K8s runtime to CRI-O
			#
			# Note: this will configure the Kubelet to use CRI-O and restart it;,
			# thereby killing all pods on the K8s node (including this daemonset).
			# The K8s control plane will then re-create the pods, but this time
			# with CRI-O. The operation can take up to 1 minute.
			if [[ "$k8s_runtime" != "crio" ]]; then
				echo "yes" > ${host_run_sysbox_deploy_k8s}/kubelet_reconfigured
				deploy_kubelet_config_service
			fi

			# Kubelet config service cleanup
			if [ -f ${host_run_sysbox_deploy_k8s}/kubelet_reconfigured ]; then
				remove_kubelet_config_service
				rm ${host_run_sysbox_deploy_k8s}/kubelet_reconfigured
				echo "Kubelet reconfig completed."
			fi

			add_label_to_node "crio-runtime=running"
			add_label_to_node "sysbox-runtime=running"

			echo "The k8s runtime on this node is now CRI-O."
			echo "Sysbox-EE installation completed."
			;;

		cleanup)
			mkdir -p ${host_run_sysbox_deploy_k8s}

			# Switch the K8s runtime away from CRI-O (but only if this daemonset installed CRI-O previously)
			if [ -f ${host_run_sysbox_deploy_k8s}/crio_installed ] && [[ "$k8s_runtime" == "crio" ]]; then
				add_label_to_node "crio-runtime=removing"

				# Note: this will restart kubelet with the prior runtime (not
				# CRI-O), thereby killing all pods (including this daemonset)
				echo "yes" > ${host_run_sysbox_deploy_k8s}/kubelet_reconfigured
				deploy_kubelet_unconfig_service
			fi

			if [ -f ${host_run_sysbox_deploy_k8s}/kubelet_reconfigured ]; then
				remove_kubelet_unconfig_service
				rm ${host_run_sysbox_deploy_k8s}/kubelet_reconfigured
				echo "Kubelet reconfig completed."
			fi

			# Uninstall Sysbox
			if [ -f ${host_run_sysbox_deploy_k8s}/sysbox_installed ]; then
				add_label_to_node "sysbox-runtime=removing"
				unconfig_crio_for_sysbox
				remove_sysbox
				remove_sysbox_deps
				crio_restart_pending=true
				rm ${host_run_sysbox_deploy_k8s}/sysbox_installed
				rm_label_from_node "sysbox-runtime"
				echo "Sysbox-EE removal completed."
			fi

			# Uninstall CRI-O
			if [ -f ${host_run_sysbox_deploy_k8s}/crio_installed ]; then
				deploy_crio_removal_service
				remove_crio_removal_service
				crio_restart_pending=false
				rm ${host_run_sysbox_deploy_k8s}/crio_installed
				rm_label_from_node "crio-runtime"
			fi

			rm -rf ${host_run_sysbox_deploy_k8s}

			if [[ "$crio_restart_pending" == "true" ]]; then
				restart_crio
			fi

			echo "The k8s runtime on this node is now $k8s_runtime."
			;;

		*)
			echo invalid arguments
			print_usage
			;;
	esac

	# This script will be called as a daemonset. Do not return, otherwise the
   # daemonset will restart and rexecute the script
	echo "Done."

	sleep infinity
}

main "$@"
