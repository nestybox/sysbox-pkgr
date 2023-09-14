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
# Script to install or remove Sysbox (CE) and Sysbox-EE on a Kubernetes node.
# The script assumes it will run inside the sysbox deploy daemonset container,
# and that several host directories are mounted onto the container. The script
# requires full root privileges on the host (e.g., CAP_SYS_ADMIN + write access
# to /proc) in order to install Sysbox on it.
#
# Note: inspired by kata-deploy (github.com/kata-containers/packaging/tree/master/kata-deploy)
#

set -o errexit
set -o pipefail
set -o nounset

# The Sysbox edition to install: Sysbox (CE) or Sysbox-EE.
sysbox_edition=""

# The daemonset Dockerfile places sysbox artifacts here
sysbox_artifacts="/opt/sysbox"
crio_artifacts="/opt/crio-deploy"

# The daemonset spec will set up these mounts.
host_systemd="/mnt/host/lib/systemd/system"
host_sysctl="/mnt/host/lib/sysctl.d"
host_bin="/mnt/host/usr/bin"
host_lib_mod="/mnt/host/usr/lib/modules-load.d"
host_local_bin="/mnt/host/usr/local/bin"
host_etc="/mnt/host/etc"
host_os_release="/mnt/host/os-release"
host_crio_conf_file="${host_etc}/crio/crio.conf"
host_crio_conf_file_backup="${host_crio_conf_file}.orig"
host_run="/mnt/host/run"
host_var_lib="/mnt/host/var/lib"
host_var_lib_sysbox_deploy_k8s="${host_var_lib}/sysbox-deploy-k8s"

#
# Subid default values.
#
# Sysbox supports up 4K sys contaienrs per K8s node, each with 64K subids.
#
# Historical note: prior to Docker's acquisition of Nesytbox, Sysbox-CE was
# limited to 16-pods-per-node via variable subid_alloc_min_range below, whereas
# Sysbox-EE was limited to 4K-pods-per-node. After Docker's acquisition of
# Nestybox (05/22) Sysbox-EE is no longer being offered and therefore Docker has
# decided to lift the Sysbox-CE limit to encourage adoption of Sysbox on K8s
# clusters (the limit will now be 4K-pods-per-node as it was in Sysbox-EE).
#
subid_alloc_min_start=100000
subid_alloc_min_range=268435456
subid_alloc_max_end=4294967295

# We use CRI-O's default user "containers" for the sub-id range (rather than
# user "sysbox").
subid_user="containers"
subid_def_file="${host_etc}/login.defs"
subuid_file="${host_etc}/subuid"
subgid_file="${host_etc}/subgid"

# Shiftfs
shiftfs_min_kernel_ver=5.4

# Current OS distro and kernel release
os_distro_release=""
os_kernel_release=""

# System platform architecture
sys_arch=""

# Installation flags
do_sysbox_install="true"
do_sysbox_update="false"
do_crio_install="true"

#
# CRI-O Installation Functions
#

function deploy_crio_installer_service() {
	echo "Deploying CRI-O installer agent on the host ($k8s_version) ..."

	cp ${crio_artifacts}/bin/${k8s_version}/cri-o.${sys_arch}.tar.gz ${host_local_bin}/cri-o.${sys_arch}.tar.gz
	cp ${crio_artifacts}/bin/${k8s_version}/crio-patched ${host_local_bin}/crio-patched

	cp ${crio_artifacts}/scripts/crio-installer.sh ${host_local_bin}/crio-installer.sh
	cp ${crio_artifacts}/scripts/crio-extractor.sh ${host_local_bin}/crio-extractor.sh
	cp ${crio_artifacts}/systemd/crio-installer.service ${host_systemd}/crio-installer.service

	mkdir -p ${host_var_lib_sysbox_deploy_k8s}
	cp ${crio_artifacts}/config/etc_cni_net.d_200-loopback.conf ${host_var_lib_sysbox_deploy_k8s}/etc_cni_net.d_200-loopback.conf
	cp ${crio_artifacts}/config/etc_containers_registries.conf.d_000-shortnames.conf ${host_var_lib_sysbox_deploy_k8s}/etc_containers_registries.conf.d_000-shortnames.conf
	cp ${crio_artifacts}/config/etc_containers_storage.conf ${host_var_lib_sysbox_deploy_k8s}/etc_containers_storage.conf
	cp ${crio_artifacts}/config/etc_containers_registries.conf ${host_var_lib_sysbox_deploy_k8s}/etc_containers_registries.conf
	cp ${crio_artifacts}/config/etc_containers_registries.d_default.yaml ${host_var_lib_sysbox_deploy_k8s}/etc_containers_registries.d_default.yaml
	cp ${crio_artifacts}/config/etc_containers_policy.json ${host_var_lib_sysbox_deploy_k8s}/etc_containers_policy.json

	systemctl daemon-reload
	echo "Running CRI-O installer agent on the host (may take several seconds) ..."
	systemctl restart crio-installer.service
}

function remove_crio_installer_service() {
	echo "Removing CRI-O installer agent from the host ..."
	systemctl stop crio-installer.service
	systemctl disable crio-installer.service
	rm -f ${host_local_bin}/crio-installer.sh
	rm -f ${host_local_bin}/crio-extractor.sh
	rm -f ${host_systemd}/crio-installer.service

	systemctl daemon-reload
}

function deploy_crio_removal_service() {
	echo "Deploying CRI-O uninstaller ..."
	cp ${crio_artifacts}/scripts/crio-removal.sh ${host_local_bin}/crio-removal.sh
	cp ${crio_artifacts}/scripts/crio-extractor.sh ${host_local_bin}/crio-extractor.sh
	cp ${crio_artifacts}/systemd/crio-removal.service ${host_systemd}/crio-removal.service

	systemctl daemon-reload
	systemctl restart crio-removal.service
}

function remove_crio_removal_service() {
	echo "Removing the CRI-O uninstaller ..."
	systemctl stop crio-removal.service
	systemctl disable crio-removal.service
	rm -f ${host_local_bin}/crio-removal.sh
	rm -f ${host_local_bin}/crio-extractor.sh
	rm -f ${host_systemd}/crio-removal.service

	systemctl daemon-reload
}

function deploy_kubelet_config_service() {
	echo "Deploying Kubelet config agent on the host ..."
	mkdir -p ${host_var_lib_sysbox_deploy_k8s}
	cp ${crio_artifacts}/scripts/kubelet-config-helper.sh ${host_local_bin}/kubelet-config-helper.sh
	cp ${crio_artifacts}/systemd/kubelet-config-helper.service ${host_systemd}/kubelet-config-helper.service
	cp ${crio_artifacts}/config/crio-kubelet-options ${host_var_lib_sysbox_deploy_k8s}/crio-kubelet-options

	cp /usr/local/bin/crictl ${host_local_bin}/sysbox-deploy-k8s-crictl

	echo "Running Kubelet config agent on the host (will restart Kubelet and temporary bring down all pods on this node for ~1 min) ..."
	systemctl daemon-reload
	systemctl restart kubelet-config-helper.service
}

function remove_kubelet_config_service() {
	echo "Stopping the Kubelet config agent on the host ..."
	systemctl stop kubelet-config-helper.service
	systemctl disable kubelet-config-helper.service

	echo "Removing Kubelet config agent from the host ..."
	rm -f ${host_local_bin}/kubelet-config-helper.sh
	rm -f ${host_systemd}/kubelet-config-helper.service
	rm -f ${host_local_bin}/sysbox-deploy-k8s-crictl
	systemctl daemon-reload
}

function deploy_kubelet_unconfig_service() {
	echo "Deploying Kubelet unconfig agent on the host ..."

	cp ${crio_artifacts}/scripts/kubelet-unconfig-helper.sh ${host_local_bin}/kubelet-unconfig-helper.sh
	cp ${crio_artifacts}/systemd/kubelet-unconfig-helper.service ${host_systemd}/kubelet-unconfig-helper.service
	cp /usr/local/bin/crictl ${host_local_bin}/sysbox-deploy-k8s-crictl

	echo "Running Kubelet unconfig agent on the host (will restart Kubelet and temporary bring down all pods on this node for ~1 min) ..."
	systemctl daemon-reload
	systemctl restart kubelet-unconfig-helper.service
}

function remove_kubelet_unconfig_service() {
	echo "Stopping the Kubelet unconfig agent on the host ..."
	systemctl stop kubelet-unconfig-helper.service
	systemctl disable kubelet-unconfig-helper.service

	echo "Removing Kubelet unconfig agent from the host ..."
	rm -f ${host_local_bin}/kubelet-unconfig-helper.sh
	rm -f ${host_systemd}/kubelet-unconfig-helper.service
	rm -f ${host_local_bin}/sysbox-deploy-k8s-crictl
	systemctl daemon-reload
}

function config_crio() {
	echo "Configuring CRI-O ..."

	if [ ! -f ${host_crio_conf_file_backup} ]; then
		cp ${host_crio_conf_file} ${host_crio_conf_file_backup}
	fi

	# Disable selinux for now.
	dasel put bool -f ${host_crio_conf_file} -p toml -m "crio.runtime.selinux" false

	# Add user "containers" to the /etc/subuid and /etc/subgid files
	get_subid_limits
	config_subid_range "$subuid_file" "$subid_alloc_min_range" "$subuid_min" "$subuid_max"
	config_subid_range "$subgid_file" "$subid_alloc_min_range" "$subgid_min" "$subgid_max"

	# Set capabilities to match default caps in containerd/docker
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "CHOWN"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "DAC_OVERRIDE"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "FSETID"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "FOWNER"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "SETUID"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "SETGID"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "SETPCAP"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "SETFCAP"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "NET_BIND_SERVICE"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "KILL"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "AUDIT_WRITE"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "NET_RAW"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "SYS_CHROOT"
	dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.runtime.default_capabilities.[]' "MKNOD"

	# Create 'crio.image' table (required for 'pause_image' settings).
	dasel put document -f ${host_crio_conf_file} -p toml -m '.crio.image'

	# Create 'crio.network' table (required for 'network_dir' settings).
	dasel put document -f ${host_crio_conf_file} -p toml -m '.crio.network'

	# CRI-O puts a default limit of 1024 processes per pod; this is too small for
	# Sysbox pods, since these run sometimes complex software such as Docker,
	# K8s, etc. Thus we increase this to 16K processes per pod. Since the max
	# limit for Linux is 4M (see /proc/sys/kernel/pid_max), this allows up to
	# ~256 Sysbox containers each consuming 16K processes on a given host. It
	# also constraints a malicious container executing a fork bomb to 16K
	# processes, well below the kernel's max pid limit.
	dasel put int -f ${host_crio_conf_file} -p toml -m "crio.runtime.pids_limit" 16384
}

function restart_crio() {
	echo "Restarting CRI-O ..."
	systemctl restart crio
}

#
# Sysbox Installation Functions
#

function get_artifacts_dir() {

	local distro=$os_distro_release

	if [[ "$distro" == "ubuntu-22.04" ]] ||
		[[ "$distro" == "ubuntu-21.10" ]] ||
		[[ "$distro" == "ubuntu-20.04" ]] ||
		[[ "$distro" == "ubuntu-18.04" ]]; then
		artifacts_dir="${sysbox_artifacts}/bin/generic"
	elif [[ "$distro" =~ "flatcar" ]]; then
		local release=$(echo $distro | cut -d"-" -f2)
		artifacts_dir="${sysbox_artifacts}/bin/flatcar-${release}"
	else
		die "Sysbox is not supported on this host's distro ($distro)".
	fi

	echo $artifacts_dir
}

function copy_sysbox_to_host() {

	local artifacts_dir=$(get_artifacts_dir)

	cp "${artifacts_dir}/sysbox-mgr" "${host_bin}/sysbox-mgr"
	cp "${artifacts_dir}/sysbox-fs" "${host_bin}/sysbox-fs"
	cp "${artifacts_dir}/sysbox-runc" "${host_bin}/sysbox-runc"
}

function rm_sysbox_from_host() {
	rm -f "${host_bin}/sysbox-mgr"
	rm -f "${host_bin}/sysbox-fs"
	rm -f "${host_bin}/sysbox-runc"

	# Remove sysbox from the /etc/subuid and /etc/subgid files
	sed -i '/sysbox:/d' "${host_etc}/subuid"
	sed -i '/sysbox:/d' "${host_etc}/subgid"
}

function copy_conf_to_host() {
	cp "${sysbox_artifacts}/systemd/99-sysbox-sysctl.conf" "${host_sysctl}/99-sysbox-sysctl.conf"
	cp "${sysbox_artifacts}/systemd/50-sysbox-mod.conf" "${host_lib_mod}/50-sysbox-mod.conf"
}

function rm_conf_from_host() {
	rm -f "${host_sysctl}/99-sysbox-sysctl.conf"
	rm -f "${host_lib_mod}/50-sysbox-mod.conf"
}

function copy_systemd_units_to_host() {
	cp "${sysbox_artifacts}/systemd/sysbox.service" "${host_systemd}/sysbox.service"
	cp "${sysbox_artifacts}/systemd/sysbox-mgr.service" "${host_systemd}/sysbox-mgr.service"
	cp "${sysbox_artifacts}/systemd/sysbox-fs.service" "${host_systemd}/sysbox-fs.service"
	systemctl daemon-reload
	systemctl enable sysbox.service
	systemctl enable sysbox-mgr.service
	systemctl enable sysbox-fs.service
}

function rm_systemd_units_from_host() {
	rm -f "${host_systemd}/sysbox.service"
	rm -f "${host_systemd}/sysbox-mgr.service"
	rm -f "${host_systemd}/sysbox-fs.service"
	systemctl daemon-reload
}

function apply_conf() {

	# Note: this requires CAP_SYS_ADMIN on the host
	echo "Configuring host sysctls ..."
	sysctl -p "${host_sysctl}/99-sysbox-sysctl.conf"
}

function start_sysbox() {
	echo "Starting $sysbox_edition ..."
	systemctl restart sysbox
	systemctl is-active --quiet sysbox
}

function stop_sysbox() {
	if systemctl is-active --quiet sysbox; then
		echo "Stopping $sysbox_edition ..."
		systemctl stop sysbox
	fi
}

function install_sysbox() {
	# Sysbox could potentially be already installed (during upgrades),
	# so stop it first to ensure that copy instructions below can
	# succeed.
	stop_sysbox

	echo "Installing $sysbox_edition on host ..."
	copy_sysbox_to_host
	copy_conf_to_host
	copy_systemd_units_to_host
	apply_conf
	start_sysbox
}

function remove_sysbox() {
	echo "Removing $sysbox_edition from host ..."
	stop_sysbox
	rm_systemd_units_from_host
	rm_conf_from_host
	rm_sysbox_from_host
}

function deploy_sysbox_installer_helper() {
	echo "Deploying $sysbox_edition installer helper on the host ..."
	cp ${sysbox_artifacts}/scripts/sysbox-installer-helper.sh ${host_local_bin}/sysbox-installer-helper.sh
	cp ${sysbox_artifacts}/systemd/sysbox-installer-helper.service ${host_systemd}/sysbox-installer-helper.service
	systemctl daemon-reload
	echo "Running $sysbox_edition installer helper on the host (may take several seconds) ..."
	systemctl restart sysbox-installer-helper.service
}

function remove_sysbox_installer_helper() {
	echo "Stopping the $sysbox_edition installer helper on the host ..."
	systemctl stop sysbox-installer-helper.service
	systemctl disable sysbox-installer-helper.service
	echo "Removing $sysbox_edition installer helper from the host ..."
	rm -f ${host_local_bin}/sysbox-installer-helper.sh
	rm -f ${host_systemd}/sysbox-installer-helper.service
	systemctl daemon-reload
}

function deploy_sysbox_removal_helper() {
	echo "Deploying $sysbox_edition removal helper on the host..."
	cp ${sysbox_artifacts}/scripts/sysbox-removal-helper.sh ${host_local_bin}/sysbox-removal-helper.sh
	cp ${sysbox_artifacts}/systemd/sysbox-removal-helper.service ${host_systemd}/sysbox-removal-helper.service
	systemctl daemon-reload
	systemctl restart sysbox-removal-helper.service
}

function remove_sysbox_removal_helper() {
	echo "Removing the $sysbox_edition removal helper ..."
	systemctl stop sysbox-removal-helper.service
	systemctl disable sysbox-removal-helper.service
	rm -f ${host_local_bin}/sysbox-removal-helper.sh
	rm -f ${host_systemd}/sysbox-removal-helper.service
	systemctl daemon-reload
}

function install_sysbox_deps_flatcar() {

	# Expected vars layout:
	# * artifacts-dir == "/opt/sysbox/bin/flatcar-<release>"
	# * distro-release == "flatcar-<release>"
	local artifacts_dir=$(get_artifacts_dir)
	local distro_release=$(echo ${artifacts_dir} | cut -d"/" -f5)

	# Let's try to install from local store first.
	if [ -d "$artifacts_dir" ]; then
		echo "Copying shiftfs module and sysbox dependencies to host ..."
		cp ${artifacts_dir}/shiftfs.ko ${host_lib_mod}/shiftfs.ko
		cp ${artifacts_dir}/fusermount ${host_bin}/fusermount
		return
	fi

	# Otherwise fetch the binaries/dependencies from an external location.
	echo "Fetching / copying shiftfs module and sysbox dependencies to host ..."
	mkdir -p ${artifacts_dir}
	pushd ${artifacts_dir}/..
	curl -LJOSs https://github.com/nestybox/sysbox-flatcar-preview/releases/download/Sysbox-${distro_release}/${distro_release}.tar.gz
	if [ $? -ne 0 ]; then
		die "Unable to fetch Sysbox dependencies for ${distro_release} distribution. Exiting ..."
	fi

	tar -xf ${distro_release}.tar.gz
	rm -r ${distro_release}.tar.gz

	cp ${artifacts_dir}/shiftfs.ko ${host_lib_mod}/shiftfs.ko
	cp ${artifacts_dir}/fusermount ${host_bin}/fusermount
}

function install_sysbox_deps() {

	# The installation of sysbox dependencies on the host is done via the
	# sysbox-installer-helper agent, which is a systemd service that we drop on
	# the host and request systemd to start. This way the agent can install
	# packages on the host as needed. One of those dependencies is shiftfs, which
	# unlike the other dependencies, needs to be built from source on the host
	# machine (with the corresponding kernel headers, etc). The shiftfs sources
	# are included in the sysbox-deploy-k8s container image, and here we copy
	# them to the host machine (in dir /run/shiftfs_dkms). The
	# sysbox-installer-helper agent will build those sources on the host and
	# install shiftfs on the host kernel via dkms. For the specific case of
	# Flatcar, we carry a pre-built shiftfs binary as we can't easily build it
	# on the Flatcar host.

	echo "Installing Sysbox dependencies on host ..."

	local kversion=$(echo $os_kernel_release | cut -d "." -f1-2)
	if semver_lt $kversion 5.4; then
		echo "Kernel has version $kversion, which is below the min required for shiftfs ($shiftfs_min_kernel_ver); skipping shiftfs installation."
		return
	fi

	if host_flatcar_distro; then
		install_sysbox_deps_flatcar
	else
		echo "Copying shiftfs sources to host ..."
		if semver_ge $kversion 5.4 && semver_lt $kversion 5.8; then
			echo "Kernel version $kversion is >= 5.4 and < 5.8"
			cp -r "/opt/shiftfs-k5.4" "$host_run/shiftfs-dkms"
		elif semver_ge $kversion 5.8 && semver_lt $kversion 5.11; then
			echo "Kernel version $kversion is >= 5.8 and < 5.11"
			cp -r "/opt/shiftfs-k5.10" "$host_run/shiftfs-dkms"
		elif semver_ge $kversion 5.11 && semver_lt $kversion 5.13; then
			echo "Kernel version $kversion is >= 5.11 and < 5.13"
			cp -r "/opt/shiftfs-k5.11" "$host_run/shiftfs-dkms"
		elif semver_ge $kversion 5.13 && semver_lt $kversion 5.15; then
			echo "Kernel version $kversion is >= 5.13 and < 5.15"
			cp -r "/opt/shiftfs-k5.13" "$host_run/shiftfs-dkms"
		elif semver_ge $kversion 5.15 && semver_lt $kversion 5.17; then
			echo "Kernel version $kversion is >= 5.15 and < 5.17"
			cp -r "/opt/shiftfs-k5.16" "$host_run/shiftfs-dkms"
		elif semver_ge $kversion 5.17 && semver_lt $kversion 5.18; then
			echo "Kernel version $kversion is 5.17"
			cp -r "/opt/shiftfs-k5.17" "$host_run/shiftfs-dkms"
		else
			echo "Kernel version $kversion is >= 5.18"
			cp -r "/opt/shiftfs-k5.18" "$host_run/shiftfs-dkms"
		fi
	fi

	deploy_sysbox_installer_helper
	remove_sysbox_installer_helper
}

function remove_sysbox_deps() {
	echo "Removing sysbox dependencies from host ..."

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
	res=$(grep "^SUB_UID_MIN" $subid_def_file >/dev/null 2>&1)
	if [ $? -eq 0 ]; then
		subuid_min=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_UID_MAX" $subid_def_file >/dev/null 2>&1)
	if [ $? -eq 0 ]; then
		subuid_max=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_GID_MIN" $subid_def_file >/dev/null 2>&1)
	if [ $? -eq 0 ]; then
		subgid_min=$(echo $res | cut -d " " -f2)
	fi

	res=$(grep "^SUB_GID_MAX" $subid_def_file >/dev/null 2>&1)
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

	if [ ! -f $subid_file ] || [ ! -s $subid_file ]; then
		echo "$subid_user:$subid_min:$subid_size" >"${subid_file}"
		return
	fi

	readarray -t subid_entries <"${subid_file}"

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
			echo "$subid_user:$hole_start:$subid_size" >>$subid_file
			return
		fi

		hole_start=$((start + size))
	done

	hole_end=$subid_max
	if [ $((hole_end - hole_start)) -lt $subid_size ]; then
		echo "failed to allocate $subid_size sub ids in range $subid_min:$subid_max"
		return
	else
		echo "$subid_user:$hole_start:$subid_size" >>$subid_file
		return
	fi
}

function config_crio_for_sysbox() {
	echo "Adding Sysbox to CRI-O config ..."

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

	# In Flatcar's case we must further adjust crio config.
	if host_flatcar_distro; then
		sed -i 's@/usr/bin/sysbox-runc@/opt/bin/sysbox-runc@' ${host_crio_conf_file}
	fi

	# In GKE configure existing plugins 
	if is_host_gke; then
		dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.network.plugin_dirs.[]' "/opt/cni/bin/"
		dasel put string -f ${host_crio_conf_file} -p toml -m 'crio.network.plugin_dirs.[]' "/home/kubernetes/bin"
	fi
}

function unconfig_crio_for_sysbox() {
	echo "Removing Sysbox from CRI-O config ..."

	# Note: dasel does not yet have a proper delete command, so we need the "sed" below.
	dasel put document -f "${host_crio_conf_file}" -p toml '.crio.runtime.runtimes.sysbox-runc' ''
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
	echo "Usage: $0 [ce|ee] [install|cleanup]"
}

function get_k8s_version() {
	local version=$(kubectl get node $NODE_NAME -o jsonpath='{.status.nodeInfo.kubeletVersion}' | awk -F "." '{print $1 "." $2}')

	if [ "$?" -ne 0 ]; then
		die "invalid Kubernetes version"
	fi

	echo "$version"
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
	echo "${distro_name}-${version_id}"
}

function get_sys_arch() {
	local uname_m=$(uname -m)

	if [[ "$uname_m" == "x86_64" ]]; then
		sys_arch=amd64
	elif [[ "$uname_m" == "aarch64" ]]; then
		sys_arch=arm64
	elif [[ "$uname_m" == "arm" ]]; then
		sys_arch=armhf
	elif [[ "$uname_m" == "armel" ]]; then
		sys_arch=armel
	fi

	echo "${sys_arch}"
}

function host_flatcar_distro() {
	local distro=$(get_host_distro)
	echo $distro | grep -q "flatcar"
}

function get_host_kernel() {
	uname -r
}

function is_host_gke() {
	curl -Ls -o /dev/null "http://metadata.google.internal/computeMetadata/v1/instance/image" -H "Metadata-Flavor: Google" && true || false
}

function is_supported_distro() {

	local distro=$os_distro_release

	if [[ "$distro" == "ubuntu-22.04" ]] ||
		[[ "$distro" == "ubuntu-21.10" ]] ||
		[[ "$distro" == "ubuntu-20.04" ]] ||
		[[ "$distro" == "ubuntu-18.04" ]] ||
		[[ "$distro" =~ "debian" ]] ||
		[[ "$distro" =~ "flatcar" ]]; then
		return
	fi

	false
}

function is_supported_kernel() {

	local kversion=$(echo $os_kernel_release | cut -d "." -f1-2)

	# Ubuntu distro is supported starting with kernel 5.3+.
	if [[ "$os_distro_release" =~ "ubuntu" ]]; then
		if semver_lt $kversion 5.3; then
			echo "Unsupported kernel version $kversion for Ubuntu distribution (< 5.3)."
			return 1
		fi

		return 0
	fi

	# For all other distros, Sysbox requires 5.5+.
	if semver_lt $kversion 5.5; then
		echo "Unsupported kernel version $kversion for $os_distro_release distribution (< 5.5)."
		return 1
	fi

	return 0
}

function is_supported_arch() {
	if [[ "$sys_arch" == "amd64" ]] || [[ "$sys_arch" == "arm64" ]]; then
		return
	fi

	false
}

function is_supported_k8s_version() {

	local ver=$k8s_version

	if [[ "$ver" == "v1.24" ]] ||
		[[ "$ver" == "v1.25" ]] ||
		[[ "$ver" == "v1.26" ]] ||
		[[ "$ver" == "v1.27" ]]; then
		return
	fi

	if [[ "$ver" == "v1.19" ]] ||
		[[ "$ver" == "v1.20" ]] ||
		[[ "$ver" == "v1.21" ]] ||
		[[ "$ver" == "v1.22" ]] ||
		[[ "$ver" == "v1.23" ]]; then
		echo "Unsupported kubernetes version: $ver (EOL release)."
	fi

	false
}

function is_kernel_upgraded() {
	local cur_kernel=$os_kernel_release

	if [ ! -f ${host_var_lib_sysbox_deploy_k8s}/os_kernel_release ]; then
		false
		return
	fi

	local prev_kernel=$(cat ${host_var_lib_sysbox_deploy_k8s}/os_kernel_release)
	if [[ ${cur_kernel} == ${prev_kernel} ]]; then
		false
		return
	fi

	true
}

function add_label_to_node() {
	local label=$1
	echo "Adding K8s label \"$label\" to node ..."
	kubectl label node "$NODE_NAME" --overwrite "${label}"
}

function rm_label_from_node() {
	local label=$1
	echo "Removing K8s label \"$label\" from node ..."
	kubectl label node "$NODE_NAME" "${label}-"
}

function add_taint_to_node() {
	local taint=$1
	echo "Adding K8s taint \"$taint\" to node ..."
	kubectl taint nodes "$NODE_NAME" "$taint" --overwrite=true
}

function rm_taint_from_node() {
	taint=$1
	echo "Removing K8s taint \"$taint\" from node ..."
	kubectl taint nodes "$NODE_NAME" "$taint"-
}

function install_precheck() {
	if systemctl is-active --quiet crio; then
		do_crio_install="false"
	fi

	if systemctl is-active --quiet sysbox; then
		do_sysbox_install="false"
	fi

	if is_kernel_upgraded; then
		do_sysbox_update="true"
	fi
}

# Compare two versions in SemVer format.
#
# Examples:  (1.0.1, 1.0.1) = 0
#            (1.0.1, 1.0.2) = 2
#            (1.0.1, 1.0.0) = 1
#            (1, 1.0) = 0
#            (3.0.4.10, 3.0.4.2) = 1
#            (5.0.0-22, 5.0.0-22) = 0
#            (5.0.0-22, 5.0.0-21) = 1
#            (5.0.0-21, 5.0.0-22) = 2
#
function version_compare() {

	if [[ $1 == $2 ]]; then
		return 0
	fi

	local IFS='.|-'
	local i ver1=($1) ver2=($2)

	# Fill empty fields in ver1 with zeros.
	for ((i = ${#ver1[@]}; i < ${#ver2[@]}; i++)); do
		ver1[i]=0
	done

	for ((i = 0; i < ${#ver1[@]}; i++)); do
		if [[ -z ${ver2[i]} ]]; then
			# Fill empty fields in ver2 with zeros.
			ver2[i]=0
		fi
		if ((10#${ver1[i]} > 10#${ver2[i]})); then
			return 1
		fi
		if ((10#${ver1[i]} < 10#${ver2[i]})); then
			return 2
		fi
	done

	return 0
}

# Compare semantic versions; takes two semantic version numbers of the form
# x.y.z (or x.y), and returns 0 if the first is less than the
# second, and 1 otherwise.
function semver_lt() {
	version_compare $1 $2
	if [ "$?" -eq "2" ]; then
		return 0
	else
		return 1
	fi
}

# Compare semantic versions; takes two semantic version numbers of the form
# x.y.z (or x.y), and returns 0 if the first is greater than or equal to the
# second, and 1 otherwise.
function semver_ge() {
	version_compare $1 $2
	if [ "$?" -ne "2" ]; then
		return 0
	else
		return 1
	fi
}

function do_edition_adjustments() {
	local edition_tag=$1

	# Set the Sysbox edition name being installed.
	if [[ ${edition_tag} == "ce" ]]; then
		sysbox_edition="Sysbox"
	elif [[ ${edition_tag} == "ee" ]]; then
		sysbox_edition="Sysbox-EE"
	else
		print_usage
		die "invalid sysbox edition value: $edition_tag"
	fi
}

# Function holds all the adjustments that need to be carried out to meet
# distro-specific requirements. For example, in Flatcar's case these special
# requirements are a consequence of its particular partition scheme (read-only
# /usr). For readability and maintainability purposes, we opted by placing this
# adjustment logic away from the natural location where each file component is
# utilized, so we must keep this point in mind if the files being edited here
# were to be modified prior to the invocation of this routine.
function do_distro_adjustments() {

	local distro=$(get_host_distro)
	if [[ ! ${distro} =~ "flatcar" ]]; then
		return
	fi

	# Ensure that Flatcar installation proceeds only in Sysbox-EE case.
	if [[ ${sysbox_edition} != "Sysbox-EE" ]]; then
		die "Flatcar OS distribution is only supported on Sysbox Enterprise-Edition. Exiting ..."
	fi

	# Adjust global vars.
	host_bin="/mnt/host/opt/bin"
	host_local_bin="/mnt/host/opt/local/bin"
	host_systemd="/mnt/host/etc/systemd/system"
	host_sysctl="/mnt/host/opt/lib/sysctl.d"
	host_lib_mod="/mnt/host/opt/lib/modules-load.d"

	# Ensure that required folders are already present.
	mkdir -p ${host_bin} ${host_local_bin} ${host_systemd} ${host_sysctl} ${host_lib_mod}

	# Adjust crio helper scripts and services.
	sed -i 's@/usr/local/bin/crio@/opt/local/bin/crio@g' ${crio_artifacts}/systemd/crio-installer.service
	sed -i '/Type=oneshot/a Environment=PATH=/opt/local/bin:/sbin:/bin:/usr/sbin:/usr/bin' ${crio_artifacts}/systemd/crio-removal.service
	sed -i 's@/usr/local/bin/crio@/opt/local/bin/crio@g' ${crio_artifacts}/systemd/crio-removal.service

	# Adjust kubelet helper scripts and services.
	sed -i '/^ExecStart=/ s@/usr/local/bin@/opt/local/bin@' ${crio_artifacts}/systemd/kubelet-config-helper.service
	sed -i '/^ExecStart=/ s@/usr/local/bin@/opt/local/bin@' ${crio_artifacts}/systemd/kubelet-unconfig-helper.service
	sed -i '/^crictl_bin/ s@/usr/local/bin@/opt/local/bin@' ${crio_artifacts}/scripts/kubelet-config-helper.sh
	sed -i '/^crictl_bin/ s@/usr/local/bin@/opt/local/bin@' ${crio_artifacts}/scripts/kubelet-unconfig-helper.sh

	# Adjust sysbox helper scripts and services.
	sed -i '/Type=notify/a Environment=PATH=/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin' ${sysbox_artifacts}/systemd/sysbox-mgr.service
	sed -i '/^ExecStart=/ s@/usr/bin/sysbox-mgr@/opt/bin/sysbox-mgr@' ${sysbox_artifacts}/systemd/sysbox-mgr.service
	sed -i '/^ExecStart=/ s@/usr/bin/sysbox-fs@/opt/bin/sysbox-fs@' ${sysbox_artifacts}/systemd/sysbox-fs.service
	sed -i '/Type=notify/a Environment=PATH=/opt/bin:/sbin:/bin:/usr/sbin:/usr/bin' ${sysbox_artifacts}/systemd/sysbox-fs.service
	sed -i '/^ExecStart=/ s@/usr/bin@/opt/bin@g' ${sysbox_artifacts}/systemd/sysbox.service
	sed -i '/^ExecStart=/ s@/usr/local/bin@/opt/local/bin@g' ${sysbox_artifacts}/systemd/sysbox-installer-helper.service
	sed -i '/^ExecStart=/ s@/usr/local/bin@/opt/local/bin@g' ${sysbox_artifacts}/systemd/sysbox-removal-helper.service

	# Sysctl adjustments.
	sed -i '/^kernel.unprivileged_userns_clone/ s/^#*/# /' ${sysbox_artifacts}/systemd/99-sysbox-sysctl.conf
}

#
# Main Function
#

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	os_distro_release=$(get_host_distro)
	if ! is_supported_distro; then
		die "Sysbox is not supported on this host's distro ($os_distro_release)".
	fi

	os_kernel_release=$(get_host_kernel)
	if ! is_supported_kernel; then
		die "Sysbox is not supported on this host's kernel release ($os_kernel_release)".
	fi

	sys_arch=$(get_sys_arch)
	if ! is_supported_arch; then
		die "Sysbox is not supported on this platform architecture ($sys_arch)".
	fi

	k8s_version=$(get_k8s_version)
	if ! is_supported_k8s_version; then
		die "Sysbox is not supported on this Kubernetes version ($k8s_version)".
	fi

	k8s_runtime=$(get_container_runtime)
	if [[ $k8s_runtime == "" ]]; then
		die "Failed to detect K8s node runtime."
	elif [ "$k8s_runtime" == "cri-o" ]; then
		k8s_runtime="crio"
	fi

	echo "Detected Kubernetes version $k8s_version"

	local edition_tag=${1:-}
	if [ -z "$edition_tag" ]; then
		print_usage
		die "invalid arguments"
	fi

	# Adjust env-vars associated to the Sysbox product edition being (un)installed.
	do_edition_adjustments $edition_tag

	local action=${2:-}
	if [ -z "$action" ]; then
		print_usage
		die "invalid arguments"
	fi

	# Perform distro-specific adjustments.
	do_distro_adjustments

	local crio_restart_pending=false

	case "$action" in
	install)
		mkdir -p ${host_var_lib_sysbox_deploy_k8s}
		install_precheck

		# Prevent new pods being scheduled till sysbox installation is completed.
		add_taint_to_node "sysbox-runtime=not-running:NoSchedule"

		# Install CRI-O
		if [[ "$do_crio_install" == "true" ]]; then
			add_label_to_node "crio-runtime=installing"
			deploy_crio_installer_service
			remove_crio_installer_service
			config_crio
			crio_restart_pending=true
			echo "yes" >${host_var_lib_sysbox_deploy_k8s}/crio_installed
		fi

		# (Re)Install Sysbox
		if [[ "$do_sysbox_install" == "true" ]] ||
			[[ "$do_sysbox_update" == "true" ]]; then
			add_label_to_node "sysbox-runtime=installing"
			install_sysbox_deps
			install_sysbox
			config_crio_for_sysbox
			crio_restart_pending=true
			echo "yes" >${host_var_lib_sysbox_deploy_k8s}/sysbox_installed
			echo "$os_kernel_release" >${host_var_lib_sysbox_deploy_k8s}/os_kernel_release
		fi

		if [[ "$crio_restart_pending" == "true" ]]; then
			restart_crio
		fi

		# Switch the K8s runtime to CRI-O
		#
		# Note: this will configure the Kubelet to use CRI-O and restart it,
		# thereby killing all pods on the K8s node (including this daemonset).
		# The K8s control plane will then re-create the pods, but this time
		# with CRI-O. The operation can take up to 1 minute.
		if [[ "$k8s_runtime" != "crio" ]]; then
			echo "yes" >${host_var_lib_sysbox_deploy_k8s}/kubelet_reconfigured
			deploy_kubelet_config_service
		fi

		# Kubelet config service cleanup
		if [ -f ${host_var_lib_sysbox_deploy_k8s}/kubelet_reconfigured ]; then
			remove_kubelet_config_service
			rm -f ${host_var_lib_sysbox_deploy_k8s}/kubelet_reconfigured
			echo "Kubelet reconfig completed."
		fi

		add_label_to_node "crio-runtime=running"
		add_label_to_node "sysbox-runtime=running"
		rm_taint_from_node "sysbox-runtime=not-running:NoSchedule"

		echo "The k8s runtime on this node is now CRI-O."
		echo "$sysbox_edition installation completed."
		;;

	cleanup)
		mkdir -p ${host_var_lib_sysbox_deploy_k8s}

		# Prevent new pods being scheduled during sysbox cleanup phase.
		add_taint_to_node "sysbox-runtime=not-running:NoSchedule"

		# Switch the K8s runtime away from CRI-O (but only if this daemonset installed CRI-O previously)
		if [ -f ${host_var_lib_sysbox_deploy_k8s}/crio_installed ] && [[ "$k8s_runtime" == "crio" ]]; then
			add_label_to_node "crio-runtime=removing"

			# Note: this will restart kubelet with the prior runtime (not
			# CRI-O), thereby killing all pods (including this daemonset)
			echo "yes" >${host_var_lib_sysbox_deploy_k8s}/kubelet_reconfigured
			deploy_kubelet_unconfig_service
		fi

		if [ -f ${host_var_lib_sysbox_deploy_k8s}/kubelet_reconfigured ]; then
			remove_kubelet_unconfig_service
			rm -f ${host_var_lib_sysbox_deploy_k8s}/kubelet_reconfigured
			echo "Kubelet reconfig completed."
		fi

		# Uninstall Sysbox
		if [ -f ${host_var_lib_sysbox_deploy_k8s}/sysbox_installed ]; then
			add_label_to_node "sysbox-runtime=removing"
			unconfig_crio_for_sysbox
			remove_sysbox
			remove_sysbox_deps
			crio_restart_pending=true
			rm -f ${host_var_lib_sysbox_deploy_k8s}/sysbox_installed
			rm -f ${host_var_lib_sysbox_deploy_k8s}/os_kernel_release
			rm_label_from_node "sysbox-runtime"
			echo "$sysbox_edition removal completed."
		fi

		# Uninstall CRI-O
		if [ -f ${host_var_lib_sysbox_deploy_k8s}/crio_installed ]; then
			deploy_crio_removal_service
			remove_crio_removal_service
			crio_restart_pending=false
			rm -f ${host_var_lib_sysbox_deploy_k8s}/crio_installed
			rm_label_from_node "crio-runtime"
		fi

		rm -rf ${host_var_lib_sysbox_deploy_k8s}

		if [[ "$crio_restart_pending" == "true" ]]; then
			restart_crio
		fi

		rm_taint_from_node "sysbox-runtime=not-running:NoSchedule"

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
