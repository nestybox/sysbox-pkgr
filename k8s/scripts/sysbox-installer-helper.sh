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
# Helper script to install Sysbox dependencies on host (e.g. shiftfs, rsync, etc.)
#

set -o errexit
set -o pipefail
set -o nounset

shiftfs_dkms=/run/shiftfs-dkms
apt=$(which apt-get || true)
yum=$(which yum || true)

function die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function install_package_deps() {

	if [[ ! -z $apt ]]; then
		# Certificates package is required prior to running apt-update.
		apt-get -y install ca-certificates
		apt-get update
		apt-get install -y rsync fuse iptables
	elif [[ ! -z $yum ]]; then
    	yum install -y rsync fuse iptables
	fi
}

function install_shiftfs() {
	# If shiftfs is not needed, skip
	if ! shiftfs_needed; then
		echo "Skipping shiftfs installation (kernel has id-mapped mounts support)."
		return
	fi

	# If shiftfs is already installed, skip
	if shiftfs_installed; then
		echo "Skipping shiftfs installation (it's already installed)."
		return
	fi

	echo "Installing Shiftfs ..."

	if [[ ! -z $apt ]]; then
		apt-get install -y make dkms
	elif [[ ! -z $yum ]]; then
    	yum install -y make dkms
	fi

	sh -c "cd $shiftfs_dkms && make -f Makefile.dkms"

	if ! shiftfs_installed; then
		echo "Shiftfs installation failed!"
		return
	fi

	if [[ ! -z $apt ]]; then
		apt-get remove --purge -y make dkms
	fi

	echo "Shiftfs installation done."
}

function shiftfs_installed() {
	modinfo shiftfs >/dev/null 2>&1
}

function compare_ge() {
	echo "$1" "$2" | awk '{exit !($1 >= $2)}'
}

function shiftfs_needed() {
	# shiftfs is not needed for kernels >= 5.19 where idmapped mounts are present
	# and stable, but is still recommended if it is available. the max supported
	# version for shiftfs is 6.2, so check against that here
	local kversion=$(uname -r | cut -d "." -f1-2)

	# do not need full semver comparison since kversion will be X.Y thanks to cut
	if compare_ge $kversion 6.2; then
		# not needed
		return 1
	else
		return 0
	fi
}

function probe_kernel_mods() {

	echo "Probing kernel modules ..."

	if shiftfs_needed; then
		# If provided by the caller, load the passed shiftfs module, otherwise assume
		# that this one is already present in the system's default modules location.
		local shiftfs_module=${1:-}
		if [ ! -z "${shiftfs_module}" ]; then
			if ! lsmod | grep -q shiftfs; then
				insmod ${shiftfs_module}
			fi
		else
			modprobe shiftfs
		fi
	fi

	modprobe configfs

	if ! mount | grep -q configfs; then
		echo -e "\nConfigfs kernel module is not loaded. Configfs may be required " \
			"by certain applications running inside a Sysbox container.\n"
	fi

	if shiftfs_needed && ! lsmod | grep -q shiftfs; then
		echo -e "\nShiftfs kernel module is not loaded. Shiftfs is required " \
			"for host volume mounts into Sysbox containers to have proper ownership " \
			"(user-ID and group-ID).\n"
	fi
}

function flatcar_distro() {
	grep -q "^ID=flatcar" /etc/os-release
}

function check_procfs_mount_userns() {

	# Attempt to mount procfs from a user-namespace.
	if unshare -U -p -f --mount-proc -r cat /dev/null; then
		return 0
	fi

	# Find out if there's anything we can do to workaround this situation. In certain
	# scenarios (e.g. Flatcar >= 3033.2.4), a fake (bind-mounted) '/proc/cmdline' can
	# prevent procfs from being mounted within a user-namespace. In these cases we'll
	# attempt to unmount this resource and try again.
	if mount | egrep -q "cmdline" && umount /proc/cmdline; then
		if unshare -U -p -f --mount-proc -r cat /dev/null; then
			return 0
		fi
	fi

	return 1
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	if ! check_procfs_mount_userns; then
		die "Sysbox unmet requirement: node is unable to mount procfs from within unprivileged user-namespaces."
	fi

	# In flatcar's case the shiftfs module is explicitly provided by the installer
	# itself.
	if flatcar_distro; then
		probe_kernel_mods "/opt/lib/modules-load.d/shiftfs.ko"
		return
	fi

	install_package_deps
	install_shiftfs
	probe_kernel_mods
}

main "$@"
