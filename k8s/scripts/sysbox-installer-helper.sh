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

function die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function install_package_deps() {
	apt-get install -y rsync fuse iptables
}

function install_shiftfs() {

	# If shiftfs is already installed, skip
	if shiftfs_installed; then
		echo "Skipping shiftfs installation (it's already installed)."
		return
	fi

	echo "Installing Shiftfs ..."

	apt-get install -y make dkms
	sh -c "cd $shiftfs_dkms && make -f Makefile.dkms"

	if ! shiftfs_installed; then
		echo "Shiftfs installation failed!"
		return
	fi

	apt-get remove --purge -y make dkms
	echo "Shiftfs installation done."
}

function shiftfs_installed() {
	modinfo shiftfs >/dev/null 2>&1
}

function probe_kernel_mods() {
	local modpath=$1

	echo "Probing kernel modules ..."
	if [ -z ${modpath} ]; then
		modprobe shiftfs
		modprobe configfs
	else
		modprobe -t ${modpath} shiftfs
		modprobe -t ${modpath} configfs
	fi

	if ! mount | grep -q configfs; then
		echo -e "\nConfigfs kernel module is not loaded. Configfs may be required " \
			"by certain applications running inside a Sysbox container.\n"
	fi

	if ! lsmod | grep -q shiftfs; then
		echo -e "\nShiftfs kernel module is not loaded. Shiftfs is required " \
			"for host volume mounts into Sysbox containers to have proper ownership " \
			"(user-ID and group-ID).\n"
	fi
}

function flatcar_distro() {
	grep -q "^ID=flatcar" /etc/os-release
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	if flatcar_distro; then
		probe_kernel_mods "/opt/lib/modules.d"
		return
	fi

	apt-get update
	install_package_deps
	install_shiftfs

	probe_kernel_mods
}

main "$@"
