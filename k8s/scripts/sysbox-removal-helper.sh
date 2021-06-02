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
# Helper script to remove Sysbox dependencies on host (e.g. shiftfs, rsync, etc.)
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

function remove_shiftfs() {

	if ! shiftfs_installed; then
		echo "Skipping shiftfs uninstallation (shiftfs is not installed)."
		return
	fi

	if lsmod | grep shiftfs; then
		echo "Removing Shiftfs ..."
		rmmod shiftfs
	fi

	echo "Shiftfs removal done."
}

function shiftfs_installed() {
	modinfo shiftfs > /dev/null 2>&1
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
	   die "This script must be run as root"
	fi

	remove_shiftfs
}

main "$@"
