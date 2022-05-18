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
# Script to remove CRI-O from a host
#

set -o errexit
set -o pipefail
set -o nounset

CRIO_VERSION=1.21

function die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function restore_crictl_config() {
	if [ -f /etc/crictl.orig.yaml ]; then
		mv /etc/crictl.orig.yaml /etc/crictl.yaml
	fi
}

function flatcar_distro() {
	grep -q "^ID=flatcar" /etc/os-release
}

function do_uninstall_crio() {
	local path=$1

	chmod +x "${path}"/crio-extractor.sh
	local path_dir=$(dirname "$path")
	"${path}"/crio-extractor.sh uninstall "$path_dir"
}

function uninstall_crio() {

	echo "Uninstalling CRI-O ..."

	systemctl stop crio
	systemctl disable crio

	if flatcar_distro; then
		do_uninstall_crio "/opt/local/bin"
	else
		do_uninstall_crio "/usr/local/bin"
	fi

	sed -i '/containers:/d' /etc/subuid
	sed -i '/containers:/d' /etc/subgid

	echo "CRI-O uninstallation done."
}

function stop_crio() {
	echo "Stopping CRI-O ..."
	systemctl stop crio
	echo "CRI-O stop done."
}

function is_crio_running() {
	command -v crio >/dev/null 2>&1
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	if ! is_crio_running; then
		echo "CRI-O is not present; skipping removal."
		exit 0
	fi

	stop_crio
	uninstall_crio
	restore_crictl_config
}

main "$@"
