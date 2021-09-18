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
# Script to install CRI-O on a host
#

set -o errexit
set -o pipefail
set -o nounset

crio_tar_file_name="cri-o.amd64.v1.20.3.tar.gz"

function die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function backup_crictl_config() {

	if [ -f /etc/crictl.yaml ]; then
		mv /etc/crictl.yaml /etc/crictl.orig.yaml
	fi
}

function flatcar_distro() {
	grep -q "^ID=flatcar" /etc/os-release
}

function do_install_crio() {
	local path=$1
	local crio_tar_file_path="${path}/${crio_tar_file_name}"

	pushd "$path"
	tar -xvf "$crio_tar_file_path"
	rm -r "$crio_tar_file_path"
	pushd cri-o

	chmod +x "${path}"/crio-extractor.sh
	local path_dir=$(dirname "$path")
	"${path}"/crio-extractor.sh install "$path_dir"
	rm -r ${path}/cri-o

	# Adjust PATH env-var and crio's binary location if it doesn't match the default
	# location.
	if [[ "$path" != "/usr/local/bin" ]]; then
		sed -i "/Type=notify/a Environment=PATH=${path}:/sbin:/bin:/usr/sbin:/usr/bin" /etc/systemd/system/crio.service
		sed -i "s@/usr/local/bin/crio@${path}/crio@" /etc/systemd/system/crio.service
	fi
}

function install_crio() {

	echo "Installing CRI-O ..."

	if flatcar_distro; then
		do_install_crio "/opt/local/bin"
	else
		do_install_crio "/usr/local/bin"
	fi

	# Ensure that cri-o service is automatically started at boot-up time.
	systemctl enable crio

	echo "CRI-O installation done."
}

function restart_crio() {
	echo "Restarting CRI-O ..."
	systemctl restart crio
	systemctl is-active --quiet crio
	echo "CRI-O restart done."
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	if systemctl is-active crio; then
		echo "CRI-O is already running; skipping installation."
		exit 0
	fi

	backup_crictl_config
	install_crio
}

main "$@"
