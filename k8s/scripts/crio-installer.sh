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

# The instructions in this function are typically executed as part of the
# containers-common's deb-pkg installation (which is a dependency of the cri-o
# pkg) by creating the default config files required for cri-o operations.
# However, these config files are not part of the cri-o tar file that
# we're relying on in this installation process, so we must explicitly create
# this configuration state as part of the installation process.
function config_containers_common() {

	local containers_dir="/etc/containers"
	mkdir -p "$containers_dir"

	# Create a default system-wide registries.conf file and associated drop-in
	# dir if not already present.
	local reg_file="${containers_dir}/registries.conf"
	local reg_dropin_dir="${containers_dir}/registries.conf.d"
	mkdir -p "$reg_dropin_dir"
	if [ ! -f "$reg_file" ]; then
		echo "unqualified-search-registries = [\"docker.io\", \"quay.io\"]" >"$reg_file"
	fi

	# Create a default registry-configuration file if not already present.
	local reg_conf_dir="${containers_dir}/registries.d"
	local reg_conf_file="${reg_conf_dir}/default.yaml"
	mkdir -p "$reg_conf_dir"
	if [ ! -f "$reg_conf_file" ]; then
		cat >"$reg_conf_file" <<EOF
# This is the default signature write location for docker registries.
default-docker:
  sigstore-staging: file:///var/lib/containers/sigstore
EOF
	fi

	# Create a default storage.conf file if not already present.
	local storage_conf_file="${containers_dir}/storage.conf"
	if [ ! -f "$storage_conf_file" ]; then
		cat >"$storage_conf_file" <<EOF
# This file is is the configuration file for all tools
# that use the containers/storage library.
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
[storage.options]
additionalimagestores = []
[storage.options.overlay]
mountopt = "nodev,metacopy=on"
[storage.options.thinpool]
EOF
	fi

	# Create a default policy.json file if not already present.
	local policy_file="${containers_dir}/policy.json"
	if [ ! -f "$policy_file" ]; then
		cat >"$policy_file" <<EOF
{
    "default": [
        {
            "type": "insecureAcceptAnything"
        }
    ],
    "transports":
        {
            "docker-daemon":
                {
                    "": [{"type":"insecureAcceptAnything"}]
                }
        }
}
EOF
	fi
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
	config_containers_common
}

main "$@"
