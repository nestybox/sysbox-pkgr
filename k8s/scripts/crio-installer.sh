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

CRIO_VERSION=1.20

function die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function backup_crictl_config() {

	# We do this to avoid the CRI-O installation from stopping and asking
	# questions about merging crictl.yaml (we can't bypass this question with "apt-get -y",
	# thus causing the installation to fail).

	if [ -f /etc/crictl.yaml ]; then
		mv /etc/crictl.yaml /etc/crictl.orig.yaml
	fi

}

function flatcar_distro() {
	grep -q "^ID=flatcar" /etc/os-release
}

function install_crio_deb() {

	local OS_VERSION_ID=$(grep VERSION_ID /etc/os-release | cut -d "=" -f2 | tr -d '"')
	local OS=xUbuntu_${OS_VERSION_ID}
	local VERSION=${CRIO_VERSION}

	echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /" >/etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
	echo "deb http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /" >/etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.list

	curl -L https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:$VERSION/$OS/Release.key | apt-key add -
	curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | apt-key add -

	apt-get update
	apt-get install -y cri-o cri-o-runc
}

function install_crio_flatcar() {

	pushd /opt

	if ! curl -S https://storage.googleapis.com/k8s-conform-cri-o/artifacts/cri-o.amd64.v1.20.3.tar.gz >cri-o.amd64.v1.20.3.tar.gz; then
		echo "Unable to download CRI-O binaries during Sysbox installation."
		return
	fi

	tar -xvf cri-o.amd64.v1.20.3.tar.gz
	rm cri-o.amd64.v1.20.3.tar.gz
	pushd cri-o

	chmod +x /opt/bin/crio-extractor.sh
	/opt/bin/crio-extractor.sh install

	# Adjust crio path.
	sed -i '/Type=notify/a Environment=PATH=/opt/crio/bin:/sbin:/bin:/usr/sbin:/usr/bin' /etc/systemd/system/crio.service
	sed -i 's@/usr/local/bin/crio@/opt/crio/bin/crio@' /etc/systemd/system/crio.service
}

function install_crio() {

	echo "Installing CRI-O ..."

	if flatcar_distro; then
		install_crio_flatcar
	else
		install_crio_deb
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
	set -x
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
