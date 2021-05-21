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
# Script to revert the kubelet config done by the kubelet-config-helper
#

set -o errexit
set -o pipefail
set -o nounset

host_run_crio_deploy_k8s="/run/crio-deploy-k8s"
host_crio_runtime_endpoint=""

function die() {
   msg="$*"
   echo "ERROR: $msg" >&2
   exit 1
}

function revert_kubelet_config() {
	local config_file="${host_run_crio_deploy_k8s}/config"

	if [ ! -f "$config_file" ]; then
		echo "Failed to revert kubelet config; file $config_file not found."
		return
	fi

	if ! grep "kubelet_env_file" "$config_file"; then
		echo "Failed to revert kubelet config; config not found in $config_file"
		return
	fi

	# The config file will have this: kubelet_env_file=/path/to/file
	# Here, we copy the orig config file to the target "/path/to/file".
	local target=$(grep "kubelet_env_file" "$config_file" | cut -d "=" -f2)
	cp "${host_run_crio_deploy_k8s}/kubelet.orig" "$target"
	rm "${host_run_crio_deploy_k8s}/kubelet.orig"
	rm "$config_file"
}

function start_kubelet() {

	echo "Starting Kubelet ..."
	systemctl start kubelet
}

function stop_kubelet() {

	echo "Stopping Kubelet ..."
	systemctl stop kubelet
}

function get_crio_runtime_endpoint() {

    local kubeletBin=$(command -v kubelet)

	host_noncrio_runtime_endpoint=$(systemctl status kubelet | egrep ${kubeletBin} | egrep -o "container-runtime-endpoint=\S*" | cut -d '=' -f2)
}

# Wipe out all the pods previously created by the crio runtime.
function clean_crio_runtime_state() {

	if [[ "${host_crio_runtime_endpoint}" == "" ]]; then
		return
	fi

	# Collect all the existing podIds as seen by crictl.
	podList=$(crictl --runtime-endpoint ${host_crio_runtime_endpoint} ps | awk 'NR>1 {print $NF}')
	for pod in ${podList}; do
		# Avoid doing any sanity checking in these steps as we don't want to
		# interrupt the process if any of the instructions fail for a particular
		# pod.
		crictl --runtime-endpoint "${host_crio_runtime_endpoint}" stopp ${pod}
		crictl --runtime-endpoint "${host_crio_runtime_endpoint}" rmp ${pod}
	done
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
	   die "This script must be run as root"
	fi

	get_crio_runtime_endpoint
	revert_kubelet_config
	stop_kubelet
	clean_crio_runtime_state
	start_kubelet
}

main "$@"
