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

run_sysbox_deploy_k8s="/run/sysbox-deploy-k8s"
runtime=""

kubelet_bin="/usr/bin/kubelet"
crictl_bin="/usr/local/bin/sysbox-deploy-k8s-crictl"

function die() {
   msg="$*"
   echo "ERROR: $msg" >&2
   exit 1
}

function get_kubelet_bin() {
	local tmp=$(systemctl show kubelet | grep "ExecStart=" | cut -d ";" -f1)
	kubelet_bin=${tmp#"ExecStart={ path="}
	kubelet_bin=$(echo $kubelet_bin | xargs)
}

function revert_kubelet_config() {
	local config_file="${run_sysbox_deploy_k8s}/config"

	echo "Reverting kubelet config (from $config_file)"

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
	cp "${run_sysbox_deploy_k8s}/kubelet.orig" "$target"
	rm "${run_sysbox_deploy_k8s}/kubelet.orig"
	rm "$config_file"
}

function restart_kubelet() {
	echo "Restarting Kubelet ..."
	systemctl restart kubelet
}

function stop_kubelet() {
	echo "Stopping Kubelet ..."
	systemctl stop kubelet
}

function revert_kubelet_config_snap() {
	local prior_runtime=$(cat ${run_sysbox_deploy_k8s}/prior_runtime)

	echo "Reverting kubelet snap config"

	# If runtime is unknown, assume it's Docker
	if [[ ${prior_runtime} == "" ]] || [[ ${prior_runtime} =~ "docker" ]]; then
		echo "Reverting runtime to Docker"
		snap unset $kubelet_snap container-runtime-endpoint
		snap set $kubelet_snap container-runtime=docker
	else
		echo "Reverting runtime to $prior_runtime"
		snap set $kubelet_snap container-runtime-endpoint=${prior_runtime}
	fi
}

function restart_kubelet_snap() {
	snap restart $kubelet_snap
}

function stop_kubelet_snap() {
	snap stop $kubelet_snap
}

function get_runtime() {
	set +e
	runtime=$(systemctl status kubelet | egrep ${kubelet_bin} | egrep -o "container-runtime-endpoint=\S*" | cut -d '=' -f2)
	set -e

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function get_runtime_kubelet_snap() {

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi

	local ctr_runtime_type=$(snap get $kubelet_snap container-runtime)
	if [[ "$ctr_runtime_type" == "remote" ]]; then
		runtime=$(snap get $kubelet_snap container-runtime-endpoint)
	fi
}

# Wipe out all the pods previously created by the current runtime (i.e., CRI-O)
function clean_runtime_state() {

	# Collect all the existing podIds as seen by crictl.
	podList=$($crictl_bin --runtime-endpoint ${runtime} ps | awk 'NR>1 {print $NF}')

   # Cleanup the pods; turn off errexit in these steps as we don't want to
	# interrupt the process if any of the instructions fail for a particular
	# pod.
	set +e
	for pod in ${podList}; do
		ret=$($crictl_bin --runtime-endpoint "${runtime}" stopp ${pod})
		if [ $? -ne 0 ]; then
			echo "Failed to stop pod ${pod}: $ret"
		fi

		ret=$($crictl_bin --runtime-endpoint "${runtime}" rmp ${pod})
		if [ $? -ne 0 ]; then
			echo "Failed to remove pod ${pod}: $ret"
		fi
	done
	set -e

	# Restart prior runtime
	local prior_runtime=$(cat ${run_sysbox_deploy_k8s}/prior_runtime)

	if [[ "$prior_runtime" =~ "containerd" ]]; then

		# This is a softlink created by kubelet-config-helper; remove it.
		rm -f /var/run/containerd/containerd.sock

		echo "Re-starting containerd on the host ..."
		systemctl restart containerd
	fi

	if [[ "$prior_runtime" =~ "dockershim" ]]; then
		# This is a softlink created by kubelet-config-helper; remove it.
		rm -f /var/run/dockershim.sock

		echo "Re-starting docker on the host ..."
		systemctl restart docker
	fi
}

function do_unconfig() {
	get_kubelet_bin
	get_runtime

	if [[ ! ${runtime} =~ "crio" ]]; then
		echo "Expected kubelet to be using CRI-O, but it's using $runtime; no action will be taken."
		return
	fi

	stop_kubelet
	clean_runtime_state
	revert_kubelet_config
	restart_kubelet
}

function do_unconfig_kubelet_snap() {
	echo "Detected kubelet snap package on host."

	kubelet_snap=$(snap list | grep kubelet | awk '{print $1}')

	get_runtime_kubelet_snap

	if [[ ! ${runtime} =~ "crio" ]]; then
		echo "Expected kubelet to be using CRI-O, but it's using $runtime; no action will be taken."
		return
	fi

	stop_kubelet_snap
	clean_runtime_state
	revert_kubelet_config_snap
	restart_kubelet_snap
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
	   die "This script must be run as root"
	fi

	# Check if the kubelet is deployed via a snap service (as in Ubuntu-based AWS
	# EKS nodes); otherwise assume it's deployed via a systemd service.
	if snap list 2>&1 | grep -q kubelet; then
		do_unconfig_kubelet_snap
	else
		do_unconfig
	fi
}

main "$@"
