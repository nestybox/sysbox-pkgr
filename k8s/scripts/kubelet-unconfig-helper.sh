#!/bin/bash -x

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

var_lib_sysbox_deploy_k8s="/var/lib/sysbox-deploy-k8s"
crictl_bin="/usr/local/bin/sysbox-deploy-k8s-crictl"
kubelet_bin=""
runtime=""

# Container's default restart-policy mode (i.e. no restart).
kubelet_ctr_restart_mode="no"

function die() {
	msg="$*"
	echo "ERROR: $msg" >&2
	exit 1
}

function get_kubelet_bin() {
	local tmp=$(systemctl show kubelet | grep "ExecStart=" | cut -d ";" -f1)
	tmp=${tmp#"ExecStart={ path="}
	echo "$tmp" | xargs
}

function get_kubelet_service_dropin_file() {
	systemctl show kubelet | grep "^DropInPaths" | cut -d "=" -f2
}

# Wipe out all the pods previously created by the current runtime (i.e., CRI-O)
function clean_runtime_state() {

	# Collect all the existing podIds as seen by crictl.
	podList=$($crictl_bin --runtime-endpoint "$runtime" pods | awk 'NR>1 {print $1}')

	# Turn off errexit in these steps as we don't want to interrupt the process
	# if any of the instructions fail for a particular pod / container.
	set +e

	# Stop / remove all the existing pods.
	for pod in ${podList}; do
		ret=$($crictl_bin --runtime-endpoint "$runtime" stopp ${pod})
		if [ $? -ne 0 ]; then
			echo "Failed to stop pod ${pod}: $ret"
		fi

		ret=$($crictl_bin --runtime-endpoint "$runtime" rmp ${pod})
		if [ $? -ne 0 ]; then
			echo "Failed to remove pod ${pod}: $ret"
		fi
	done

	# At this point all the pre-existing containers may be stopped and eliminated,
	# but there may be inactive containers that we want to eliminate too.
	cntrList=$($crictl_bin --runtime-endpoint "$runtime" ps -a | awk 'NR>1 {print $1}')

	for cntr in ${cntrList}; do
		ret=$($crictl_bin --runtime-endpoint "$runtime" stop --timeout 0 "$cntr")
		if [ $? -ne 0 ]; then
			echo "Failed to stop container ${cntr}: ${ret}"
		fi

		ret=$($crictl_bin --runtime-endpoint "$runtime" rm --force "$cntr")
		if [ $? -ne 0 ]; then
			echo "Failed to remove container ${cntr}: ${ret}"
		fi
	done

	set -e

	# Revert the runtime socket changes made during installation.
	local prior_runtime=$(cat ${var_lib_sysbox_deploy_k8s}/prior_runtime)
	local prior_runtime_path=$(echo $prior_runtime | sed 's@unix://@@' | cut -d" " -f1)

	# We don't want to restart containerd in RKE2 scenarios as this one should
	# be only managed by the rke2-agent.
	#
	# TODO: Do some refactoring to merge these two "containerd" scenarios by
	# moving out the container-restart instruction to the caller.
	if echo "$prior_runtime" | egrep -q "k3s.*containerd"; then
		# This is a softlink created by kubelet-config-helper; remove it.
		rm -f "$prior_runtime_path"

	elif [[ "$prior_runtime" =~ "containerd" ]]; then
		rm -f "$prior_runtime_path"

		echo "Re-starting containerd on the host ..."
		systemctl restart containerd
	fi

	if [[ "$prior_runtime" =~ "dockershim" ]]; then
		rm -f /var/run/dockershim.sock

		echo "Re-starting docker on the host ..."
		systemctl restart docker
	fi
}

# Sets the restart-policy mode for any given docker container.
function set_ctr_restart_policy() {
	local cntr=$1
	local mode=$2

	# Docker's supported restart-policy modes.
	if [[ $mode != "no" ]] &&
		[[ $mode != "always" ]] &&
		[[ $mode != "on-failure" ]] &&
		[[ $mode != "unless-stopped" ]]; then
		echo "Unsupported restart-policy mode: $mode"
		return
	fi

	if ! docker update --restart=$mode $cntr; then
		echo "Unable to modify container $cntr restart mode to $mode."
		return
	fi

	echo "Successfully modified $cntr container's restart-policy to mode: $mode."
}

# Sets the restart-policy mode for the kubelet docker container.
function set_kubelet_ctr_restart_policy() {
	local mode=$1

	kubelet_ctr_restart_mode=$(docker inspect --format='{{.HostConfig.RestartPolicy.Name}}' kubelet)

	set_ctr_restart_policy "kubelet" $mode
}

# Reverts the restart-policy mode previously stored in a global-variable.
function revert_kubelet_ctr_restart_policy() {
	set_ctr_restart_policy "kubelet" $kubelet_ctr_restart_mode
}

###############################################################################
# Scenario 1: Snap setup -- Snap-based kubelet
###############################################################################

function restart_kubelet_snap() {
	snap restart $kubelet_snap
}

function stop_kubelet_snap() {
	snap stop $kubelet_snap
}

function revert_kubelet_config_snap() {
	local prior_runtime=$(cat ${var_lib_sysbox_deploy_k8s}/prior_runtime)

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

function get_runtime_kubelet_snap() {

	# If runtime is unknown, assume it's Docker.
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi

	local ctr_runtime_type=$(snap get $kubelet_snap container-runtime)
	if [[ "$ctr_runtime_type" == "remote" ]]; then
		runtime=$(snap get $kubelet_snap container-runtime-endpoint)
	fi
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

function kubelet_snap_deployment() {
	snap list 2>&1 | grep -q kubelet
}

###############################################################################
# Scenario 2: RKE setup -- Docker-based kubelet created by rke tool
###############################################################################

function restart_kubelet_rke() {
	docker restart kubelet
}

function stop_kubelet_rke() {
	docker stop kubelet
}

function get_runtime_kubelet_docker() {
	set +e
	runtime=$(docker exec kubelet bash -c "ps -e -o command | egrep \^kubelet | egrep -o \"container-runtime-endpoint=\S*\" | cut -d '=' -f2")
	set -e

	# If runtime is unknown, assume it's Docker.
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function revert_kubelet_config_rke() {

	# Obtain kubelet's container entrypoint.
	local kubelet_entrypoint=$(docker inspect --format='{{index .Config.Entrypoint 0}}' kubelet)

	if [ -z ${kubelet_entrypoint} ] ||
		! docker exec kubelet bash -c "test -f ${kubelet_entrypoint}.orig"; then
		echo "Failed to revert kubelet config; original entrypoint not found: ${kubelet_entrypoint}.orig"
		return
	fi

	echo "Reverting kubelet's RKE config"

	# Revert to original entrypoint.
	docker exec kubelet bash -c "mv ${kubelet_entrypoint}.orig ${kubelet_entrypoint}"
}

function do_unconfig_kubelet_rke() {
	echo "Detected RKE's docker-based kubelet deployment on host."

	get_runtime_kubelet_docker
	if [[ ! ${runtime} =~ "crio" ]]; then
		echo "Expected kubelet to be using CRI-O, but it's using $runtime; no action will be taken."
		return
	fi

	# In RKE's case we must add a few steps to the typical logic utilized in other
	# setups. In this case, as kubelet executes as the 'init' process of a docker
	# container, we must do the following:
	#
	# * Modify kubelet's container restart-policy to prevent this one from being
	#   re-spawned by docker once that we temporarily shut it down.
	# * Revert the kubelet's container entrypoint to honor its original
	#   initialization attributes.
	# * Once the usual kubelet's "stop + clean + restart" cycle is completed, we
	#   must revert the changes made to the kubelet's container restart-policy.

	set_kubelet_ctr_restart_policy "no"
	revert_kubelet_config_rke
	stop_kubelet_rke
	clean_runtime_state
	restart_kubelet_rke
	revert_kubelet_ctr_restart_policy
}

function kubelet_rke_deployment() {
	# Docker presence is a must-have in rke setups. As we are enforcing this
	# requirement at the very beginning of the execution path, no other rke
	# related routine will check for docker's presence.
	if ! command -v docker >/dev/null 2>&1; then
		return 1
	fi

	docker inspect --format='{{.Config.Labels}}' kubelet |
		egrep -q "rke.container.name:kubelet"
}

###############################################################################
# Scenario 3: RKE2 setup -- Host-based kubelet managed by rke2-agent's systemd
# service
###############################################################################

function start_rke2() {
	echo "Starting RKE2 agent ..."
	systemctl start rke2-agent
}

function stop_rke2() {
	echo "Stopping RKE2 agent ..."
	systemctl stop rke2-agent
}

function revert_kubelet_config_rke2() {

	echo "Executing RKE2's Kubelet revert configuration function ..."

	local rancher_config="/etc/rancher/rke2/config.yaml"

	if egrep -q "container-runtime-endpoint:.*crio.sock" "$rancher_config"; then
		sed -i '/container-runtime-endpoint:/d' "$rancher_config"
	fi
}

function get_runtime_kubelet_rke2() {
	set +e
	runtime=$(ps -e -o command | egrep kubelet | egrep -o "container-runtime-endpoint=\S*" | cut -d '=' -f2)
	set -e

	# If runtime is unknown, assume it's Docker.
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function do_unconfig_kubelet_rke2() {
	echo "Detected RKE2's host-based kubelet deployment on host."

	get_runtime_kubelet_rke2
	if [[ ! ${runtime} =~ "crio" ]]; then
		echo "Expected kubelet to be using CRI-O, but it's using $runtime; no action will be taken."
		return
	fi

	stop_rke2
	clean_runtime_state
	revert_kubelet_config_rke2
	start_rke2
}

function kubelet_rke2_deployment() {

	# Worker nodes in RKE2 setups rely on rke2-agent's systemd service.
	if systemctl is-active --quiet rke2-agent; then
		return
	fi

	false
}

###############################################################################
# Scenario 4: Docker-based kubelet managed through a systemd service
###############################################################################

function get_runtime_kubelet_systemctl {
	set +e
	# Notice that in this scenario there may be more than one 'container-runtime'
	# entry present in the kubelet's exec instruction, so we must only look at
	# the latest (relevant) one.
	runtime=$(ps -e -o command | egrep kubelet | egrep -o "container-runtime-endpoint=\S*" | tail -1 | cut -d '=' -f2)
	set -e

	# If runtime is unknown, assume it's Docker.
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function do_unconfig_kubelet_docker_systemd() {
	echo "Detected systemd-managed docker-based kubelet deployment on host."

	get_runtime_kubelet_systemctl
	if [[ ! ${runtime} =~ "crio" ]]; then
		echo "Expected kubelet to be using CRI-O, but it's using $runtime; no action will be taken."
		return
	fi

	stop_kubelet
	clean_runtime_state
	revert_kubelet_config
	start_kubelet
}

function kubelet_docker_systemd_deployment() {

	# Docker presence is a must-have requirement in these setups (obviously). As
	# we are enforcing this requirement at the very beginning of the execution
	# path, no other systemd-docker related routine will check for docker's
	# presence.
	if ! command -v docker >/dev/null 2>&1; then
		return 1
	fi

	# Ensure that a container named 'kubelet' exists (typical de-facto standard).
	if ! systemctl show kubelet.service | egrep -q "^ExecStart.*=docker run"; then
		return 1
	fi

	# Ensure that the entrypoint of this kubelet container is executing 'kubelet'
	# itself.
	if ! docker inspect --format='{{index .Config.Entrypoint 0}}' kubelet |
		awk -F "/" '{print $NF}' | egrep -q "kubelet"; then
		return 1
	fi
}

###############################################################################
# Scenario 5: Host-based kubelet managed through a systemd service
###############################################################################

function start_kubelet() {
	echo "Starting Kubelet ..."
	systemctl start kubelet
}

function restart_kubelet() {
	echo "Restarting Kubelet ..."
	systemctl restart kubelet
}

function stop_kubelet() {
	echo "Stopping Kubelet ..."
	systemctl stop kubelet
}

function revert_kubelet_config() {
	local config_file="${var_lib_sysbox_deploy_k8s}/config"
	local kubelet_systemd_dropin="${var_lib_sysbox_deploy_k8s}/kubelet_systemd_dropin"
	local kubelet_sysbox_systemd_dropin="/etc/systemd/system/kubelet.service.d/01-kubelet-sysbox-dropin.conf"

	echo "Reverting kubelet config (from $config_file)"

	if [ ! -f "$config_file" ]; then
		echo "Failed to revert kubelet config; file $config_file not found."
		return
	fi

	if ! grep "kubelet_env_file" "$config_file"; then
		echo "Failed to revert kubelet config; config not found in $config_file"
		return
	fi

	# The config file will have these entries:
	#
	# * kubelet_env_file=/path/to/file
	# * kubelet_systemd_file=/path/to/file
	#
	# Below, we copy these original files back to their original locations.

	local target=$(grep "kubelet_env_file" "$config_file" | cut -d "=" -f2)
	if [ ! -z "$target" ]; then
		cp "${var_lib_sysbox_deploy_k8s}/kubelet_env_file.orig" "$target"
		rm "${var_lib_sysbox_deploy_k8s}/kubelet_env_file.orig"
	fi

	local target=$(grep "kubelet_systemd_file" "$config_file" | cut -d "=" -f2)
	if [ ! -z "$target" ]; then
		# If the primary kubelet systemd file was one artificially introduced by
		# Sysbox during installation, we simply want to remove it here. In the
		# other scenarios we must copy the original file to its former location.
		if [[ "$target" == "$kubelet_sysbox_systemd_dropin" ]]; then
			rm -r "$target"
		else
			cp "${var_lib_sysbox_deploy_k8s}/kubelet_systemd_file.orig" "$target"
			rm -r "${var_lib_sysbox_deploy_k8s}/kubelet_systemd_file.orig"
		fi

		systemctl daemon-reload
	fi

	rm "$config_file"
}

function do_unconfig_kubelet() {
	echo "Detected systemd-managed host-based kubelet deployment on host."

	# Obtain kubelet path.
	kubelet_bin=$(get_kubelet_bin)
	if [ -z "$kubelet_bin" ]; then
		die "Kubelet binary not identified."
	fi

	get_runtime_kubelet_systemctl
	if [[ ! ${runtime} =~ "crio" ]]; then
		echo "Expected kubelet to be using CRI-O, but it's using $runtime; no action will be taken."
		return
	fi

	stop_kubelet
	clean_runtime_state
	revert_kubelet_config
	restart_kubelet
}

function main() {

	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	#
	# The following kubelet deployment scenarios are currently supported:
	#
	# * Snap: Snap-based kubelet (as in Ubuntu-based AWS EKS nodes).
	# * RKE: Docker-based kubelet created as a static-pod (Rancher's RKE approach).
	# * RKE2: Host-based kubelet managed by rke2-agent's systemd service (Rancher's RKE2 approach).
	# * Systemd+Docker: Docker-based kubelet managed by a systemd service (Lokomotive's approach).
	# * Systemd: Host-based kubelet managed by a systemd service (most common approach).
	#
	if kubelet_snap_deployment; then
		do_unconfig_kubelet_snap
	elif kubelet_rke_deployment; then
		do_unconfig_kubelet_rke
	elif kubelet_rke2_deployment; then
		do_unconfig_kubelet_rke2
	elif kubelet_docker_systemd_deployment; then
		do_unconfig_kubelet_docker_systemd
	else
		do_unconfig_kubelet
	fi
}

main "$@"
