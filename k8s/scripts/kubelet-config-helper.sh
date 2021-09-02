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
# Script to configure the kubelet with the CRI-O runtime on a host
#

set -o errexit
set -o pipefail
set -o nounset

run_sysbox_deploy_k8s="/run/sysbox-deploy-k8s"
runtime=""

kubelet_bin="/usr/bin/kubelet"
crictl_bin="/usr/local/bin/sysbox-deploy-k8s-crictl"

# Container's default restart-policy mode (i.e. no restart).
kubelet_ctr_restart_mode="no"

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

function replace_cmd_option {
	cmd_opts=$1
	opt=$2
	want_val=$3

	read -a curr_args <<<${cmd_opts}
	declare -a new_args

	found_opt=false

	for arg in "${curr_args[@]}"; do

		new_arg=$arg

		if [[ "$arg" == "$opt="* ]]; then
			found_opt=true
			val=${arg#"$opt="}
			if [[ "$val" != "$want_val" ]]; then
				new_arg="$opt=$want_val"
			fi
		fi

		new_args+=($new_arg)
	done

	result=$(printf "%s " "${new_args[@]}")

	if ! $found_opt; then
		result="$result $opt=$want_val"
	fi

	echo $result
}

function get_kubelet_env_files() {
	systemctl show kubelet | grep EnvironmentFile | awk '{ print $1 }' | cut -d"=" -f2 | tr "\n" " "
}

function get_kubelet_env_var() {
	local env_var=$(systemctl show kubelet | grep ExecStart= | cut -d ";" -f2 | sed -e 's@argv\[\]=${kubelet_bin}@@g' | awk '{print $NF}')
	env_var=${env_var#"$"}
	echo $env_var
}

function get_kubelet_service_file() {
	systemctl show kubelet | grep "^FragmentPath" | cut -d "=" -f2
}

# Creates a systemd service unit "drop-in" file for the kubelet, configured to
# use the $env_var from the given $env_file.
function add_systemd_dropin_file() {
	local env_file=$1
	local env_var=$2

	local kubelet_service_file=$(get_kubelet_service_file)
	local exec_start=$(grep "^ExecStart=" $kubelet_service_file)

	mkdir -p "/etc/systemd/system/kubelet.service.d"

	cat >"/etc/systemd/system/kubelet.service.d/01-kubelet.conf" <<EOF
[service]
EnvironmentFile=-$env_file
ExecStart=
$exec_start \$$env_var
EOF

	echo "Created systemd drop-in file for kubelet (/etc/systemd/system/kubelet.service.d/01-kubelet.conf)"
}

# Adds the kubelet config in the given file; the given $env_file may or may not
# exist. If it does not exist, this function will create it and add or replace
# a definiton for $env_var
function add_kubelet_env_var() {
	local env_file=$1
	local env_var=$2

	# If the extra args file does not have the extra args/opts, add them as needed
	if [ ! -f "$env_file" ]; then
		mkdir -p $(dirname "$env_file")
		touch "$env_file"
		echo "Created kubelet env file $env_file"
	fi

	if ! grep -q "$env_var" "$env_file"; then
		echo "$env_var=\"\"" >>"$env_file"
	fi

	replace_kubelet_env_var "$env_file" "$env_var"
}

# Replaces the kubelet config in the given file; the given $env_file is assumed
# to exist and have a definition for $env_var in it already.
function replace_kubelet_env_var() {
	local env_file=$1
	local env_var=$2

	readarray -t opts <${run_sysbox_deploy_k8s}/crio-kubelet-options

	# add newline at end of $env_file if not present
	sed -i '$a\' "$env_file"

	touch tmp.txt

	while read -r line; do
		new_line=$line

		# ignore comment lines
		if [[ "$line" == "#*" ]]; then
			continue
		fi

		# replace the options in the line(s) starting with $env_var
		if [[ "$line" == "$env_var="* ]]; then

			line_prefix="$env_var"

			# Handle quoted or unquoted variable definitions ($env_var="..." or $env_var=...)
			if [[ "$line" == "$line_prefix=\""* ]]; then
				line_opts=$(echo $line | cut -d'"' -f2)
			else
				line_opts=${line#"$line_prefix"}
			fi

			set +e
			for opt in "${opts[@]}"; do
				opt_name=$(echo $opt | cut -d"=" -f1)
				opt_val=$(echo $opt | cut -d"=" -f2)
				if [[ "$opt_name" != "" ]] && [[ "$opt_val" != "" ]]; then
					if [[ $line_opts != "" ]]; then
						line_opts=$(replace_cmd_option "$line_opts" "$opt_name" "$opt_val")
					else
						line_opts="${opt_name}=${opt_val}"
					fi
				fi
			done
			set -e

			new_line="$line_prefix=\"$line_opts\""
		fi

		echo $new_line >>tmp.txt

	done <"$env_file"
	mv tmp.txt "$env_file"

	echo "Modified kubelet env var $env_var in $env_file"
}

function backup_orig_config() {
	local env_file=$1
	local config_file="${run_sysbox_deploy_k8s}/config"

	mkdir -p "$run_sysbox_deploy_k8s"

	if [ -f $env_file ]; then
		echo "kubelet_env_file=${env_file}" >"$config_file"
		cp "$env_file" "${run_sysbox_deploy_k8s}/kubelet.orig"
	fi
}

# Configures the kubelet to use CRI-O, by modifying the systemd unit files that
# contain the arguments passed to kubelet.
function config_kubelet() {

	local kubelet_env_files=$(get_kubelet_env_files)

	# If systemd shows no kubelet environment files, let's create one
	if [[ "$kubelet_env_files" == "" ]]; then
		kubelet_env_file="/etc/default/kubelet"
		kubelet_env_var="KUBELET_EXTRA_ARGS"
		backup_orig_config "$kubelet_env_file"
		add_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"
		add_systemd_dropin_file "$kubelet_env_file" "$kubelet_env_var"
		return
	fi

	# If no kubelet env var was found, let's use our default one
	local kubelet_env_var=$(get_kubelet_env_var)
	if [[ "$kubelet_env_var" == "" ]]; then
		kubelet_env_var="KUBELET_EXTRA_ARGS"
	fi

	# If systemd shows kubelet environment files, let's check if they exist and
	# if so replace the env variable ($kubelet_env_var)
	for kubelet_env_file in $kubelet_env_files; do
		if [ -f "$kubelet_env_file" ]; then
			if grep -q "$kubelet_env_var" "$kubelet_env_file"; then
				backup_orig_config "$kubelet_env_file"
				replace_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"
				return
			fi
		fi
	done

	# Either the kubelet env file does not exist, or it exists but does not
	# contain the $kubelet_env_var; lets create the file and/or add the
	# $kubelet_env_var to it.
	kubelet_env_file=$(echo "$kubelet_env_files" | awk '{print $NF}')

	if [ ! -f "$kubelet_env_file" ]; then
		touch "$kubelet_env_file"
	fi

	backup_orig_config "$kubelet_env_file"
	add_kubelet_env_var "$kubelet_env_file" "$kubelet_env_var"

	# Ask systemd to reload it's config
	systemctl daemon-reload
}

function restart_kubelet() {
	echo "Restarting Kubelet ..."
	systemctl restart kubelet
}

function stop_kubelet() {
	echo "Stopping Kubelet ..."
	systemctl stop kubelet
}

function config_kubelet_snap() {
	snap set $kubelet_snap container-runtime=remote
	snap set $kubelet_snap container-runtime-endpoint=unix:///var/run/crio/crio.sock
}

function restart_kubelet_snap() {
	snap restart $kubelet_snap
}

function stop_kubelet_snap() {
	snap stop $kubelet_snap
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

# Updates the entrypoint script corresponding to the kubelet container present
# in rke setups.
function config_kubelet_rke_update() {
	local env_file=$1

	local kubelet_entrypoint=$(docker inspect --format='{{index .Config.Entrypoint 0}}' kubelet)

	# Backup original entrypoint file -- to be utilized by kubelet-unconfig-helper
	# script to revert configuration.
	docker exec kubelet bash -c "cp ${kubelet_entrypoint} ${kubelet_entrypoint}.orig"

	# Extract the kubelet attributes to execute with.
	local kubelet_attribs=$(cat $env_file | cut -d'"' -f 2)

	# Adjust kubelet's container entrypoint to incorporate the new exec attributes.
	docker exec kubelet bash -c "sed -i 's@exec .*@exec kubelet ${kubelet_attribs}@' ${kubelet_entrypoint}"

	echo "Kubelet config updated within container's entrypoint: ${kubelet_entrypoint}"
}

# Configures the kubelet to use cri-o in rke setups.
function config_kubelet_rke() {

	# Temp variables to hold kubelet's config file and its config attributes.
	local kubelet_tmp_file="/etc/default/kubelet-rke"
	local kubelet_tmp_var="KUBELET_EXTRA_ARGS"

	# Extract kubelet's current execution attributes and store them in a temp file.
	local cur_kubelet_attr=$(docker exec kubelet bash -c "ps -e -o command | egrep \^kubelet | cut -d\" \" -f2-")
	echo "${kubelet_tmp_var}=\"${cur_kubelet_attr}\"" >"${kubelet_tmp_file}"

	# Add crio-specific config attributes to the temporary kubelet config file.
	replace_kubelet_env_var "$kubelet_tmp_file" "$kubelet_tmp_var"

	# Modify the actual kubelet's config file (container entrypoint) to reflect
	# the new attributes obtained above.
	config_kubelet_rke_update "$kubelet_tmp_file"

	rm -rf "$kubelet_tmp_file"
}

function restart_kubelet_rke() {
	docker restart kubelet
}

function stop_kubelet_rke() {
	docker stop kubelet
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

function get_runtime_rke() {
	set +e
	runtime=$(docker exec kubelet bash -c "ps -e -o command | egrep \^kubelet | egrep -o \"container-runtime-endpoint=\S*\" | cut -d '=' -f2")
	set -e

	# If runtime is unknown, assume it's Docker
	if [[ ${runtime} == "" ]]; then
		runtime="unix:///var/run/dockershim.sock"
	fi
}

function clean_runtime_state_containerd() {
	local runtime=$1

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

	echo "Stopping containerd on the host ..."
	systemctl stop containerd.service

	# Create a soft link from the containerd socket to the crio socket
	# (some pods are designed to talk to containerd (e.g., gke-metadata-server)).
	echo "Soft-linking containerd socket to CRI-O socket on the host ..."
	rm -f /var/run/containerd/containerd.sock
	ln -s /var/run/crio/crio.sock /var/run/containerd/containerd.sock
}

function clean_runtime_state_dockershim() {
	local runtime=$1
	shift
	local podUids=("$@")

	# Collect all the existing containers as seen by docker.
	local cntrList=$(docker ps | awk 'NR>1 {print $1}')

	# Cleanup the pods; turn off errexit in these steps as we don't want to
	# interrupt the process if any of the instructions fail for a particular
	# pod / container.
	set +e

	for podUid in ${podUids}; do
		for cntr in ${cntrList}; do
			ret=$(docker inspect --format='{{index .Config.Labels "io.kubernetes.pod.uid"}}' $cntr 2>/dev/null | grep -q $podUid)
			if [ $? -ne 0 ]; then
				continue
			fi

			ret=$(docker stop -t0 $cntr)
			if [ $? -ne 0 ]; then
				echo "Failed to stop cntr ${cntr} from pod ${podUid}: $ret"
			fi

			ret=$(docker rm $cntr)
			if [ $? -ne 0 ]; then
				echo "Failed to remove cntr ${cntr} from pod ${podUid}: $ret"
			fi
		done
	done

	set -e

	# Create a soft link from the dockershim socket to the crio socket
	# (some pods are designed to talk to dockershim (e.g., aws-node)).
	echo "Soft-linking dockershim socket to CRI-O socket on the host ..."
	rm -f /var/run/dockershim.sock
	ln -s /var/run/crio/crio.sock /var/run/dockershim.sock
}

# Wipe out all the pods managed by the given container runtime (dockershim, containerd, etc.)
function clean_runtime_state() {
	local runtime=$1
	shift
	local podUids=("$@")

	if [[ "$runtime" =~ "containerd" ]]; then
		clean_runtime_state_containerd "$runtime"
	elif [[ "$runtime" =~ "dockershim" ]]; then
		clean_runtime_state_dockershim "$runtime" "$podUids"
	else
		echo "Container runtime not supported: ${runtime}"
		return
	fi

	# Store info about the prior runtime on the host so the
	# kubelet-unconfig-helper service can revert it if/when the crio-cleanup-k8s
	# daemonset runs.
	mkdir -p "$run_sysbox_deploy_k8s"
	echo $runtime >${run_sysbox_deploy_k8s}/prior_runtime
}

function get_pods_uids() {
	$crictl_bin --runtime-endpoint ${runtime} pods -v | egrep ^UID | cut -d" " -f2
}

function do_config_kubelet() {

	get_kubelet_bin
	get_runtime

	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	# The ideal sequence is to stop the kubelet, cleanup all pods with the
	# existing runtime, reconfig the kubelet, and restart it. But if the runtime
	# is dockershim this logic does not work well by itself, because after stopping
	# the kubelet the dockershim also stops. Thus, for dockershim we must complement
	# this logic with an extra step: we obtain all the existing pods before
	# stopping kubelet (A), and later on, once that kubelet is stopped (B), we
	# eliminate these pods through the docker-cli interface (C). Technically,
	# there's room for a race-condition scenario in which new pods could be deployed
	# right between (A) and (B), but being the time-window so small, we can safely
	# ignore this case in most setups; in the worst case scenario we would simply
	# end up with a duplicated/stale ("non-ready") pod instantiation, but this
	# wouldn't affect the proper operation of the primary ("ready") one.

	if [[ ${runtime} =~ "dockershim" ]]; then
		local podUids=$(get_pods_uids)
		stop_kubelet
		clean_runtime_state "$runtime" "$podUids"
		config_kubelet
		restart_kubelet
	else
		stop_kubelet
		clean_runtime_state "$runtime"
		config_kubelet
		restart_kubelet
	fi
}

function do_config_kubelet_snap() {
	echo "Detected kubelet snap package on host."

	kubelet_snap=$(snap list | grep kubelet | awk '{print $1}')

	get_runtime_kubelet_snap

	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	if [[ ${runtime} =~ "dockershim" ]]; then
		local podUids=$(get_pods_uids)
		stop_kubelet_snap
		clean_runtime_state "$runtime" "$podUids"
		config_kubelet_snap
		restart_kubelet_snap
	else
		stop_kubelet_snap
		clean_runtime_state "$runtime"
		config_kubelet_snap
		restart_kubelet_snap
	fi
}

function do_config_kubelet_rke() {
	echo "Detected kubelet RKE deployment on host."

	get_runtime_rke

	if [[ ${runtime} =~ "crio" ]]; then
		echo "Kubelet is already using CRI-O; no action will be taken."
		return
	fi

	# No runtime other than dockershim, and obviously crio, are expected in an
	# rke deployment.
	if [[ ! ${runtime} =~ "dockershim" ]]; then
		echo "Unsupported runtime for RKE scenario: $runtime"
		return
	fi

	# RKE bind-mounts /sys into its kubelet container to be able to write directly
	# into the hosts /sys/fs/cgroup path. With that goal in mind, RKE's kubelet
	# container entrypoint does a RW remount of /sys/fs/cgroup mountpoint. However,
	# this doesn't help host-based processes that require RW access to the cgroups
	# path (such as cri-o), that's why here we explicitly remount /sys/fs/cgroup as
	# RW within the init mount-ns.
	if mount | grep -q "/sys/fs/cgroup .*ro,"; then
		mount -o rw,remount /sys/fs/cgroup
	fi

	# In RKE's case we must add a few steps to the typical logic utilized in other
	# dockershim setups. In this case, as kubelet executes as the 'init' process
	# of a docker container, we must do the following:
	#
	# * Modify kubelet's container restart-policy to prevent this one from being
	#   re-spawned by docker once that we temporarily shut it down.
	# * Configurate the kubelet's container entrypoint to meet cri-o requirements.
	# * Once the usual kubelet's "stop + clean + restart" cycle is completed, we
	#   must revert the changes made to the kubelet's container restart-policy.

	set_kubelet_ctr_restart_policy "no"
	config_kubelet_rke
	local podUids=$(get_pods_uids)
	stop_kubelet_rke
	clean_runtime_state "$runtime" "$podUids"
	restart_kubelet_rke
	revert_kubelet_ctr_restart_policy
}

function kubelet_snap_deployment() {
	snap list 2>&1 | grep -q kubelet
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

# Enforce the common requirements needed for Sysbox + CRI-O's proper operation.
function set_common_requirements() {
	# Verify that /sys is mounted as read-write; otherwise remount it.
	if mount | grep -q "/sys .*ro,"; then
		mount -o rw,remount /sys
	fi
}

function main() {
	set -x
	euid=$(id -u)
	if [[ $euid -ne 0 ]]; then
		die "This script must be run as root"
	fi

	set_common_requirements

	#
	# The following kubelet deployment scenarios are currently supported:
	#
	# * Snap: Kubelet deployed via a snap service (as in Ubuntu-based AWS EKS nodes).
	# * RKE: Kubelet deployed as part of a docker container (Rancher's RKE approach).
	# * Systemd: Kubelet deployed via a systemd service (most common approach).
	#
	if kubelet_snap_deployment; then
		do_config_kubelet_snap
	elif kubelet_rke_deployment; then
		do_config_kubelet_rke
	else
		do_config_kubelet
	fi
}

main "$@"
