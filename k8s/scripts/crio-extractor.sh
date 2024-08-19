#!/bin/bash

#
# Script to install and uninstall CRI-O from a tar archive. Typically needed in
# OSes that don't have a package manager (e.g., Flatcar).
#
# NOTE: adapted from the CRI-O release bundle Makefile
# found here: https://github.com/cri-o/cri-o/releases
#

ETCDIR=/etc
CONTAINERS_DIR=${ETCDIR}/containers
CNIDIR=${ETCDIR}/cni/net.d
SYSTEMDDIR=${ETCDIR}/systemd/system
SELINUX=$(selinuxenabled 2>/dev/null && echo -Z)
OPT_CNI_BIN_DIR=/opt/cni/bin
VAR_LIB_SYSBOX_DEPLOY_K8S=/var/lib/sysbox-deploy-k8s

function install_all() {
	mkdir -p ${PREFIX}
	install_cni
	install_conmon
	install_crio
	install_crictl
	install_pinns
	install_runc
	install_crun
}

function install_cni() {
	install ${SELINUX} -d -m 755 ${CNIDIR}
	install ${SELINUX} -D -m 755 -t ${OPT_CNI_BIN_DIR} cni-plugins/*
	cp contrib/10-crio-bridge.conf contrib/100-crio-bridge.conf
	install ${SELINUX} -D -m 644 -t ${CNIDIR} contrib/100-crio-bridge.conf
}

function install_conmon() {
	install ${SELINUX} -D -m 755 -t ${BINDIR} bin/conmon
}

function install_crictl() {
	install ${SELINUX} -D -m 755 -t ${BINDIR} bin/crictl
}

function install_crio() {
	install ${SELINUX} -d -m 755 ${BASHINSTALLDIR}
	install ${SELINUX} -d -m 755 ${FISHINSTALLDIR}
	install ${SELINUX} -d -m 755 ${ZSHINSTALLDIR}
	install ${SELINUX} -d -m 755 ${CONTAINERS_DIR}
	install ${SELINUX} -D -m 755 -t ${BINDIR} bin/crio-status
	install ${SELINUX} -D -m 755 -t ${BINDIR} bin/crio
	install ${SELINUX} -D -m 644 -t ${ETCDIR} etc/crictl.yaml
	install ${SELINUX} -D -m 644 -t ${OCIDIR} etc/crio-umount.conf
	install ${SELINUX} -D -m 644 -t ${ETCDIR}/crio etc/crio.conf
	install ${SELINUX} -D -m 644 -t ${MANDIR}/man5 man/crio.conf.5
	install ${SELINUX} -D -m 644 -t ${MANDIR}/man5 man/crio.conf.d.5
	install ${SELINUX} -D -m 644 -t ${MANDIR}/man8 man/crio.8
	install ${SELINUX} -D -m 644 -t ${BASHINSTALLDIR} completions/bash/crio
	install ${SELINUX} -D -m 644 -t ${FISHINSTALLDIR} completions/fish/crio.fish
	install ${SELINUX} -D -m 644 -t ${ZSHINSTALLDIR} completions/zsh/_crio
	install ${SELINUX} -D -m 644 -t ${CONTAINERS_DIR} contrib/policy.json
	install ${SELINUX} -D -m 644 -t ${SYSTEMDDIR} contrib/crio.service
}

function install_pinns() {
	install ${SELINUX} -D -m 755 -t ${BINDIR} bin/pinns
}

function install_runc() {

	# If runc exists on the host, use it; otherwise install our own. This is
	# needed to avoid breaking pods that rely on the existing runc version.

	curr_runc=$(which runc)
	if [ $? -eq 0 ]; then
		if [[ "$curr_runc" != "${BINDIR}/bin/runc" ]]; then
			echo "Using existing runc (soft-linking ${BINDIR}/runc -> $curr_runc)"
			ln -s $curr_runc ${BINDIR}/runc
			mkdir -p ${VAR_LIB_SYSBOX_DEPLOY_K8S} && touch ${VAR_LIB_SYSBOX_DEPLOY_K8S}/linked_runc
		fi
	else
		echo "Installing runc at ${BINDIR}/bin/runc"
		install ${SELINUX} -D -m 755 -t ${BINDIR} bin/runc
		mkdir -p ${VAR_LIB_SYSBOX_DEPLOY_K8S} && touch ${VAR_LIB_SYSBOX_DEPLOY_K8S}/installed_runc
	fi
}

function install_crun() {
	install ${SELINUX} -D -m 755 -t ${BINDIR} bin/crun
}

function uninstall_all() {
	uninstall_cni
	uninstall_conmon
	uninstall_crio
	uninstall_crictl
	uninstall_pinns
	uninstall_runc
	uninstall_crun
}

function uninstall_cni() {
	rm ${CNIDIR}/100-crio-bridge.conf
}

function uninstall_conmon() {
	rm ${BINDIR}/conmon
}

function uninstall_crictl() {
	rm ${BINDIR}/crictl
}

function uninstall_crio() {
	rm ${BINDIR}/crio
	rm ${BINDIR}/crio-status
	rm ${ETCDIR}/crictl.yaml
	rm ${OCIDIR}/crio-umount.conf
	rm ${ETCDIR}/crio/crio.conf
	rm ${MANDIR}/man5/crio.conf.5
	rm ${MANDIR}/man5/crio.conf.d.5
	rm ${MANDIR}/man8/crio.8
	rm ${BASHINSTALLDIR}/crio
	rm ${FISHINSTALLDIR}/crio.fish
	rm ${ZSHINSTALLDIR}/_crio
	rm ${SYSTEMDDIR}/crio.service
}

function uninstall_pinns() {
	rm ${BINDIR}/pinns
}

function uninstall_runc() {

	if [ -f ${VAR_LIB_SYSBOX_DEPLOY_K8S}/installed_runc ]; then
		echo "Removing runc at ${BINDIR}/runc"
		rm ${BINDIR}/runc
		rm ${VAR_LIB_SYSBOX_DEPLOY_K8S}/installed_runc
	elif [ -f ${VAR_LIB_SYSBOX_DEPLOY_K8S}/linked_runc ]; then
		echo "Removing runc softlink at ${BINDIR}/runc"
		rm ${BINDIR}/runc
		rm ${VAR_LIB_SYSBOX_DEPLOY_K8S}/linked_runc
	fi

}

function uninstall_crun() {
	rm ${BINDIR}/crun
}

function main() {

	# Two parameters are expected:
	# * Action: install / uinstall
	# * Path: Top location where to install (uninstall) crio to (from).

	if [ "$#" -ne 2 ]; then
		printf "\n"
		printf "Usage: crio-extractor.sh [install | uninstall] path\n"
		printf "\n"
		exit 1
	fi

	# Set globals that depend on 'path' parameter.
	PREFIX="$2"
	BINDIR=${PREFIX}/bin
	MANDIR=${PREFIX}/share/man
	OCIDIR=${PREFIX}/share/oci-umount/oci-umount.d
	BASHINSTALLDIR=${PREFIX}/share/bash-completion/completions
	FISHINSTALLDIR=${PREFIX}/share/fish/completions
	ZSHINSTALLDIR=${PREFIX}/share/zsh/site-functions

	if [[ "$1" == "install" ]]; then
		install_all
	elif [[ "$1" == "uninstall" ]]; then
		uninstall_all
	fi
}

main "$@"
