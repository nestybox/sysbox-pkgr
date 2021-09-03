#!/bin/sh

#
# Script to install and uninstall CRI-O on a Flatcar OS host.
#
# NOTE: adapted from the CRI-O release bundle Makefile
# found here: https://github.com/cri-o/cri-o/releases
#

PREFIX=/opt/crio
ETCDIR=/etc
CONTAINERS_DIR=${ETCDIR}/containers
CNIDIR=${ETCDIR}/cni/net.d
BINDIR=${PREFIX}/bin
MANDIR=${PREFIX}/share/man
OCIDIR=${PREFIX}/share/oci-umount/oci-umount.d
SELINUX=$(selinuxenabled 2>/dev/null && echo -Z)
BASHINSTALLDIR=${PREFIX}/share/bash-completion/completions
FISHINSTALLDIR=${PREFIX}/share/fish/completions
ZSHINSTALLDIR=${PREFIX}/share/zsh/site-functions
SYSTEMDDIR=${ETCDIR}/systemd/system
OPT_CNI_BIN_DIR=/opt/cni/bin

ARCH=amd64

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
	if [[ "${ARCH}" == "amd64" ]]; then
		install ${SELINUX} -D -m 755 -t ${BINDIR} bin/runc
	fi
}

function install_crun() {
	install ${SELINUX} -D -m 755 -t ${BINDIR} bin/crun
}

function uninstall() {
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
	rm ${CONTAINERS_DIR}/policy.json
	rm ${SYSTEMDDIR}/crio.service
}

function uninstall_pinns() {
	rm ${BINDIR}/pinns
}

function uninstall_runc() {
	if [[ "${ARCH}" == "amd64" ]]; then
		rm ${BINDIR}/runc
	fi
}

function uninstall_crun() {
	rm ${BINDIR}/crun
}

function main() {
	set -x
	if [[ "$1" == "" ]]; then
		printf "\n"
		printf "Usage: crio-extractor.sh [install | uninstall]\n"
		printf "\n"
		exit 1
	fi

	if [[ $1 == "install" ]]; then
		install_all
	elif [[ $1 == "uninstall" ]]; then
		uninstall
	fi
}

main "$@"
