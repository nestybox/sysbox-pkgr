#!/bin/bash

#
# CRI-O build script (meant to run inside the CRI-O build container)
#
# The script will build the Nestybox-customized CRI-O and place the binaries
# under /mnt/results. It builds several versions of CRI-O.
#
# Usage: docker run -v $(shell pwd)/bin:/mnt/results crio-bld
#

declare -a CRIO_VERSIONS=(v1.24 v1.25 v1.26 v1.27)

for ver in ${CRIO_VERSIONS[@]}; do
	printf "\n*** Building CRI-O ${ver} ... ***\n\n"
	TMPDIR=$(mktemp -d)
	chmod 755 ${TMPDIR}
	git clone https://github.com/nestybox/cri-o.git ${TMPDIR}/cri-o
	git -C ${TMPDIR}/cri-o checkout -b ${ver}-sysbox origin/${ver}-sysbox
	cd ${TMPDIR}/cri-o && make binaries
	mkdir -p /mnt/results/crio/${ver}
	cp ${TMPDIR}/cri-o/bin/crio-static /mnt/results/crio/${ver}/crio
done
