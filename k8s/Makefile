#
# Sysbox Deploy K8s Daemonset Makefile
#

.PHONY: sysbox-deploy-k8s-image \
	sysbox-ee-deploy-k8s-image \
	fetch_sysbox_ce_bionic_bins \
	fetch_sysbox_ce_focal_bins \
	fetch_sysbox_ee_bionic_bins \
	fetch_sysbox_ee_focal_bins \
	fetch_sysbox_ce_bins \
	fetch_sysbox_ee_bins \
	check-sysbox-artifacts \
	check-sysbox-ee-artifacts \
	check-crio-artifacts \
	clean-sysbox-ce clean-sysbox-ee clean-crio clean

SYSBOX_BINS = sysbox-runc sysbox-mgr sysbox-fs
SYSBOX_DISTRO = ubuntu-focal ubuntu-bionic
SYSBOX_VER = 0.4.1
CRIO_VERSIONS = v1.20 v1.21

#
# The fetch_* targets download the Sysbox binaries from the Sysbox repo and
# place them in the "bin" sub-directory. The *_image targets then load those
# binaries into the sysbox-deploy-k8s image. Variable SYSBOX_VER selects the
# version of the Sysbox binaries to download.
#
fetch_sysbox_ce_bionic_bins:
	$(eval TMPDIR := $(shell mktemp -d))
	echo "TMPDIR = $(TMPDIR)"
	wget https://downloads.nestybox.com/sysbox/releases/v$(SYSBOX_VER)/sysbox-ce_$(SYSBOX_VER)-0.ubuntu-bionic_amd64.deb -P $(TMPDIR)
	dpkg -x $(TMPDIR)/sysbox-ce_$(SYSBOX_VER)-0.ubuntu-bionic_amd64.deb $(TMPDIR)/sysbox-ce-ubuntu-bionic
	mkdir -p bin/sysbox-ce/ubuntu-bionic
	rm -rf bin/sysbox-ce/ubuntu-bionic/*
	cp $(TMPDIR)/sysbox-ce-ubuntu-bionic/usr/bin/sysbox-* bin/sysbox-ce/ubuntu-bionic/.
	rm -rf $(TMPDIR)

fetch_sysbox_ce_focal_bins:
	$(eval TMPDIR := $(shell mktemp -d))
	echo "TMPDIR = $(TMPDIR)"
	wget https://downloads.nestybox.com/sysbox/releases/v$(SYSBOX_VER)/sysbox-ce_$(SYSBOX_VER)-0.ubuntu-focal_amd64.deb -P $(TMPDIR)
	dpkg -x $(TMPDIR)/sysbox-ce_$(SYSBOX_VER)-0.ubuntu-focal_amd64.deb $(TMPDIR)/sysbox-ce-ubuntu-focal
	mkdir -p bin/sysbox-ce/ubuntu-focal
	rm -rf bin/sysbox-ce/ubuntu-focal/*
	cp $(TMPDIR)/sysbox-ce-ubuntu-focal/usr/bin/sysbox-* bin/sysbox-ce/ubuntu-focal/.
	rm -rf $(TMPDIR)

fetch_sysbox_ee_bionic_bins:
	$(eval TMPDIR := $(shell mktemp -d))
	echo "TMPDIR = $(TMPDIR)"
	wget https://downloads.nestybox.com/sysbox/releases/v$(SYSBOX_VER)/sysbox-ee_$(SYSBOX_VER)-0.ubuntu-bionic_amd64.deb -P $(TMPDIR)
	dpkg -x $(TMPDIR)/sysbox-ee_$(SYSBOX_VER)-0.ubuntu-bionic_amd64.deb $(TMPDIR)/sysbox-ee-ubuntu-bionic
	mkdir -p bin/sysbox-ee/ubuntu-bionic
	rm -rf bin/sysbox-ee/ubuntu-bionic/*
	cp $(TMPDIR)/sysbox-ee-ubuntu-bionic/usr/bin/sysbox-* bin/sysbox-ee/ubuntu-bionic/.
	rm -rf $(TMPDIR)

fetch_sysbox_ee_focal_bins:
	$(eval TMPDIR := $(shell mktemp -d))
	echo "TMPDIR = $(TMPDIR)"
	wget https://downloads.nestybox.com/sysbox/releases/v$(SYSBOX_VER)/sysbox-ee_$(SYSBOX_VER)-0.ubuntu-focal_amd64.deb -P $(TMPDIR)
	dpkg -x $(TMPDIR)/sysbox-ee_$(SYSBOX_VER)-0.ubuntu-focal_amd64.deb $(TMPDIR)/sysbox-ee-ubuntu-focal
	mkdir -p bin/sysbox-ee/ubuntu-focal
	rm -rf bin/sysbox-ee/ubuntu-focal/*
	cp $(TMPDIR)/sysbox-ee-ubuntu-focal/usr/bin/sysbox-* bin/sysbox-ee/ubuntu-focal/.
	rm -rf $(TMPDIR)

fetch_sysbox_ce_bins: fetch_sysbox_ce_bionic_bins fetch_sysbox_ce_focal_bins

fetch_sysbox_ee_bins: fetch_sysbox_ee_bionic_bins fetch_sysbox_ee_focal_bins

#
# The check-* targets verify that CRI-O and Sysbox binaries are in the "bin" directory:
#
# bin
# ├── crio
# │   ├── v1.20
# │   │   └── crio
# │   └── v1.21
# │       └── crio
# ├── sysbox-ce
# │   ├── ubuntu-bionic
# │   │   ├── sysbox-fs
# │   │   ├── sysbox-mgr
# │   │   └── sysbox-runc
# │   └── ubuntu-focal
# │       ├── sysbox-fs
# │       ├── sysbox-mgr
# │       └── sysbox-runc

check-sysbox-artifacts:
	@$(foreach distro,$(SYSBOX_DISTRO),$(foreach file,$(SYSBOX_BINS),[ -f "bin/sysbox-ce/$(distro)/$(file)" ] || "missing sysbox-ce binary: bin/sysbox-ce/$(distro)/$(file)";))

check-sysbox-ee-artifacts:
	@$(foreach distro,$(SYSBOX_DISTRO),$(foreach file,$(SYSBOX_BINS),[ -f "bin/sysbox-ee/$(distro)/$(file)" ] || "missing sysbox-ee binary: bin/sysbox-ee/$(distro)/$(file)";))

check-crio-artifacts:
	@$(foreach version,$(CRIO_VERSIONS),[ -f "bin/crio/$(version)/crio" ] || "missing CRI-O binary: bin/crio/$(version)/crio";)

#
# These targets build the sysbox-deploy-k8s images (for sysbox-ce and sysbox-ee)
#

all: sysbox-deploy-k8s-image sysbox-ee-deploy-k8s-image

sysbox-deploy-k8s-image: check-crio-artifacts fetch_sysbox_ce_bins check-sysbox-artifacts
	docker build -t ghcr.io/nestybox/sysbox-deploy-k8s:v$(SYSBOX_VER) -f Dockerfile.sysbox-ce .

sysbox-ee-deploy-k8s-image: check-crio-artifacts fetch_sysbox_ee_bins check-sysbox-ee-artifacts
	docker build -t ghcr.io/nestybox/sysbox-ee-deploy-k8s:v$(SYSBOX_VER) -f Dockerfile.sysbox-ee .

#
# Cleanup targets
#

clean-sysbox-ce:
	-rm -r bin/sysbox-ce

clean-sysbox-ee:
	-rm -r bin/sysbox-ee

clean-crio:
	-rm -r bin/crio

clean: clean-sysbox-ce clean-sysbox-ee clean-crio
