#
# Sysbox Deploy K8s Daemonset Makefile
#

.PHONY: sysbox-deploy-k8s-image \
	fetch_sysbox_ce_bins \
	fetch_sysbox_ee_bins \
	check-sysbox-artifacts \
	check-crio-artifacts \
	clean-sysbox-ce clean-crio clean


SHELL := /bin/bash

SYSBOX_BINS = sysbox-runc sysbox-mgr sysbox-fs

# Obtain the version to build from the Sysbox repo itself. If a full version string
# is not found in the corresponding VERSION file, append a dummy revision/patch ("0")
# to match the name of the sysbox's deb image to download.
# Examples:
# 1) if VERSION = 0.6.3, then
#     SYSBOX_CE_VER        = 0.6.3
#     SYSBOX_CE_VER_SEMVER = 0.6.3
#     SYSBOX_CE_VER_FULL   = 0.6.3-0
#
# 2) if VERSION = 0.6.3-1, then
#     SYSBOX_CE_VER        = 0.6.3-1
#     SYSBOX_CE_VER_SEMVER = 0.6.3
#     SYSBOX_CE_VER_FULL   = 0.6.3-1
#
SYSBOX_CE_VER = $(shell cat ../sources/sysbox/VERSION)
SYSBOX_CE_VER_SEMVER = $(shell echo $(SYSBOX_CE_VER) | cut -d"-" -f1)
SYSBOX_CE_VER_FULL = $(shell echo $(SYSBOX_CE_VER) | sed '/-[0-9]/!s/.*/&-0/')

# CRIO versions to build.
CRIO_VERSIONS = v1.29 v1.30 v1.31 v1.32 v1.33

# Patch version is used to track changes to the sysbox-deploy-k8s image not related to
# the Sysbox's version. For example, if we need to rebuild the sysbox-deploy-k8s image
# due to a change in any of the files in this directory, we bump this patch version.
# If there's no need for a 'patch' version, then the patch version is set to nil (i.e.,
# empty). This is useful to distinguish between sysbox-deploy-k8s images that have the
# same Sysbox version but differ in other components (e.g., crio versions, supported
# k8s releases, etc.).
SYSBOX_DEPLOY_K8S_IMAGE_PATCH := ""

# Obtain the current system architecture.
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	SYS_ARCH := amd64
else ifeq ($(UNAME_M),aarch64)
	SYS_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
	SYS_ARCH := arm64
else ifeq ($(UNAME_M),arm)
	SYS_ARCH := armhf
else ifeq ($(UNAME_M),armel)
	SYS_ARCH := armel
endif

#
# Sysbox artifacts for Ubuntu distro
#

# The fetch_* targets download the Sysbox binaries from the Sysbox repo and
# place them in the "bin" sub-directory. The *_image targets then load those
# binaries into the sysbox-deploy-k8s image. Variable SYSBOX_CE_VER selects
# the version of the Sysbox binaries to download.

fetch-sysbox-ce-bins:
	@echo "Fetching Sysbox CE binaries ..."
	$(eval TMPDIR := $(shell mktemp -d))
	@echo "TMPDIR = $(TMPDIR)"
	wget https://storage.googleapis.com/sysbox-releases/v$(SYSBOX_CE_VER_SEMVER)/sysbox-ce/sysbox-ce_$(SYSBOX_CE_VER_FULL).linux_$(SYS_ARCH).deb -P $(TMPDIR)
	mkdir -p $(TMPDIR)/sysbox-ce-generic
	dpkg -x $(TMPDIR)/sysbox-ce_$(SYSBOX_CE_VER_FULL).linux_$(SYS_ARCH).deb $(TMPDIR)/sysbox-ce-generic
	mkdir -p bin/sysbox-ce/generic
	rm -rf bin/sysbox-ce/generic/*
	cp $(TMPDIR)/sysbox-ce-generic/usr/bin/sysbox-* bin/sysbox-ce/generic/.
	rm -rf $(TMPDIR)

#
# CRI-O artifacts (only built if not already present at ./bin/crio)
#
CRIO_BINS_DIR := $(PWD)/bin/crio

ifeq ($(wildcard $(CRIO_BINS_DIR)),)
build-crio: crio-build-container
	@echo "NOTE: building CRI-O binaries at ${PWD}/bin/crio"
	docker run --rm -v $(shell pwd)/bin:/mnt/results crio-bld
else
build-crio:
	@echo "NOTE: Skipping CRI-O build (found binaries at ${PWD}/bin/crio)"
endif

crio-build-container:
	docker build -t crio-bld -f Dockerfile.crio --build-arg sys_arch=$(SYS_ARCH) \
		--build-arg CRIO_VERSIONS="${CRIO_VERSIONS}" .

#
# The check-* targets verify that CRI-O, Sysbox binaries and its dependencies are
# all in the "bin" directory:
#
# bin
# ├── crio
# │   └── v1.24
# │       └── crio
# │   └── v1.25
# │       └── crio
# │   ├── v1.26
# │   │   └── crio
# │   ├── v1.27
# │   │   └── crio
# ├── sysbox-ce
# │   ├── ubuntu-bionic
# │   │   ├── sysbox-fs
# │   │   ├── sysbox-mgr
# │   │   └── sysbox-runc
# │   └── ubuntu-focal
# │       ├── sysbox-fs
# │       ├── sysbox-mgr
# │       └── sysbox-runc
#

check-sysbox-artifacts:
	$(foreach file,$(SYSBOX_BINS),[ -f "bin/sysbox-ce/generic/$(file)" ] || "missing sysbox-ce binary: bin/sysbox-ce/generic/$(file)")

check-crio-artifacts:
	@$(foreach version,$(CRIO_VERSIONS),[ -f "bin/crio/$(version)/crio" ] || "missing CRI-O binary: bin/crio/$(version)/crio";)
	@$(foreach version,$(CRIO_VERSIONS),[ -f "bin/crio/$(version)/pinns" ] || "missing CRI-O binary: bin/crio/$(version)/pinns";)

#
# These targets build the sysbox-deploy-k8s images for sysbox-ce
#

all: sysbox-deploy-k8s-image

sysbox-deploy-k8s-image: build-crio check-crio-artifacts fetch-sysbox-ce-bins check-sysbox-artifacts
	docker build -t ghcr.io/nestybox/sysbox-deploy-k8s:v$(SYSBOX_CE_VER_FULL)$(SYSBOX_DEPLOY_K8S_IMAGE_PATCH) \
		--build-arg sys_arch=$(SYS_ARCH) \
		--build-arg sysbox_version=v$(SYSBOX_CE_VER_FULL) \
		-f Dockerfile.sysbox-ce .

#
# Cleanup targets
#

clean-sysbox-ce:
	-rm -rf bin/sysbox-ce

clean-crio:
	-rm -rf bin/crio

clean: clean-sysbox-ce clean-crio
