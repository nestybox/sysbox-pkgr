#
# Sysbox Deploy K8s Daemonset Makefile
#

.PHONY: sysbox-deploy-k8s-image \
	sysbox-ee-deploy-k8s-image \
	sysbox-ee-deploy-k8s-image-artifacts \
	sysbox-ee-deploy-k8s-image-flatcar-artifacts \
	fetch_sysbox_ce_bins \
	fetch_sysbox_ee_bins \
	check-sysbox-artifacts \
	check-sysbox-ee-artifacts \
	check-crio-artifacts \
	clean-sysbox-ce clean-sysbox-ee clean-crio clean


SHELL := /bin/bash

SYSBOX_BINS = sysbox-runc sysbox-mgr sysbox-fs
SYSBOX_FLATCAR_BINS = $(SYSBOX_BINS) fusermount shiftfs.ko
SYSBOX_VER = 0.5.0
CRIO_VERSIONS = v1.20 v1.21

# Supported Flatcar versions
FLATCAR_VERSIONS := 2905.2.3 2905.2.6 3033.2.4
FLATCAR_2905.2.3_KERNEL := "5.10.61-flatcar"
FLATCAR_2905.2.6_KERNEL := "5.10.75-flatcar"
FLATCAR_3033.2.4_KERNEL := "5.10.107-flatcar"
FLATCAR_DEV_ENVS := FLATCAR_DEV_ENV_2905.2.3 FLATCAR_DEV_ENV_2905.2.6 FLATCAR_DEV_ENV_3033.2.4

# Obtain the current system architecture.
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	SYS_ARCH := amd64
else ifeq ($(UNAME_M),aarch64)
	SYS_ARCH := arm64
else ifeq ($(UNAME_M),arm)
	SYS_ARCH := armhf
else ifeq ($(UNAME_M),armel)
	SYS_ARCH := armel
endif

# Flatcar didn't add arm64 support till '3033' stable release.
ifeq ($(SYS_ARCH),ARM64)
       FLATCAR_VERSIONS := $(shell echo ${FLATCAR_VERSIONS} | cut -f3- -d" ")
endif


#
# Sysbox artifacts for Ubuntu distro
#

# The fetch_* targets download the Sysbox binaries from the Sysbox repo and
# place them in the "bin" sub-directory. The *_image targets then load those
# binaries into the sysbox-deploy-k8s image. Variable SYSBOX_VER selects the
# version of the Sysbox binaries to download.

fetch-sysbox-ce-bins:
	$(eval TMPDIR := $(shell mktemp -d))
	echo "TMPDIR = $(TMPDIR)"
	wget https://downloads.nestybox.com/sysbox/releases/v$(SYSBOX_VER)/sysbox-ce_$(SYSBOX_VER)-0.linux_$(SYS_ARCH).deb -P $(TMPDIR)
	mkdir -p $(TMPDIR)/sysbox-ce-generic
	dpkg -x $(TMPDIR)/sysbox-ce_$(SYSBOX_VER)-0.linux_$(SYS_ARCH).deb $(TMPDIR)/sysbox-ce-generic
	mkdir -p bin/sysbox-ce/generic
	rm -rf bin/sysbox-ce/generic/*
	cp $(TMPDIR)/sysbox-ce-generic/usr/bin/sysbox-* bin/sysbox-ce/generic/.
	rm -rf $(TMPDIR)

fetch-sysbox-ee-bins:
	$(eval TMPDIR := $(shell mktemp -d))
	echo "TMPDIR = $(TMPDIR)"
	wget https://downloads.nestybox.com/sysbox/releases/v$(SYSBOX_VER)/sysbox-ee_$(SYSBOX_VER)-0.linux_$(SYS_ARCH).deb -P $(TMPDIR)
	mkdir -p $(TMPDIR)/sysbox-ee-generic
	dpkg -x $(TMPDIR)/sysbox-ee_$(SYSBOX_VER)-0.linux_$(SYS_ARCH).deb $(TMPDIR)/sysbox-ee-generic
	mkdir -p bin/sysbox-ee/generic
	rm -rf bin/sysbox-ee/generic/*
	cp $(TMPDIR)/sysbox-ee-generic/usr/bin/sysbox-* bin/sysbox-ee/generic/.
	rm -rf $(TMPDIR)


#
# Sysbox artifacts, and its dependencies, for Flatcar distro.
#
# Flatcar binaries are built in two stages:
#
# 1) We first build a flatcar dev-environment where sysbox binaries can be created.
#    To do this we initially build a docker container by importing the official
#    Flatcar dev container image. We rely on this official (original) image to build
#    a secondary (enhanced) dev environment image where kernel and kernel-module
#    resources are exposed.
#
# 2) This enhanced dev-environment image serves as the baseline over which we create
#    a Flatcar's sysbox-test image. Finally, Sysbox artifacts are generated in this
#    container.
#

build-flatcar-sysbox-ee-bins: $(FLATCAR_VERSIONS)

$(FLATCAR_VERSIONS): $(FLATCAR_DEV_ENVS)
	@printf "\n*** Building Sysbox's flatcar-$@ binaries ... ***\n\n"
	@make -C ../ sources/sysbox-internal
	@make -C ../sources/sysbox-internal/ FLATCAR_VERSION=$@ FLATCAR_KERNEL=$(FLATCAR_$@_KERNEL) sysbox-flatcar
	@mkdir -p bin/sysbox-ee/flatcar-$@
	cp ../sources/sysbox-internal/build/flatcar-$@/$(SYS_ARCH)/* bin/sysbox-ee/flatcar-$@/
	@printf "\n*** Completed building Sysbox's flatcar-$@ binaries on $(SYS_ARCH) architecture ... ***\n\n"

$(FLATCAR_DEV_ENVS):
	$(eval FLATCAR_VERSION := $(subst FLATCAR_DEV_ENV_,,$@))

	if docker inspect --type=image ghcr.io/nestybox/flatcar-${FLATCAR_VERSION}-dev-container:latest >/dev/null 2>&1; then		\
		printf "\n*** Flatcar-${FLATCAR_VERSION} dev-environment image found. Skipping build process ... ***\n\n"; 		\
	else																												\
		printf "\n*** Building Flatcar-${FLATCAR_VERSION} dev-environment for ${SYS_ARCH} architecture ... ***\n\n";									\
		TMPDIR=$$(mktemp -d);																							\
		chmod 755 $${TMPDIR};																							\
																														\
		# Fetch flatcar's official dev image and import it into a docker container.										\
		curl -L https://stable.release.flatcar-linux.net/$(SYS_ARCH)-usr/${FLATCAR_VERSION}/flatcar_developer_container.bin.bz2 \
			-o $${TMPDIR}/flatcar_developer_container.bin.bz2;															\
		bunzip2 -k $${TMPDIR}/flatcar_developer_container.bin.bz2;														\
		mkdir -p $${TMPDIR}/${FLATCAR_VERSION};																			\
		sudo mount -o ro,loop,offset=2097152 $${TMPDIR}/flatcar_developer_container.bin $${TMPDIR}/${FLATCAR_VERSION};	\
		sudo tar -cp --one-file-system -C $${TMPDIR}/${FLATCAR_VERSION} . |												\
			docker import - ghcr.io/nestybox/flatcar-dev-container-original:${FLATCAR_VERSION};							\
																														\
		# Build enhanced dev-container image.																			\
		docker image build																								\
			--build-arg FLATCAR_VERSION=${FLATCAR_VERSION} 																\
			--tag ghcr.io/nestybox/flatcar-${FLATCAR_VERSION}-dev-container:${SYS_ARCH} 											\
			-f Dockerfile.flatcar.dev .; 																				\
																														\
		sudo umount $${TMPDIR}/${FLATCAR_VERSION}; 																		\
		sudo rm -rf $${TMPDIR};						 																	\
		printf "\n*** Completed building Flatcar's dev-environment image. ***\n\n";										\
	fi

#
# CRI-O artifacts
#

build-crio: $(CRIO_VERSIONS)

$(CRIO_VERSIONS):
	@printf "\n*** Building cri-o $@ ... ***\n\n"
	$(eval TMPDIR := $(shell mktemp -d))
	@chmod 755 $(TMPDIR)
	@git clone git@github.com:nestybox/cri-o.git $(TMPDIR)/cri-o
	@git -C $(TMPDIR)/cri-o checkout -b $@-sysbox origin/$@-sysbox
	@cd $(TMPDIR)/cri-o && make binaries
	@mkdir -p bin/crio/$@
	@cp $(TMPDIR)/cri-o/bin/crio-static bin/crio/$@/crio
	@chmod 755 -R $(TMPDIR) && rm -rf $(TMPDIR)

#
# The check-* targets verify that CRI-O, Sysbox binaries and its dependencies, are
# all in the "bin" directory:
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
# └── sysbox-ee
#     ├── flatcar-2905.2.3
#     │   ├── fusermount
#     │   ├── shiftfs.ko
#     │   ├── sysbox-fs
#     │   ├── sysbox-mgr
#     │   └── sysbox-runc
#     ├── flatcar-2905.2.6
#     │   ├── fusermount
#     │   ├── shiftfs.ko
#     │   ├── sysbox-fs
#     │   ├── sysbox-mgr
#     │   └── sysbox-runc
#     ├── ubuntu-bionic
#     │   ├── sysbox-fs
#     │   ├── sysbox-mgr
#     │   └── sysbox-runc
#     └── ubuntu-focal
#         ├── sysbox-fs
#         ├── sysbox-mgr
#         └── sysbox-runc
#

check-sysbox-artifacts:
	$(foreach file,$(SYSBOX_BINS),[ -f "bin/sysbox-ce/generic/$(file)" ] || "missing sysbox-ce binary: bin/sysbox-ce/generic/$(file)")

check-sysbox-ee-artifacts:
	@$(foreach file,$(SYSBOX_BINS),[ -f "bin/sysbox-ee/generic/$(file)" ] || "missing sysbox-ee binary: bin/sysbox-ee/generic/$(file)")

check-crio-artifacts:
	@$(foreach version,$(CRIO_VERSIONS),[ -f "bin/crio/$(version)/crio" ] || "missing CRI-O binary: bin/crio/$(version)/crio";)

check-sysbox-ee-flatcar-artifacts:
	@$(foreach version,$(FLATCAR_VERSIONS),$(foreach file,$(SYSBOX_FLATCAR_BINS),[ -f "bin/sysbox-ee/flatcar-$(version)/$(file)" ] || "missing sysbox-ee-flatcar binary: bin/sysbox-ee/flatcar-$(version)/$(file)";))

#
# These targets build the sysbox-deploy-k8s images (for sysbox-ce and sysbox-ee)
#

all: sysbox-deploy-k8s-image sysbox-ee-deploy-k8s-image

sysbox-deploy-k8s-image: build-crio check-crio-artifacts fetch-sysbox-ce-bins check-sysbox-artifacts
	docker build -t ghcr.io/nestybox/sysbox-deploy-k8s:v$(SYSBOX_VER) \
		--build-arg sys_arch=$(SYS_ARCH) \
		-f Dockerfile.sysbox-ce .

sysbox-ee-deploy-k8s-image: sysbox-ee-deploy-k8s-artifacts sysbox-ee-deploy-k8s-flatcar-artifacts
	docker build -t ghcr.io/nestybox/sysbox-ee-deploy-k8s:v$(SYSBOX_VER) \
		--build-arg sys_arch=$(SYS_ARCH) \
		-f Dockerfile.sysbox-ee .

sysbox-ee-deploy-k8s-artifacts: build-crio check-crio-artifacts fetch-sysbox-ee-bins check-sysbox-ee-artifacts

#sysbox-ee-deploy-k8s-flatcar-artifacts: build-crio check-crio-artifacts build-flatcar-sysbox-ee-bins check-sysbox-ee-flatcar-artifacts
sysbox-ee-deploy-k8s-flatcar-artifacts: build-flatcar-sysbox-ee-bins
# check-sysbox-ee-flatcar-artifacts

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
