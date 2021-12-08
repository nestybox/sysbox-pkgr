#
# Sysbox Deploy K8s Daemonset Makefile
#

.PHONY: sysbox-deploy-k8s-image \
	sysbox-ee-deploy-k8s-image \
	sysbox-ee-deploy-k8s-image-artifacts \
	sysbox-ee-deploy-k8s-image-flatcar-artifacts \
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


SHELL := /bin/bash

SYSBOX_BINS = sysbox-runc sysbox-mgr sysbox-fs
SYSBOX_DISTRO = ubuntu-focal ubuntu-bionic
SYSBOX_VER = 0.4.1
CRIO_VERSIONS = v1.20 v1.21
FLATCAR_VERSIONS = 2765.2.6 2905.2.3

# Supported Flatcar versions
FLATCAR_VERSIONS := 2905.2.3 2905.2.6
FLATCAR_2905.2.3_KERNEL := "5.10.61-flatcar"
FLATCAR_2905.2.6_KERNEL := "5.10.75-flatcar"
FLATCAR_DEV_ENVS := FLATCAR_DEV_ENV_2905.2.3 FLATCAR_DEV_ENV_2905.2.6


#
# Sysbox artifacts for Ubuntu distro
#

# The fetch_* targets download the Sysbox binaries from the Sysbox repo and
# place them in the "bin" sub-directory. The *_image targets then load those
# binaries into the sysbox-deploy-k8s image. Variable SYSBOX_VER selects the
# version of the Sysbox binaries to download.

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
# Sysbox artifacts, and its dependencies, for Flatcar distro
#

build_flatcar_sysbox_ee_bins: $(FLATCAR_VERSIONS)

#$(FLATCAR_VERSIONS): FLATCAR_DEV_ENVIRONMENTS_$(FLATCAR_VERSIONS)
$(FLATCAR_VERSIONS): $(FLATCAR_DEV_ENVS)
	@printf "\n*** Building Sysbox's flatcar-$@ binaries ... ***\n\n"
	@make -C ../ sources/sysbox-internal
	@make -C ../sources/sysbox-internal/ FLATCAR_VERSION=$@ FLATCAR_KERNEL=$(FLATCAR_$@_KERNEL) sysbox-flatcar
	@mkdir -p bin/sysbox-ee/flatcar-$@
	cp ../sources/sysbox-internal/build/flatcar-$@/* bin/sysbox-ee/flatcar-$@/

$(FLATCAR_DEV_ENVS):
	$(eval FLATCAR_VERSION := $(subst FLATCAR_DEV_ENV_,,$@))

	printf "\n******** rodny $(FLATCAR_VERSION) ********\n";															\
	if docker inspect --type=image ghcr.io/nestybox/flatcar-dev-container:${FLATCAR_VERSION} >/dev/null 2>&1; then		\
		printf "\n*** Flatcar-${FLATCAR_VERSION} dev-environment image found. Skipping build process ... ***\n\n"; 		\
	else																												\
		printf "\n*** Building Flatcar-${FLATCAR_VERSION} dev-environment ... ***\n\n";									\
		TMPDIR=$$(mktemp -d);																							\
		chmod 755 $${TMPDIR};																							\
																														\
		# Fetch flatcar's official dev image and import it into a docker container.										\
		curl -L https://stable.release.flatcar-linux.net/amd64-usr/${FLATCAR_VERSION}/flatcar_developer_container.bin.bz2 \
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
			--tag ghcr.io/nestybox/flatcar-dev-container:${FLATCAR_VERSION} 											\
			-f Dockerfile.flatcar.dev .; 																				\
																														\
		sudo umount $${TMPDIR}/${FLATCAR_VERSION}; 																		\
		sudo rm -rf $${TMPDIR};						 																	\
		printf "\n*** Completed building Flatcar's dev-environment image. ***\n\n";										\
	fi

#
# CRI-O artifacts
#

build_crio: $(CRIO_VERSIONS)

$(CRIO_VERSIONS):
	@printf "\n*** Building cri-o $@ ... ***\n\n"
	$(eval TMPDIR := $(shell mktemp -d))
	@chmod 755 $(TMPDIR)
	@git clone git@github.com:nestybox/cri-o.git $(TMPDIR)/cri-o
	@git -C $(TMPDIR)/cri-o checkout -b $@-sysbox origin/$@-sysbox
	@cd $(TMPDIR)/cri-o && CONTAINER_RUNTIME=docker make build-static
	@mkdir -p bin/crio/$@
	@cp $(TMPDIR)/cri-o/bin/static/crio bin/crio/$@/
	@chmod 755 -R $(TMPDIR) && rm -rf $(TMPDIR)

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

sysbox-deploy-k8s-image: build_crio check-crio-artifacts fetch_sysbox_ce_bins check-sysbox-artifacts
	docker build -t ghcr.io/nestybox/sysbox-deploy-k8s:v$(SYSBOX_VER) -f Dockerfile.sysbox-ce .

sysbox-ee-deploy-k8s-image: sysbox-ee-deploy-k8s-artifacts sysbox-ee-deploy-k8s-flatcar-artifacts
	docker build -t ghcr.io/nestybox/sysbox-ee-deploy-k8s:v$(SYSBOX_VER) -f Dockerfile.sysbox-ee .

#sysbox-ee-deploy-k8s-artifacts: build_crio check-crio-artifacts fetch_sysbox_ee_bins check-sysbox-ee-artifacts
sysbox-ee-deploy-k8s-artifacts: check-crio-artifacts fetch_sysbox_ee_bins check-sysbox-ee-artifacts

#sysbox-ee-deploy-k8s-flatcar-artifacts: build_crio check-crio-artifacts build_flatcar_sysbox_ee_bins
sysbox-ee-deploy-k8s-flatcar-artifacts: check-crio-artifacts build_flatcar_sysbox_ee_bins

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
