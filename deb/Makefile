#
# Sysbox DEB Packager Makefile
#

.PHONY: help               \
	deb                \
	debian             \
	debian-buster      \
	debian-bullseye    \
	ubuntu             \
	ubuntu-bionic      \
	ubuntu-focal       \
	ubuntu-jammy       \
	clean

SHELL:=/bin/bash

# Obtain the current system architecture.
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	ARCH := amd64
else ifeq ($(UNAME_M),aarch64)
	ARCH := arm64
else ifeq ($(UNAME_M),arm)
	ARCH := armhf
else ifeq ($(UNAME_M),armel)
	ARCH := armel
endif

# Sysbox's default baseline image to build release binaries. Notice
# that this is currently a requirement to build official Sysbox
# packages as only Impish (or later) carries ID-mapped mount support
# in the kernel and associated clibs.
RELEASE_BASELINE_IMAGE=ubuntu-jammy

# Go version to utilize in building process.
GO_BASE_IMAGE=golang
GO_VERSION:=1.19
GO_IMAGE=$(GO_BASE_IMAGE):$(GO_VERSION)

# Sysbox source-code locations.
ifeq ($(EDITION),ce)
	SYSBOX_DIR  := $(CURDIR)/../sources/sysbox
else ifeq ($(EDITION),ee)
	SYSBOX_DIR  := $(CURDIR)/../sources/sysbox-internal
else
	echo "Unsupported Sysbox edition: $(EDITION)"
	exit 1
endif

# Sysbox component locations.
SYSBOX_IMAGE_SYSTEMD := ../systemd

SOURCE_FILES =  sysbox.tgz           \
		sysbox.service       \
		sysbox-fs.service    \
		sysbox-mgr.service   \
		99-sysbox-sysctl.conf \
		50-sysbox-mod.conf

SOURCES=$(addprefix sources/, $(SOURCE_FILES))

CHOWN:=docker run --rm -v $(CURDIR):/v -w /v alpine chown

DOCKER_BUILD=docker build                              \
	--build-arg GO_IMAGE=$(GO_IMAGE)                   \
	--build-arg arch=$(ARCH)                           \
	--build-arg DEB_FILES=sysbox-${EDITION}            \
	-t build-$@/$(ARCH)                                \
	-f $(CURDIR)/$@/Dockerfile .

DOCKER_RUN=docker run --privileged --rm -i    \
	-e EDITION                                \
	-v $(CURDIR)/build/$(ARCH)/$@:/build      \
	-v $(GOPATH)/pkg/mod:/go/pkg/mod          \
	-v $(HOME)/.gitconfig:/root/.gitconfig:ro \
	-v /lib/modules/$(KERNEL_REL):/lib/modules/$(KERNEL_REL):ro \
	-v /usr/src/$(HEADERS):/usr/src/$(HEADERS):ro \
	-v /usr/src/$(HEADERS_BASE):/usr/src/$(HEADERS_BASE):ro \
	build-$@/$(ARCH)

DOCKER_BUILD_RELEASE=docker build                                \
	--build-arg GO_IMAGE=$(GO_IMAGE)                             \
	--build-arg arch=$(ARCH)                                     \
	--build-arg DEB_FILES=sysbox-${EDITION}                      \
	-t build-$(RELEASE_BASELINE_IMAGE)/$(ARCH)                   \
	-f $(CURDIR)/$(RELEASE_BASELINE_IMAGE)/Dockerfile .

DOCKER_RUN_RELEASE=docker run --privileged --rm -i               \
	-e EDITION                                                   \
	-v $(CURDIR)/build/$(ARCH)/$(RELEASE_BASELINE_IMAGE):/build  \
	-v $(GOPATH)/pkg/mod:/go/pkg/mod                             \
	-v $(HOME)/.gitconfig:/root/.gitconfig:ro                    \
	-v /lib/modules/$(KERNEL_REL):/lib/modules/$(KERNEL_REL):ro  \
	-v /usr/src/$(HEADERS):/usr/src/$(HEADERS):ro                \
	-v /usr/src/$(HEADERS_BASE):/usr/src/$(HEADERS_BASE):ro      \
	build-$(RELEASE_BASELINE_IMAGE)/$(ARCH)

.DEFAULT := help

help:
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[1mUsage:\n  \
	make <sysbox-package> \033[36m<deb-distro>\033[0m\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ \
	{ printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ DEB package targets

all: ## Build all DEB packages
all: debian ubuntu

debian: ## Build Debian packages
debian: debian-buster debian-bullseye

debian-buster: ## Build Debian Buster package
debian-buster: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) build/$(ARCH)/$@

debian-bullseye: ## Build Debian Bullseye package
debian-bullseye: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) build/$(ARCH)/$@

ubuntu: ## Build Ubuntu packages
ubuntu: ubuntu-bionic ubuntu-focal ubuntu-jammy

ubuntu-bionic: ## Build Ubuntu Bionic package
ubuntu-bionic: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) build/$(ARCH)/$@

ubuntu-focal: ## Build Ubuntu Focal package
ubuntu-focal: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) build/$(ARCH)/$@

ubuntu-jammy: ## Build Ubuntu Jammy package
ubuntu-jammy: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) build/$(ARCH)/$@

generic: ## Build generic deb package (release purposes)
generic: $(SOURCES)
	@echo "== Building generic release package"
	$(DOCKER_BUILD_RELEASE)
	$(DOCKER_RUN_RELEASE)
	$(CHOWN) -R $(shell id -u):$(shell id -g) build/$(ARCH)/$(RELEASE_BASELINE_IMAGE)

clean: ## Remove all DEB packages
ifeq ($(EDITION),ce)
	@[ ! -d build ] || $(CHOWN) -R $(shell id -u):$(shell id -g) build
	@$(RM) -r build/$(ARCH)/*/sysbox-ce*
else ifeq ($(EDITION),ee)
	@[ ! -d build ] || $(CHOWN) -R $(shell id -u):$(shell id -g) build
	@$(RM) -r build/$(ARCH)/*/sysbox-ee*
else
	@[ ! -d build ] || $(CHOWN) -R $(shell id -u):$(shell id -g) build
	@$(RM) -r build/$(ARCH)/*
endif
	@[ ! -d sources ] || $(CHOWN) -R $(shell id -u):$(shell id -g) sources
	@$(RM) -r sources

sources/sysbox.tgz:
	mkdir -p $(@D)
	docker run --rm -i -w /v                                     \
		-v $(SYSBOX_DIR):/sysbox                                 \
		-v $(CURDIR)/$(@D):/v                                    \
		alpine                                                   \
		tar -C / -czf /v/sysbox.tgz --exclude='sysbox-pkgr' sysbox

sources/sysbox.service: ../systemd/sysbox.service
	mkdir -p $(@D)
	cp $< $@

sources/sysbox-fs.service: ../systemd/sysbox-fs.service
	mkdir -p $(@D)
	cp $< $@

sources/sysbox-mgr.service: ../systemd/sysbox-mgr.service
	mkdir -p $(@D)
	cp $< $@

sources/99-sysbox-sysctl.conf: ../systemd/99-sysbox-sysctl.conf
	mkdir -p $(@D)
	cp $< $@

sources/50-sysbox-mod.conf: ../systemd/50-sysbox-mod.conf
	mkdir -p $(@D)
	cp $< $@
