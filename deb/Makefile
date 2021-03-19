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
	clean

SHELL:=/bin/bash
ARCH:=$(shell uname -m)

# Go version to utilize in slave containers for the building process.
# We are temporarily skipping these settings as we are relying on Go's
# top-of-tree (till 1.13 comes out).
GO_BASE_IMAGE=golang
GO_VERSION:=1.13
GO_IMAGE=$(GO_BASE_IMAGE):$(GO_VERSION)

# Sysbox source-code locations.
ifeq ($(PLATFORM),ce)
	SYSBOX_DIR  := $(CURDIR)/../sources/sysbox
else ifeq ($(PLATFORM),ee)
	SYSBOX_DIR  := $(CURDIR)/../sources/sysbox-internal
else
	echo "Unsupported Sysbox platform: $(PLATFORM)"
	exit 1
endif

# Sysbox component locations.
SYSBOX_IMAGE_SYSTEMD := ../systemd

SOURCE_FILES =  sysbox.tgz           \
		sysbox.service       \
		sysbox-fs.service    \
		sysbox-mgr.service   \
		sysbox-systemd.conf  \
		sysbox-configfs.conf

SOURCES=$(addprefix sources/, $(SOURCE_FILES))

CHOWN:=docker run --rm -v $(CURDIR):/v -w /v alpine chown

DOCKER_BUILD=docker build                                  \
	--build-arg GO_IMAGE=$(GO_IMAGE)                   \
	--build-arg DEB_FILES=sysbox-${PLATFORM}           \
	-t debbuild-$@/$(ARCH)                             \
	-f $(CURDIR)/$@/Dockerfile .

DOCKER_RUN=docker run --privileged --rm -i       \
	-e PLATFORM                              \
	-e VERSION                               \
	-e COMMIT_ID                             \
	-e BUILT_BY                              \
	-e HOSTNAME                              \
	-v $(CURDIR)/debbuild/$@:/build          \
	-v $(GOPATH)/pkg/mod:/go/pkg/mod         \
	-v $(TEST_VOL1):/var/lib/docker          \
	-v $(TEST_VOL2):/var/lib/sysbox          \
	-v $(TEST_VOL3):/mnt/scratch             \
	-v $(HOME)/.gitconfig:/root/.gitconfig:ro     \
	-v /lib/modules/$(KERNEL_REL):/lib/modules/$(KERNEL_REL):ro \
	-v /usr/src/$(HEADERS):/usr/src/$(HEADERS):ro \
	-v /usr/src/$(HEADERS_BASE):/usr/src/$(HEADERS_BASE):ro \
	debbuild-$@/$(ARCH)


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
	$(CHOWN) -R $(shell id -u):$(shell id -g) debbuild/$@

debian-bullseye: ## Build Debian Bullseye package
debian-bullseye: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) debbuild/$@

ubuntu: ## Build Ubuntu packages
ubuntu: ubuntu-bionic ubuntu-focal

ubuntu-bionic: ## Build Ubuntu Bionic package
ubuntu-bionic: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) debbuild/$@

ubuntu-focal: ## Build Ubuntu Focal package
ubuntu-focal: $(SOURCES)
	@echo "== Building packages for $@ =="
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) debbuild/$@

clean: ## Remove all DEB packages
ifeq ($(PLATFORM),ce)
	@[ ! -d debbuild ] || $(CHOWN) -R $(shell id -u):$(shell id -g) debbuild
	@$(RM) -r debbuild/*/sysbox-ce*
else ifeq ($(PLATFORM),ee)
	@[ ! -d debbuild ] || $(CHOWN) -R $(shell id -u):$(shell id -g) debbuild
	@$(RM) -r debbuild/*/sysbox-ee*
else
	@[ ! -d debbuild ] || $(CHOWN) -R $(shell id -u):$(shell id -g) debbuild
	@$(RM) -r debbuild/*
endif
	@[ ! -d sources ] || $(CHOWN) -R $(shell id -u):$(shell id -g) sources
	@$(RM) -r sources

sources/sysbox.tgz:
	mkdir -p $(@D)
	docker run --rm -i -w /v                                         \
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

sources/sysbox-systemd.conf: ../systemd/sysbox-systemd.conf
	mkdir -p $(@D)
	cp $< $@

sources/sysbox-configfs.conf: ../systemd/sysbox-configfs.conf
	mkdir -p $(@D)
	cp $< $@
