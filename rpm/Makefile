#
# Sysbox RPM Packager Makefile
#

.PHONY: help     \
	rpm          \
	centos       \
	centos-8     \
	fedora       \
	fedora-31    \
	fedora-32    \
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

DOCKER_BUILD=docker build                                  \
	--build-arg GO_IMAGE=$(GO_IMAGE)                   \
	--build-arg COMMON_FILES=$(SYSBOX_IMAGE_COMMON)    \
	-t rpmbuild-$@/$(ARCH)                             \
	-f $(CURDIR)/$@/Dockerfile .

DOCKER_RUN=docker run --rm -i                    \
	-e EDITION                               \
	-v $(CURDIR)/rpmbuild/$@:/build          \
	-v $(GOPATH)/pkg/mod:/go/pkg/mod         \
	rpmbuild-$@/$(ARCH)


help:
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[1mUsage:\n  \
	make <sysbox-package> \033[36m<rpm-distro>\033[0m\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ \
	{ printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ RPM building targets

all: ## Build all RPM packages
all: centos fedora

centos: ## Build Centos packages
centos: centos-8

centos-8: ## Build Centos-8 package
centos-8: $(SOURCES)
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) rpmbuild/$@

fedora: ## Build Fedora packages
fedora: fedora-31 fedora-32

fedora-31: ## Build Fedora-31 package
fedora-31: $(SOURCES)
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) rpmbuild/$@

fedora-32: ## Build Fedora-32 packages
fedora-32: $(SOURCES)
	$(DOCKER_BUILD)
	$(DOCKER_RUN)
	$(CHOWN) -R $(shell id -u):$(shell id -g) rpmbuild/$@

clean: ## Remove build artifacts
	@[ ! -d rpmbuild ] || $(CHOWN) -R $(shell id -u):$(shell id -g) rpmbuild
	@$(RM) -r rpmbuild
	@[ ! -d sources ] || $(CHOWN) -R $(shell id -u):$(shell id -g) sources
	@$(RM) -r sources

sources/sysbox.tgz:
	mkdir -p $(@D)
	docker run --rm -i -w /v \
		-v $(SYSBOX_DIR):/sysbox \
		-v $(CURDIR)/$(@D):/v \
		alpine \
		tar -C / -czf /v/sysbox.tgz --exclude .git --exclude='sysbox-pkgr' sysbox

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
