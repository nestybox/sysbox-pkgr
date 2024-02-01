#
# Sysbox Packager Makefile
#

SHELL:=/bin/bash
ARCH=$(shell uname -m)

.PHONY: help                        \
		sysbox-all          \
		sysbox-ce           \
		sysbox-deb          \
		sysbox-rpm          \
		sysbox-ce-deb       \
		sysbox-ce-rpm       \
		sysbox-ce-repo      \
		test-sysbox-all     \
		test-sysbox-ce      \
		test-sysbox-deb     \
		test-sysbox-deb     \
		test-sysbox-rpm     \
		test-sysbox-ce-deb  \
		test-sysbox-ce-rpm  \
		clean               \
		clean-ce            \
		clean-deb           \
		clean-rpm           \
		clean-ce-deb        \
		clean-ce-rpm

# CE git repository structures.
CE_SOURCES=sources/sysbox

# Path to deb and rpm packages
DEB_PACKAGE_PATH=deb/debbuild
RPM_PACKAGE_PATH=rpd/rpmbuild

# List of all the sysbox targets (build + tests)
SYSBOX_TARGETS := $(shell egrep '^.*sysbox.*: \#' Makefile | awk -F: '{print $$1}')


.DEFAULT := help

help: ## Show build targets
	@awk 'BEGIN {FS = ":.*##"; printf "\n\033[1mUsage:\n  \
	make <sysbox-package> \033[36m<distro>\033[0m\n\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ \
	{ printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Building targets

sysbox-all: ## Build all sysbox packages
sysbox-all: sysbox-ce

sysbox-ce: ## Build sysbox-ce DEB and RPM packages
sysbox-ce: sysbox-ce-deb sysbox-ce-rpm

sysbox-deb: ## Build all sysbox DEB packages
sysbox-deb: sysbox-ce-deb

sysbox-rpm: ## Build all sysbox RPM packages
sysbox-rpm: sysbox-ce-rpm

sysbox-ce-deb: ## Build sysbox-ce DEB package
sysbox-ce-deb: $(CE_SOURCES) clean-ce-deb
	$(eval export EDITION=ce)
	@$(MAKE) -C deb --no-print-directory $(filter-out $(SYSBOX_TARGETS)@,$(MAKECMDGOALS))

sysbox-ce-rpm: ## Build sysbox-ce RPM package
sysbox-ce-rpm: $(CE_SOURCES) clean-ce-rpm
	$(eval export EDITION=ce)
	@$(MAKE) -C rpm --no-print-directory $(filter-out $(SYSBOX_TARGETS)@,$(MAKECMDGOALS))

sysbox-ce-repo: ## Set path to the sysbox-ce repo (remote github repo by default)
sysbox-ce-repo:
	$(eval REPO_PATH=$(filter-out sysbox-ce-repo $@,$(MAKECMDGOALS)))
	@printf "\n*** Setting sysbox-ce repository path to $(REPO_PATH) ***\n\n"
	@mkdir -p sources
	@ln -sf $(REPO_PATH) $(CE_SOURCES)

sources/sysbox:
	@printf "\n*** Cloning sysbox-ce superproject repository to $(CE_SOURCES) ***\n\n"
	@git clone --recursive https://github.com/nestybox/sysbox.git sources/sysbox

##@ Testing targets

test-sysbox-all: ## Test all sysbox packages
test-sysbox-all: test-sysbox-ce

test-sysbox-ce: ## Test sysbox-ce DEB and RPM packages
test-sysbox-ce: tesst-sysbox-ce-deb test-sysbox-ce-rpm

test-sysbox-deb: ## Test all sysbox DEB packages
test-sysbox-deb: test-sysbox-ce-deb

test-sysbox-rpm: ## Test all sysbox RPM packages
test-sysbox-rpm: test-sysbox-ce-rpm

test-sysbox-ce-deb: ## Test sysbox-ce DEB package
test-sysbox-ce-deb: sysbox-ce-deb
	@cp $(DEB_PACKAGE_PATH)/$(lastword $@,$(MAKECMDGOALS))/sysbox-ce*.deb $(CE_SOURCES)
	@$(MAKE) -C $(CE_SOURCES) --no-print-directory test-sysbox-installer PACKAGE_FILE_PATH="."
	@$(MAKE) -C $(CE_SOURCES) --no-print-directory test-sysbox-shiftuid-installer PACKAGE_FILE_PATH="."

test-sysbox-ce-rpm: ## Test sysbox-ce RPM package
test-sysbox-ce-rpm: sysbox-ce-rpm
	@cp $(RPM_PACKAGE_PATH)/$(lastword $@,$(MAKECMDGOALS))/sysbox-ce*.deb $(CE_SOURCES)
	@$(MAKE) -C $(CE_SOURCES) --no-print-directory test-sysbox-installer PACKAGE_FILE_PATH="."

##@ Cleaning targets

clean: ## Remove build artifacts
clean: clean-ce

clean-ce: ## Remove sysbox-ce DEB and RPM packages
clean-ce: clean-ce-deb clean-ce-rpm

clean-deb: ## Remove sysbox DEB packages
clean-deb: clean-ce-deb

clean-rpm: ## Remove sysbox RPM packages
clean-rpm: clean-ce-rpm

clean-ce-deb: ## Remove sysbox-ce DEB package
	$(eval export EDITION=ce)
	$(MAKE) -C deb --no-print-directory clean

clean-ce-rpm: ## Remove sysbox-ce RPM package
	$(eval export EDITION=ce)
	$(MAKE) -C rpm --no-print-directory clean
