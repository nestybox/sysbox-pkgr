#
# Sysbox Packager Makefile
#

SHELL:=/bin/bash
ARCH=$(shell uname -m)

.PHONY: help                        \
		sysbox-all          \
		sysbox-ce           \
		sysbox-ee           \
		sysbox-deb          \
		sysbox-rpm          \
		sysbox-ce-deb       \
		sysbox-ce-rpm       \
		sysbox-ee-deb       \
		sysbox-ee-rpm       \
		sysbox-ce-repo      \
		sysbox-ee-repo      \
		test-sysbox-all     \
		test-sysbox-ce      \
		test-sysbox-ee      \
		test-sysbox-deb     \
		test-sysbox-deb     \
		test-sysbox-rpm     \
		test-sysbox-ce-deb  \
		test-sysbox-ce-rpm  \
		test-sysbox-ee-deb  \
		test-sysbox-ee-rpm  \
		clean               \
		clean-ce            \
		clean-ee            \
		clean-deb           \
		clean-rpm           \
		clean-ce-deb        \
		clean-ce-rpm        \
		clean-ee-deb        \
		clean-ee-rpm        \
		ubuntu-bionic       \
		ubuntu-focal        \
		debian-buster       \
		debian-bullseye


# CE & EE git repository structures.
CE_SOURCES=sources/sysbox
EE_SOURCES=sources/sysbox-internal

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
sysbox-all: sysbox-ce sysbox-ee

sysbox-ce: ## Build sysbox-ce DEB and RPM packages
sysbox-ce: sysbox-ce-deb sysbox-ce-rpm

sysbox-ee: ## Build sysbox-ee DEB and RPM packages
sysbox-ee: sysbox-ee-deb sysbox-ee-rpm

sysbox-deb: ## Build all sysbox DEB packages
sysbox-deb: sysbox-ce-deb sysbox-ee-deb

sysbox-rpm: ## Build all sysbox RPM packages
sysbox-rpm: sysbox-ce-rpm sysbox-ee-rpm

sysbox-ce-deb: ## Build sysbox-ce DEB package
sysbox-ce-deb: $(CE_SOURCES) clean-ce-deb
	$(eval export EDITION=ce)
	@$(MAKE) -C deb --no-print-directory $(filter-out $(SYSBOX_TARGETS)@,$(MAKECMDGOALS))

sysbox-ce-rpm: ## Build sysbox-ce RPM package
sysbox-ce-rpm: $(CE_SOURCES) clean-ce-rpm
	$(eval export EDITION=ce)
	@$(MAKE) -C rpm --no-print-directory $(filter-out $(SYSBOX_TARGETS)@,$(MAKECMDGOALS))

sysbox-ee-deb: ## Build sysbox-ee DEB package
sysbox-ee-deb: $(EE_SOURCES) clean-ee-deb
	$(eval export EDITION=ee)
	@$(MAKE) -C deb --no-print-directory $(filter-out $(SYSBOX_TARGETS)@,$(MAKECMDGOALS))

sysbox-ee-rpm: ## Build sysbox-ee RPM package
sysbox-ee-rpm: $(EE_SOURCES) clean-ee-rpm
	$(eval export EDITION=ee)
	@$(MAKE) -C rpm --no-print-directory $(filter-out $(SYSBOX_TARGETS)@,$(MAKECMDGOALS))

sysbox-ce-repo: ## Set path to the sysbox-ce repo (remote github repo by default)
sysbox-ce-repo:
	$(eval REPO_PATH=$(filter-out sysbox-ce-repo $@,$(MAKECMDGOALS)))
	@printf "\n*** Setting sysbox-ce repository path to $(REPO_PATH) ***\n\n"
	@mkdir -p sources
	@ln -sf $(REPO_PATH) $(CE_SOURCES)

sysbox-ee-repo: ## Set path to the sysbox-ee repo (remote github repo by default)
sysbox-ee-repo:
	$(eval REPO_PATH=$(filter-out sysbox-ee-repo $@,$(MAKECMDGOALS)))
	@printf "\n*** Setting sysbox-ee repository path to $(REPO_PATH) ***\n\n"
	@mkdir -p sources
	@ln -sf $(REPO_PATH) $(EE_SOURCES)

sources/sysbox:
	@printf "\n*** Cloning sysbox-ce superproject repository to $(CE_SOURCES) ***\n\n"
	@git clone --recursive git@github.com:nestybox/sysbox.git sources/sysbox

sources/sysbox-internal:
	@printf "\n*** Cloning sysbox-ee superproject repository to $(EE_SOURCES) ***\n\n"
	@git clone --recursive git@github.com:nestybox/sysbox-internal.git sources/sysbox-internal


##@ Testing targets

test-sysbox-all: ## Test all sysbox packages
test-sysbox-all: test-sysbox-ce test-sysbox-ee

test-sysbox-ce: ## Test sysbox-ce DEB and RPM packages
test-sysbox-ce: tesst-sysbox-ce-deb test-sysbox-ce-rpm

test-sysbox-ee: ## Test sysbox-ee DEB and RPM packages
test-sysbox-ee: test-sysbox-ee-deb test-sysbox-ee-rpm

test-sysbox-deb: ## Test all sysbox DEB packages
test-sysbox-deb: test-sysbox-ce-deb test-sysbox-ee-deb

test-sysbox-rpm: ## Test all sysbox RPM packages
test-sysbox-rpm: test-sysbox-ce-rpm test-sysbox-ee-rpm

test-sysbox-ce-deb: ## Test sysbox-ce DEB package
test-sysbox-ce-deb: sysbox-ce-deb
	@cp $(DEB_PACKAGE_PATH)/$(lastword $@,$(MAKECMDGOALS))/sysbox-ce*.deb $(CE_SOURCES)
	@$(MAKE) -C $(CE_SOURCES) --no-print-directory test-sysbox-installer PACKAGE_FILE_PATH="."
	@$(MAKE) -C $(CE_SOURCES) --no-print-directory test-sysbox-shiftuid-installer PACKAGE_FILE_PATH="."

test-sysbox-ce-rpm: ## Test sysbox-ce RPM package
test-sysbox-ce-rpm: sysbox-ce-rpm
	@cp $(RPM_PACKAGE_PATH)/$(lastword $@,$(MAKECMDGOALS))/sysbox-ce*.deb $(CE_SOURCES)
	@$(MAKE) -C $(CE_SOURCES) --no-print-directory test-sysbox-installer PACKAGE_FILE_PATH="."

test-sysbox-ee-deb: ## Test sysbox-ee DEB package
test-sysbox-ee-deb: sysbox-ee-deb
	@cp $(DEB_PACKAGE_PATH)/$(lastword $@,$(MAKECMDGOALS))/sysbox-ee*.deb $(EE_SOURCES)
	@$(MAKE) -C $(EE_SOURCES) --no-print-directory test-sysbox-installer PACKAGE_FILE_PATH="."
	@$(MAKE) -C $(EE_SOURCES) --no-print-directory test-sysbox-shiftuid-installer PACKAGE_FILE_PATH="."

test-sysbox-ee-rpm: ## Test sysbox-ee RPM package
test-sysbox-ee-rpm: sysbox-ee-rpm
	@cp $(RPM_PACKAGE_PATH)/$(lastword $@,$(MAKECMDGOALS))/sysbox-ee*.deb $(EE_SOURCES)
	@$(MAKE) -C $(EE_SOURCES) --no-print-directory test-sysbox-installer PACKAGE_FILE_PATH="."


##@ Cleaning targets

clean: ## Remove build artifacts
clean: clean-ce clean-ee

clean-ce: ## Remove sysbox-ce DEB and RPM packages
clean-ce: clean-ce-deb clean-ce-rpm

clean-ee: ## Remove sysbox-ee DEB and RPM packages
clean-ee: clean-ee-deb clean-ee-rpm

clean-deb: ## Remove sysbox DEB packages
clean-deb: clean-ce-deb clean-ee-deb

clean-rpm: ## Remove sysbox RPM packages
clean-ee: clean-ce-rpm clean-ee-rpm

clean-ce-deb: ## Remove sysbox-ce DEB package
	$(eval export EDITION=ce)
	$(MAKE) -C deb --no-print-directory clean

clean-ce-rpm: ## Remove sysbox-ce RPM package
	$(eval export EDITION=ce)
	$(MAKE) -C rpm --no-print-directory clean

clean-ee-deb: ## Remove sysbox-ee DEB package
	$(eval export EDITION=ee)
	$(MAKE) -C deb --no-print-directory clean

clean-ee-rpm: ## Remove sysbox-ee RPM package
	$(eval export EDITION=ee)
	$(MAKE) -C rpm --no-print-directory clean
