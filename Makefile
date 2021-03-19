#
# Sysbox Packager Makefile
#

SHELL:=/bin/bash
ARCH=$(shell uname -m)

.PHONY: help                    \
		sysbox-all      \
		sysbox-ce       \
		sysbox-ee       \
		sysbox-deb      \
		sysbox-rpm      \
		sysbox-ce-deb   \
		sysbox-ce-rpm   \
		sysbox-ee-deb   \
		sysbox-ee-rpm   \
		clean-all       \
		clean-ce        \
		clean-ee        \
		clean-deb       \
		clean-rpm       \
		clean-ce-deb    \
		clean-ce-rpm    \
		clean-ee-deb    \
		clean-ee-rpm

# CE & EE git repository structures.
CE_SOURCES=sources/sysbox
EE_SOURCES=sources/sysbox-internal

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
sysbox-rpm: clean-rpm sysbox-ce-rpm sysbox-ee-rpm

sysbox-ce-deb: ## Build sysbox-ce DEB package
sysbox-ce-deb: $(CE_SOURCES) clean-ce-deb
	$(eval export EDITION=ce)
	@$(MAKE) -C deb --no-print-directory $(filter-out sysbox-ce sysbox-deb $@,$(MAKECMDGOALS))

sysbox-ce-rpm: ## Build sysbox-ce RPM package
sysbox-ce-rpm: $(CE_SOURCES) clean-ce-rpm
	$(eval export EDITION=ce)
	@$(MAKE) -C rpm --no-print-directory $(filter-out sysbox-ce sysbox-rpm $@,$(MAKECMDGOALS))

sysbox-ee-deb: ## Build sysbox-ee DEB package
sysbox-ee-deb: $(EE_SOURCES) clean-ee-deb
	$(eval export EDITION=ee)
	@$(MAKE) -C deb --no-print-directory $(filter-out sysbox-ee sysbox-deb $@,$(MAKECMDGOALS))

sysbox-ee-rpm: ## Build sysbox-ee RPM package
sysbox-ee-rpm: $(EE_SOURCES) clean-ee-rpm
	$(eval export EDITION=ee)
	@$(MAKE) -C rpm --no-print-directory $(filter-out sysbox-ee sysbox-rpm $@,$(MAKECMDGOALS))

sources/sysbox:
	git clone --recursive git@github.com:nestybox/sysbox.git sources/sysbox

sources/sysbox-internal:
	git clone --recursive git@github.com:nestybox/sysbox-internal.git sources/sysbox-internal

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
	@$(MAKE) -C deb --no-print-directory clean

clean-ce-rpm: ## Remove sysbox-ce RPM package
	$(eval export EDITION=ce)
	@$(MAKE) -C rpm --no-print-directory clean

clean-ee-deb: ## Remove sysbox-ee DEB package
	$(eval export EDITION=ee)
	@$(MAKE) -C deb --no-print-directory clean

clean-ee-rpm: ## Remove sysbox-ee RPM package
	$(eval export EDITION=ee)
	@$(MAKE) -C rpm --no-print-directory clean
