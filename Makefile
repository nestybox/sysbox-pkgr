SHELL:=/bin/bash
ARCH=$(shell uname -m)

#
# TODO:
# - Eliminate specific pkg-build targets (e.g. ubuntu-bionic) from here. This
#   is a hack to workaround an unsolved issue, but it hurts on my eyes.
#
.PHONY: help                  \
		build-deb     \
		build-rpm     \
		clean         \
		clean-deb     \
		ubuntu-bionic \
		ubuntu-focal  \
		clean-rpm

.DEFAULT := help

help: ## Show build targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), \
	$$2);printf " \033[36m%-20s\033[0m  %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build debian and rpm packages
build: clean
	$(MAKE) -C deb help
	$(MAKE) -C rpm help

build-deb: ## Build debian packages
build-deb: clean-deb
	$(MAKE) -C deb $(filter-out $@,$(MAKECMDGOALS))

build-rpm: ## Build rpm packages (not supported yet)
build-rpm: clean-rpm
	$(MAKE) -C rpm $(filter-out $@,$(MAKECMDGOALS))

clean: ## Remove build artifacts
	$(MAKE) -C deb clean
	$(MAKE) -C rpm clean

clean-deb: ## Remove deb build artifacts
	$(MAKE) -C deb clean

clean-rpm: ## Remove rpm build artifacts
	$(MAKE) -C rpm clean
