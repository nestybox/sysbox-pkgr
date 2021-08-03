#
# Sysbox Deploy K8s Daemonset Makefile
#

.PHONY: sysbox-deploy-k8s-image \
	sysbox-ee-deploy-k8s-image \
	check-sysbox-artifacts \
	check-sysbox-ee-artifacts

SYSBOX_BINS = sysbox-runc sysbox-mgr sysbox-fs
SYSBOX_DISTRO = ubuntu-focal ubuntu-bionic

all: sysbox-deploy-k8s-image sysbox-ee-deploy-k8s-image

sysbox-deploy-k8s-image: check-sysbox-artifacts
	docker build -t ghcr.io/nestybox/sysbox-deploy-k8s -f Dockerfile.sysbox-ce .

sysbox-ee-deploy-k8s-image: check-sysbox-ee-artifacts
	docker build -t ghcr.io/nestybox/sysbox-ee-deploy-k8s -f Dockerfile.sysbox-ee .

# Verifies that sysbox binaries are in the expected location (temporary target
# until the process of creating the binaries is automated).
check-sysbox-artifacts:
	@$(foreach distro,$(SYSBOX_DISTRO),$(foreach file,$(SYSBOX_BINS),[ -f "bin/sysbox-ce/$(distro)/$(file)" ] || "missing sysbox-ce binary: bin/sysbox-ce/$(distro)/$(file)";))

check-sysbox-ee-artifacts:
	@$(foreach distro,$(SYSBOX_DISTRO),$(foreach file,$(SYSBOX_BINS),[ -f "bin/sysbox-ee/$(distro)/$(file)" ] || "missing sysbox-ee binary: bin/sysbox-ee/$(distro)/$(file)";))
