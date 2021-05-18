#
# Sysbox Deploy K8s Daemonset Makefile
#

.PHONY: sysbox-deploy-k8s-image \
	copy-artifacts \
	rm-artifacts \
	check-sysbox-bin \
	clean

SYSBOX_BINS = sysbox-runc sysbox-mgr sysbox-fs
SYSBOX_DISTRO = ubuntu-focal ubuntu-bionic

all: sysbox-deploy-k8s-image crio-deploy-k8s-image

sysbox-deploy-k8s-image: check-artifacts
	docker build -t ghcr.io/nestybox/sysbox-deploy-k8s .

crio-deploy-k8s-image:
	docker build -t ghcr.io/nestybox/crio-deploy-k8s -f Dockerfile.crio .

# Verifies that sysbox binaries are in the expected location (temporary target
# until the process of creating the binaries is automated).
check-artifacts:
	@$(foreach distro,$(SYSBOX_DISTRO),$(foreach file,$(SYSBOX_BINS),[ -f "bin/$(distro)/$(file)" ] || "missing sysbox binary: bin/$(distro)/$(file)";))
