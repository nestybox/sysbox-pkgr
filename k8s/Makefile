#
# Sysbox Deploy K8s Daemonset Makefile
#
# TODO:
#
# - Automate generating & copying the sysbox binaries for each supported distro,
#   and including them in the image gnerated by Make target
#   sysbox-deploy-k8s-image. Currently this is being done by hand.

.PHONY: sysbox-deploy-k8s-image \
	copy-artifacts \
	rm-artifacts \
	check-sysbox-bin \
	clean

SYSBOX_BINS = sysbox-runc sysbox-mgr sysbox-fs
SYSBOX_DISTRO = ubuntu-focal ubuntu-bionic

default: sysbox-deploy-k8s-image

sysbox-deploy-k8s-image: copy-artifacts check-artifacts
	docker build -t ghcr.io/nestybox/sysbox-deploy-k8s .

copy-artifacts: rm-artifacts
	cp -r ../systemd systemd

rm-artifacts:
	rm -rf systemd

# Verifies that sysbox binaries are in the expected location (temporary target
# until the process of creating the binaries is automated).
check-artifacts:
	@$(foreach distro,$(SYSBOX_DISTRO),$(foreach file,$(SYSBOX_BINS),[ -f "bin/$(distro)/$(file)" ] || "missing sysbox binary: bin/$(distro)/$(file)";))

clean: rm-artifacts
