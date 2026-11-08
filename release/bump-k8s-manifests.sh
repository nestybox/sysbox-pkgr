#!/usr/bin/env bash
#
# Points the Sysbox K8s install/uninstall manifests at a new sysbox-deploy-k8s
# image tag.
#
# Usage: bump-k8s-manifests.sh <sysbox-dir> <image-tag>
#
# Example: bump-k8s-manifests.sh sources/sysbox v0.7.2-0

set -euo pipefail

sysbox_dir=${1:?usage: $0 <sysbox-dir> <image-tag>}
image_tag=${2:?usage: $0 <sysbox-dir> <image-tag>}

[[ ${image_tag} =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || {
    echo "invalid image tag '${image_tag}'" >&2
    exit 1
}

manifests=(
    "${sysbox_dir}/sysbox-k8s-manifests/sysbox-install.yaml"
    "${sysbox_dir}/sysbox-k8s-manifests/sysbox-uninstall.yaml"
)

for manifest in "${manifests[@]}"; do
    [[ -f ${manifest} ]] || {
        echo "${manifest} not found" >&2
        exit 1
    }

    # Rewrite the tag of the sysbox-deploy-k8s image (any registry).
    tmp=$(mktemp)
    sed -E "s#(sysbox-deploy-k8s:)v[0-9][^[:space:]\"']*#\1${image_tag}#" \
        "${manifest}" > "${tmp}"
    cat "${tmp}" > "${manifest}"
    rm -f "${tmp}"

    grep -q "sysbox-deploy-k8s:${image_tag}\$" "${manifest}" || {
        echo "failed to update ${manifest}" >&2
        exit 1
    }
done
