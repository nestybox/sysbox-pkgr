#!/usr/bin/env bash
#
# Generates the body of a Sysbox GitHub release: the changelog entry of the
# release followed by the sha256 checksums of the release packages.
#
# Usage: release-notes.sh <sysbox-dir> <debs-dir> <output-file>
#
# The layout matches that of previous Sysbox releases.

set -euo pipefail

sysbox_dir=${1:?usage: $0 <sysbox-dir> <debs-dir> <output-file>}
debs_dir=${2:?usage: $0 <sysbox-dir> <debs-dir> <output-file>}
output=${3:?usage: $0 <sysbox-dir> <debs-dir> <output-file>}

version=$(tr -d '[:space:]' < "${sysbox_dir}/VERSION")
changelog_file="${sysbox_dir}/CHANGELOG.md"

# Computes the sha256 of a file (GNU coreutils or BSD/macOS).
function sha256() {
    if command -v sha256sum > /dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Emits the body of the changelog entry for the release, without its heading
# and without trailing blank lines.
function changelog_body() {
    awk -v heading="## [${version}]" '
        index($0, heading) == 1 { found = 1; next }
        found && /^## / { exit }
        found { print }
    ' "${changelog_file}" | sed -e :a -e '/^[[:space:]]*$/{$d;N;ba' -e '}'
}

body=$(changelog_body)
[[ -n ${body} ]] || {
    echo "no CHANGELOG.md entry found for ${version}" >&2
    exit 1
}

shopt -s nullglob
debs=("${debs_dir}"/sysbox-ce_"${version}".linux_*.deb)
[[ ${#debs[@]} -gt 0 ]] || {
    echo "no sysbox-ce ${version} packages found in ${debs_dir}" >&2
    exit 1
}

{
    echo "# Official Packages"
    echo
    echo "See attached binaries."
    echo
    echo "# Changelog"
    echo
    echo "${body}"
    echo
    echo "# Checksums"
    echo
    echo '```'
    for deb in "${debs[@]}"; do
        name=$(basename "${deb}")
        echo "\$ sha256sum ${name}"
        echo "$(sha256 "${deb}")  ${name}"
        echo
    done | sed '$d'
    echo '```'
} > "${output}"
