#!/usr/bin/env bash
#
# Verifies that a Sysbox source tree is ready to be released.
#
# Usage: check-release-ready.sh <sysbox-dir> [--skip-tag-check]
#
# The following conditions must hold:
#
# * The VERSION file holds a plain semantic version (e.g., 0.7.2).
# * The top-most CHANGELOG.md entry is "## [<VERSION>] - <date>" (i.e., not an
#   "unreleased" entry) and has at least one bullet and no TODO placeholders.
# * The v<VERSION> tag exists, is an annotated tag carrying a signature, and
#   points at the commit checked out in <sysbox-dir>. Release tags are created
#   and signed by a maintainer; this script only checks that a signature is
#   present, it doesn't verify it (the maintainer's public key isn't available
#   in CI).
#
# With --skip-tag-check the tag conditions are not enforced (used by dry runs,
# which build from an arbitrary ref, possibly before the tag exists).

set -euo pipefail

sysbox_dir=${1:?usage: $0 <sysbox-dir> [--skip-tag-check]}
skip_tag_check=false
[[ ${2:-} = "--skip-tag-check" ]] && skip_tag_check=true

# Prints an error message and aborts.
function fail() {
    echo "release check failed: $*" >&2
    exit 1
}

# Checks that the v<version> tag is a signed annotated tag at HEAD.
function check_tag() {
    local tag="v$1"
    local tag_ref="refs/tags/${tag}"

    git -C "${sysbox_dir}" rev-parse -q --verify "${tag_ref}" > /dev/null ||
        fail "tag ${tag} not found; a maintainer must create and push it"

    local tag_type
    tag_type=$(git -C "${sysbox_dir}" cat-file -t "${tag_ref}")
    [[ ${tag_type} = "tag" ]] ||
        fail "tag ${tag} is not annotated (use 'git tag -s')"

    git -C "${sysbox_dir}" cat-file tag "${tag_ref}" |
        grep -q -- '-----BEGIN \(PGP\|SSH\) SIGNATURE-----' ||
        fail "tag ${tag} is not signed (use 'git tag -s')"

    local tag_commit head_commit
    tag_commit=$(git -C "${sysbox_dir}" rev-parse "${tag_ref}^{commit}")
    head_commit=$(git -C "${sysbox_dir}" rev-parse HEAD)
    [[ ${tag_commit} = "${head_commit}" ]] ||
        fail "tag ${tag} points at ${tag_commit}, not at ${head_commit}"
}

version_file="${sysbox_dir}/VERSION"
changelog_file="${sysbox_dir}/CHANGELOG.md"

[[ -f ${version_file} ]] || fail "${version_file} not found"
[[ -f ${changelog_file} ]] || fail "${changelog_file} not found"

version=$(tr -d '[:space:]' < "${version_file}")

# Check that the version is a plain semantic version.
if [[ ! ${version} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "VERSION '${version}' is not of the form MAJOR.MINOR.PATCH"
fi

# Check that the top-most changelog entry matches the version being released.
top_entry=$(grep -m1 '^## ' "${changelog_file}" || true)
entry_regex="^## \[${version}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$"
if [[ ! ${top_entry} =~ ${entry_regex} ]]; then
    fail "top CHANGELOG.md entry '${top_entry}' doesn't match" \
         "'## [${version}] - YYYY-MM-DD'"
fi

# Extract the body of the top-most entry and sanity check it.
body=$(awk '/^## /{n++; next} n==1' "${changelog_file}")
grep -q '^[[:space:]]*\* ' <<< "${body}" ||
    fail "CHANGELOG.md entry for ${version} has no bullet points"
if grep -q 'TODO' <<< "${body}"; then
    fail "CHANGELOG.md entry for ${version} contains TODO placeholders"
fi

# Check the release tag.
[[ ${skip_tag_check} = true ]] || check_tag "${version}"

echo "release check passed for Sysbox v${version}"
