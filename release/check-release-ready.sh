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
# * The v<VERSION> tag doesn't exist yet in the sysbox repo (local or origin),
#   unless --skip-tag-check is given (used by dry runs).

set -euo pipefail

sysbox_dir=${1:?usage: $0 <sysbox-dir> [--skip-tag-check]}
skip_tag_check=false
[[ ${2:-} = "--skip-tag-check" ]] && skip_tag_check=true

# Prints an error message and aborts.
function fail() {
    echo "release check failed: $*" >&2
    exit 1
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

# Check that the release tag is not taken.
if [[ ${skip_tag_check} = false ]]; then
    tag="v${version}"
    if git -C "${sysbox_dir}" rev-parse -q --verify \
           "refs/tags/${tag}" > /dev/null; then
        fail "tag ${tag} already exists locally"
    fi
    if git -C "${sysbox_dir}" ls-remote --exit-code --tags origin \
           "refs/tags/${tag}" > /dev/null 2>&1; then
        fail "tag ${tag} already exists in origin"
    fi
fi

echo "release check passed for Sysbox v${version}"
