#!/usr/bin/env bash
#
# Prepares a Sysbox source tree for a release: bumps the VERSION file and adds
# a new entry at the top of CHANGELOG.md.
#
# Usage: prepare-release.sh <sysbox-dir> <version> [<date>]
#
# The new changelog entry is drafted from the commit subjects found in the
# sysbox repo and in each of its submodules since the previous release tag.
# The draft is meant to be reviewed and edited by a maintainer before the
# release is cut.

set -euo pipefail

sysbox_dir=${1:?usage: $0 <sysbox-dir> <version> [<date>]}
version=${2:?usage: $0 <sysbox-dir> <version> [<date>]}
release_date=${3:-$(date -u +%Y-%m-%d)}

version_file="${sysbox_dir}/VERSION"
changelog_file="${sysbox_dir}/CHANGELOG.md"

# Subjects matching this pattern are bookkeeping commits that don't belong in
# the changelog.
noise_regex='^(Updating submodules?|Release v|Merge )|Updating submodules?\.?$'

# Prints an error message and aborts.
function fail() {
    echo "prepare-release failed: $*" >&2
    exit 1
}

# Ensures that the new version is well formed and newer than the current one.
function check_version() {
    local current=$1

    [[ ${version} =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        fail "version '${version}' is not of the form MAJOR.MINOR.PATCH"

    local newest
    newest=$(printf '%s\n%s\n' "${current}" "${version}" | sort -V | tail -1)
    if [[ ${current} = "${version}" || ${newest} != "${version}" ]]; then
        fail "version ${version} is not newer than current ${current}"
    fi

    if grep -q "^## \[${version}\]" "${changelog_file}"; then
        fail "CHANGELOG.md already has an entry for ${version}"
    fi
}

# Emits one changelog bullet per commit in the given range of the given repo.
# Arguments: <repo-dir> <range> [<bullet-prefix>].
function log_bullets() {
    local repo=$1 range=$2 prefix=${3:-}

    git -C "${repo}" log --no-merges --reverse --format='%s' "${range}" |
        grep -Ev "${noise_regex}" |
        sed "s/^/* ${prefix}/" || true
}

# Emits the draft changelog bullets for everything since the previous release.
function draft_bullets() {
    local prev_tag="v$1"

    if ! git -C "${sysbox_dir}" rev-parse -q --verify \
             "refs/tags/${prev_tag}" > /dev/null; then
        echo "* TODO: describe changes (tag ${prev_tag} not found)."
        return
    fi

    log_bullets "${sysbox_dir}" "${prev_tag}..HEAD"

    # Walk the submodules whose pinned commit changed since the last release.
    local path old new
    while read -r path; do
        old=$(git -C "${sysbox_dir}" rev-parse "${prev_tag}:${path}" \
                  2> /dev/null) || continue
        new=$(git -C "${sysbox_dir}" rev-parse "HEAD:${path}")
        [[ ${old} = "${new}" ]] && continue
        if [[ ! -e ${sysbox_dir}/${path}/.git ]]; then
            echo "warning: submodule ${path} not checked out; skipping" >&2
            continue
        fi
        log_bullets "${sysbox_dir}/${path}" "${old}..${new}" "[${path}] "
    done < <(git -C "${sysbox_dir}" submodule status | awk '{print $2}')
}

current_version=$(tr -d '[:space:]' < "${version_file}")
check_version "${current_version}"

# Build the new changelog entry in a temp file.
entry=$(mktemp)
trap 'rm -f "${entry}"' EXIT
{
    echo "## [${version}] - ${release_date}"
    echo "### Added"
    draft_bullets "${current_version}"
    echo
} > "${entry}"

# Insert the entry right before the first existing entry.
tmp_changelog=$(mktemp)
awk -v entry_file="${entry}" '
    !done && /^## \[/ {
        while ((getline line < entry_file) > 0) print line
        done = 1
    }
    { print }
' "${changelog_file}" > "${tmp_changelog}"
cat "${tmp_changelog}" > "${changelog_file}"
rm -f "${tmp_changelog}"

echo "${version}" > "${version_file}"

echo "Prepared Sysbox v${version} (previous: v${current_version})."
