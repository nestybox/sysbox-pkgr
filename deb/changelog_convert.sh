#!/bin/bash
#
# Copyright: (C) 2019-2022 Nestybox Inc.  All rights reserved.
#
# Description: Script converts a user-defined changelog file into a
# debian-friendly counterpart.
#
# Required input:
#
# User-defined changelog file must necessarily utilize the following layout:
#
# $ cat CHANGELOG.md
# ...
# ## [0.0.2-dev] - unreleased
# ### Added
#  * Generate external documentation: README, user-guide, design-guide, etc.
#  * Extend Sysbox support to Ubuntu-Bionic.
#
# ## [0.0.1] - 2019-06-23
# ### Added
#  * Initial public release.
# ...
#
# Expected output:
#
# $ cat sysbox-pkgr/deb/common/sysbox-ce/changelog
# ...
# sysbox-ce (0.0.2-0) unstable; urgency=medium
#
#  * Generate external documentation: README, user-guide, design-guide, etc.
#  * Extend Sysbox support to Ubuntu-Bionic.
#
#  -- Rodny Molina <rmolina@nestybox.com> Tue, 20 Aug 2019 16:21:10 -0700
#
# sysbox-ce (0.0.1-0) unstable; urgency=medium
#
#  * Initial public release.
#
#  -- Rodny Molina <rmolina@nestybox.com> Tue, 23 Jul 2019 17:37:44 -0400
# ...
#
# Note 1: The CHANGELOG.md file will be parsed attending to the two following
# reg-expresions. Anything that doesn't match this pattern will be ignored.
#
# - "^## "  Example: "## [0.0.1] - 2019-06-23
# - "^ * "  Example: " * Extend Sysbox support to Ubuntu-Bionic."
#
# Note 2: As per Debian's policy guidelines, the "unreleased" label must be
# utilized to tag packages that have not been properly released yet. We must keep
# this in mind when generating 'private' images to be provided to third parties.
# In these cases, the "version" tag will be derived from the sysbox/VERSION file;
# for all othe entries (i.e. "released" entries), the version field will be
# extracted from the changelog file itself.

# Input file to be created/edited by whoever creates a new Sysbox release.
changelog_file="sysbox/CHANGELOG.md"

# Version file to be taking into account to set the latest (top-most) changelog
# entry.
version_file="sysbox/VERSION"

# Output file to be generated by this script, and to be included in Sysbox's
# debian-package installer.
debian_changelog="debian/changelog"

# Base container image used to build Sysbox binaries.
BASE_DISTRO=${BASE_IMAGE%:*}
BASE_DISTRO_RELEASE=${BASE_IMAGE#*:}

# Redirect all generated output.
exec >${debian_changelog}

function print_tag_header() {

    local tag=$1
    local unreleased=$2

    if [[ "$SYSBOX_RELEASE" = "true" ]]; then
        if [[ $unreleased = true ]]; then
            echo -e "sysbox-${EDITION} (${tag}.linux) UNRELEASED; urgency=medium\n"
        else
            echo -e "sysbox-${EDITION} (${tag}.linux) unstable; urgency=medium\n"
        fi
    else
        if [[ $unreleased = true ]]; then
            echo -e "sysbox-${EDITION} (${tag}.${BASE_DISTRO}-${BASE_DISTRO_RELEASE}) UNRELEASED; urgency=medium\n"
        else
            echo -e "sysbox-${EDITION} (${tag}.${BASE_DISTRO}-${BASE_DISTRO_RELEASE}) unstable; urgency=medium\n"
        fi
    fi
}

function print_tag_trailer() {

    local tag=$1
    local unreleased=$2

    local tag_author=""
    local tag_email=""
    local tag_date=""

    if [[ "$unreleased" = true ]]; then
        tag_author=$(git config user.name)
        tag_email=$(git config user.email)
        tag_date=$(date --rfc-2822)
    else
        tag_author=$(git -C sysbox log -1 --format=%aN v$1)
        tag_email=$(git -C sysbox log -1 --format=%ae v$1)
        tag_date=$(git -C sysbox log -1 --format=%aD v$tag)
    fi

    echo -e "\n -- ${tag_author} <${tag_email}>  ${tag_date}\n"
}

function main() {
    local currTag=""
    local prevTag=""
    local unreleased=""
    local prevUnreleased=""

    # Ensure that a version file is available.
    if [[ ! -f ${version_file} ]]; then
        echo "Sysbox VERSION file not found. Exiting..."
        exit 1
    fi

    # Ensure that a changelog file is available.
    if [[ ! -f ${changelog_file} ]]; then
        echo "Sysbox CHANGELOG.md file not found. Exiting..."
        exit 1
    fi
    local versionTag=$(cat ${version_file})

    # Iterate though CHANGELOG.md file to extract relevant information.
    while IFS= read -r line; do
        if echo ${line} | egrep -q "^## "; then

            local currTag=$(echo ${line} | cut -d"[" -f2 | cut -d"]" -f1)

            # If an 'unreleased' entry is found (usually the first / top-most
            # line in changelog file), then we will honor the tag present in the
            # 'version' file. For all other entries we will exclusively rely on
            # tags present in the changelog file.
            if echo ${line} | egrep -q "unreleased"; then
                unreleased=true
                currTag=${versionTag}
            else
                unreleased=false
            fi

            if [[ ${currTag} != ${prevTag} ]] && [[ ${prevTag} != "" ]]; then
                print_tag_trailer ${prevTag} ${prevUnreleased}
            fi

            print_tag_header ${currTag} ${unreleased}

            prevTag=${currTag}
            prevUnreleased=${unreleased}

        elif echo "${line}" | egrep -q "^ * "; then
            echo -e "${line}"
        fi

    done < ${changelog_file}

    print_tag_trailer ${currTag} ${unreleased}
}

main
