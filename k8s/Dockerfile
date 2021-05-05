#
# Copyright 2019-2020 Nestybox, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Docker image for deploying Sysbox on a K8s host.
#
# Build with:
#
# docker build -t nestybox/sysbox-deploy-k8s .
#

# Note: we use a centos base image because it carries a systemctl that can
# communicate with the host's systemd via dbus. This does not work when using a
# ubuntu + systemd image (systemctl can't not connect to the host's dbus, even
# though the host's dbus socket was mounted into the container).

FROM centos/systemd

ARG DEST=/opt/sysbox

RUN yum install -y curl wget

RUN curl -Lso /bin/kubectl https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && \
    chmod +x /bin/kubectl

# dasl for yaml, toml, json parsing
RUN curl -s https://api.github.com/repos/tomwright/dasel/releases/latest | \
    grep browser_download_url | \
    grep linux_amd64 | \
    cut -d '"' -f 4 | \
    wget -qi - && mv dasel_linux_amd64 dasel && chmod +x dasel && mv ./dasel /usr/local/bin/dasel

# Load sysbox artifacts
COPY bin ${DEST}/bin
COPY systemd ${DEST}/systemd
COPY scripts ${DEST}/scripts
COPY config ${DEST}/config
