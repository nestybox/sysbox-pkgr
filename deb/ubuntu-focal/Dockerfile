ARG GO_IMAGE
ARG BUILD_IMAGE=ubuntu:focal
ARG DEBIAN_FRONTEND=noninteractive
FROM ${GO_IMAGE} as golang

FROM ${BUILD_IMAGE}

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections && \
    apt-get update &&                            \
    apt-get install -y --no-install-recommends   \
    build-essential                              \
    ca-certificates                              \
    devscripts                                   \
    equivs                                       \
    git                                          \
    wget                                         \
    pkg-config                                   \
    libnet-dev                                   \
    libseccomp2                                  \
    libseccomp-dev                               \
    iproute2                                     \
    kmod                                         \
    unzip &&                                     \
    \
    # Housekeeping
    apt-get clean -y &&                          \
    rm -rf                                       \
    /var/cache/debconf/*                      \
    /var/lib/apt/lists/*                      \
    /var/log/*                                \
    /tmp/*                                    \
    /var/tmp/*                                \
    /usr/share/doc/*                          \
    /usr/share/man/*                          \
    /usr/share/local/*

ARG GO_VERSION
ENV GOPATH /go
ENV PATH $PATH:/usr/local/go/bin:$GOPATH/bin

ARG DEB_FILES
COPY ${DEB_FILES} /root/build-deb/debian
RUN mk-build-deps -t "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y" -i /root/build-deb/debian/control

ENV DISTRO ubuntu
ENV SUITE focal

COPY --from=golang /usr/local/go /usr/local/go

# Let's explicitly set go-module feature to 'auto' mode (default as per Go 1.13) to avoid
# potential changes to this feature's default mode in the future. Even though we are
# relying on modules for the package's building process, we are enabling 'auto' mode to
# allow 'go get' traditional behavior (fetch entire git repo). Notice that we need git's
# metadata to allow a git-checkout operation further below.
ENV GO111MODULE=auto
RUN go env -w GONOSUMDB=github.com/nestybox

# install protoc compiler for gRPC
RUN mkdir -p ~/bin/protoc \
    && cd ~/bin/protoc/ \
    && wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip \
    && unzip protoc-3.6.1-linux-x86_64.zip \
    && cp -r include/* /usr/local/include/ \
    && cp bin/protoc /usr/local/bin/ \
    && cd \
    && rm -rf ~/bin/protoc/ \
    && GIT_TAG="v1.3.1" \
    && go get -d -u github.com/golang/protobuf/protoc-gen-go \
    && git -C "$GOPATH"/src/github.com/golang/protobuf checkout $GIT_TAG > /dev/null \
    && go install github.com/golang/protobuf/protoc-gen-go

# install Docker.
RUN apt-get update \
    && apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg2 \
    software-properties-common \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && apt-key fingerprint 0EBFCD88 \
    && add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
    focal \
    stable" \
    && apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io
ADD https://raw.githubusercontent.com/docker/docker-ce/master/components/cli/contrib/completion/bash/docker /etc/bash_completion.d/docker.sh

# Use the old definition for SECCOMP_NOTIF_ID_VALID in /usr/include/linux/seccomp.h
#
# This is needed because the definition changed in the mainline kernel
# on 06/2020 (from SECCOMP_IOR -> SECCOMP_IOW), and some distros we
# support have picked it up in their latest releases / kernels
# updates. The kernel change was backward compatible, so by using the
# old definition, we are guaranteed it will work on kernels before and
# after the change. On the other hand, if we were to use the new
# definition, seccomp notify would fail when sysbox runs in old
# kernels.
RUN sed -i 's/^#define SECCOMP_IOCTL_NOTIF_ID_VALID[ \t]*SECCOMP_IOW(2, __u64)/#define SECCOMP_IOCTL_NOTIF_ID_VALID   SECCOMP_IOR(2, __u64)/g' /usr/include/linux/seccomp.h

WORKDIR /root/build-deb
COPY sources/ /sources
COPY build-deb /root/build-deb/build-deb
COPY changelog_convert.sh /root/build-deb/changelog_convert.sh

ENTRYPOINT ["/root/build-deb/build-deb"]
