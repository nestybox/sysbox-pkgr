ARG GO_IMAGE
ARG BUILD_IMAGE=debian:buster
FROM ${GO_IMAGE} as golang

FROM ${BUILD_IMAGE}

RUN apt-get update &&  \
    apt-get install -y \
    curl               \
    devscripts         \
    equivs             \
    git                \
    wget               \
    pkg-config         \
    kmod               \
    libnet-dev         \
    libseccomp2        \
    libseccomp-dev

ARG GO_VERSION
ENV GOPATH /go
ENV PATH $PATH:/usr/local/go/bin:$GOPATH/bin

ARG COMMON_FILES
COPY ${COMMON_FILES} /root/build-deb/debian
RUN mk-build-deps -t "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y" -i /root/build-deb/debian/control

ENV DISTRO debian
ENV SUITE buster

COPY --from=golang /usr/local/go /usr/local/go

# Explicit activation of go-module feature (by default in 'auto' mode as per Go 1.13).
ENV GO111MODULE=on
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
    && go get -u github.com/golang/protobuf/protoc-gen-go

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
