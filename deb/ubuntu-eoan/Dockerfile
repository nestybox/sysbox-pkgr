ARG GO_IMAGE
ARG BUILD_IMAGE=ubuntu:eoan
FROM ${GO_IMAGE} as golang

FROM ${BUILD_IMAGE}

RUN apt-get update &&                            \
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

ARG COMMON_FILES
COPY ${COMMON_FILES} /root/build-deb/debian
RUN mk-build-deps -t "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y" -i /root/build-deb/debian/control

COPY sources/ /sources

ENV DISTRO ubuntu
ENV SUITE eoan

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
    eoan \
    stable" \
    && apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io
ADD https://raw.githubusercontent.com/docker/docker-ce/master/components/cli/contrib/completion/bash/docker /etc/bash_completion.d/docker.sh

WORKDIR /root/build-deb
COPY build-deb /root/build-deb/build-deb
COPY changelog_convert.sh /root/build-deb/changelog_convert.sh

ENTRYPOINT ["/root/build-deb/build-deb"]