# Optional companion image: the CLI tools this course's optional steps ask
# for (trivy, tshark/tcpdump, kubectl, jq, sqlite), preloaded so a learner
# does not have to install them on the host. Not part of the required
# compose stack — see docs/setup.md. Attaches to the same lab networks so
# it can reach notes-api/soc-lite/agentic-soc by service name.
FROM alpine:3.20

ARG TRIVY_VERSION=0.74.0
ARG KUBECTL_VERSION=v1.30.4

RUN apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      git \
      jq \
      libcap \
      make \
      openssl \
      python3 \
      py3-pip \
      sqlite \
      tcpdump \
      tshark \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump \
    && case "$(uname -m)" in \
         x86_64) TRIVY_ARCH="64bit"; K8S_ARCH="amd64" ;; \
         aarch64) TRIVY_ARCH="ARM64"; K8S_ARCH="arm64" ;; \
         *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
         | tar -xz -C /usr/local/bin trivy \
    && curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${K8S_ARCH}/kubectl" -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

LABEL org.opencontainers.image.source="https://github.com/sanketn26/learn-security" \
      org.opencontainers.image.description="Optional CLI toolbox for the Defensive Security Engineering course labs" \
      org.opencontainers.image.licenses="MIT"

RUN adduser -D -u 1000 learner \
    && addgroup learner wireshark
USER learner
WORKDIR /workspace

CMD ["bash"]
