# pipeline-guard: a portable image for the CLI + GitHub Action.
#
# The built-in policy engine (scanners/terraform_policy.py, scanners/k8s_policy.py)
# needs nothing beyond Python + PyYAML. Trivy and conftest are installed here so
# the *real* scanner/policy binaries are available when this image runs in CI;
# neither is required to import or unit-test the package (see TrivyRunner /
# ConftestRunner, which are only invoked when their binary is present).

FROM python:3.12-slim AS base

ARG TRIVY_VERSION=0.50.1
ARG CONFTEST_VERSION=0.53.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# Trivy (container image scanning).
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

# Conftest (OPA-based policy testing) -- architecture-aware download.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) conftest_arch="x86_64" ;; \
      arm64) conftest_arch="arm64" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -sfL -o /tmp/conftest.tar.gz \
      "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_${conftest_arch}.tar.gz"; \
    tar -xzf /tmp/conftest.tar.gz -C /usr/local/bin conftest; \
    rm /tmp/conftest.tar.gz

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY policies ./policies
RUN pip install --no-cache-dir .

ENTRYPOINT ["pipeline-guard"]
CMD ["--help"]
