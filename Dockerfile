# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/wolfi-base AS base

RUN apk upgrade --no-cache && apk add --no-cache bash go make git ca-certificates upx

FROM base AS build
WORKDIR /obot-providers/enterprise-providers
COPY . /obot-providers/enterprise-providers
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make package-providers

RUN mkdir -p /runtime/obot-providers/enterprise-providers /runtime/etc/ssl/certs /runtime/tmp \
    && chmod 1777 /runtime/tmp \
    && cp /etc/ssl/certs/ca-certificates.crt /runtime/etc/ssl/certs/ca-certificates.crt \
    && cp /obot-providers/.envrc.providers.enterprise /runtime/obot-providers/.envrc.providers.enterprise \
    && cp -a auth-providers model-providers /runtime/obot-providers/enterprise-providers/ \
    && for binary in */bin/obot-provider; do \
        mkdir -p "/runtime/obot-providers/enterprise-providers/$(dirname "$binary")"; \
        cp "$binary" "/runtime/obot-providers/enterprise-providers/$binary"; \
    done

# Compress only the packaged copies, retaining ordinary binaries in the build stage.
FROM build AS package
ARG COMPRESS_BINARIES=true
RUN case "$COMPRESS_BINARIES" in \
        true) upx --best --lzma /runtime/obot-providers/enterprise-providers/*/bin/obot-provider \
            && upx --test /runtime/obot-providers/enterprise-providers/*/bin/obot-provider ;; \
        false) ;; \
        *) echo 'COMPRESS_BINARIES must be true or false' >&2; exit 1 ;; \
    esac

FROM scratch AS enterprise-providers
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /obot-providers/enterprise-providers
COPY --from=package /runtime/ /
