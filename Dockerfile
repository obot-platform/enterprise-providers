# syntax=docker/dockerfile:1
FROM cgr.dev/chainguard/wolfi-base AS base

RUN apk upgrade --no-cache && apk add --no-cache go make git curl

FROM base AS build
WORKDIR /obot-providers/enterprise-providers
COPY . /obot-providers/enterprise-providers
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    BIN_DIR=/bin make package-providers

RUN mkdir -p /runtime/obot-providers/enterprise-providers \
    && cp /obot-providers/.envrc.providers.enterprise /runtime/obot-providers/.envrc.providers.enterprise \
    && cp -a auth-providers model-providers /runtime/obot-providers/enterprise-providers/ \
    && find /obot-providers/enterprise-providers -mindepth 2 -maxdepth 2 -type d -name bin -exec sh -c 'provider="$(basename "$(dirname "$1")")"; mkdir -p "/runtime/obot-providers/enterprise-providers/${provider}"; cp -a "$1" "/runtime/obot-providers/enterprise-providers/${provider}/bin"' _ {} \;

FROM cgr.dev/chainguard/wolfi-base AS enterprise-providers
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
WORKDIR /obot-providers/enterprise-providers
COPY --from=build /runtime/ /
