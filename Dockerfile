# syntax=docker/dockerfile:1

FROM cgr.dev/chainguard/wolfi-base AS build

RUN apk upgrade --no-cache && apk add --no-cache go-1.26 ca-certificates

ARG PROVIDER_DIR
WORKDIR /src
COPY . .

RUN test -n "${PROVIDER_DIR}" \
    && test -f "${PROVIDER_DIR}/go.mod"

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    cd "${PROVIDER_DIR}" \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/bin/gptscript-go-tool .

RUN mkdir -p "/out/enterprise-tools/${PROVIDER_DIR}/bin" \
    && cp /out/bin/gptscript-go-tool "/out/enterprise-tools/${PROVIDER_DIR}/bin/gptscript-go-tool" \
    && if [ -d auth-providers-common/templates ]; then \
        mkdir -p /out/enterprise-tools/auth-providers-common/templates; \
        cp -R auth-providers-common/templates/. /out/enterprise-tools/auth-providers-common/templates/; \
    fi

FROM cgr.dev/chainguard/wolfi-base

RUN apk upgrade --no-cache && apk add --no-cache ca-certificates

ARG PROVIDER_DIR
ENV GPTSCRIPT_TOOL_DIR=/enterprise-tools/${PROVIDER_DIR}
ENV PORT=8000

COPY --from=build /out/enterprise-tools /enterprise-tools
RUN ln -s "${GPTSCRIPT_TOOL_DIR}/bin/gptscript-go-tool" /bin/gptscript-go-tool

WORKDIR ${GPTSCRIPT_TOOL_DIR}
EXPOSE 8000 9999
ENTRYPOINT ["/bin/gptscript-go-tool"]
