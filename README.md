# Enterprise Providers

> [!WARNING]
> This repository is deprecated. Provider development has moved to
> [obot-platform/providers](https://github.com/obot-platform/providers).

Do not open new provider changes here. The repository and its existing release
artifacts remain available for older Obot releases that still consume the
separate enterprise-providers image.

The information below documents the legacy build.

`make build` produces static Go binaries with absolute build paths and debug symbols
removed. Set `CGO_ENABLED=1` if a local build requires cgo.

`make docker-build` packages the provider registries, version metadata, and
UPX-compressed binaries in a `scratch` image. Obot consumes the existing
`/obot-providers` directory with `COPY --from`; the image has no shell or default
command. A CA certificate bundle and writable `/tmp` are included for running a
provider directly with an explicit `--entrypoint`.

Compression minimizes executable size at the cost of build time and startup
decompression. To retain ordinary ELF binaries for debugging, binary inspection,
or environments that restrict executable unpacking, build with:

```sh
docker build --build-arg COMPRESS_BINARIES=false -t enterprise-providers:uncompressed .
```

The Docker build cross-compiles for its target platform, including `linux/amd64`
and `linux/arm64`, without running target binaries during the build.
