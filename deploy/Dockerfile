# Builds this fork from source and bakes in one deploy profile
# (deploy/<PROFILE>/), whose files seed the data directory on first boot.
#   docker build -f deploy/Dockerfile --build-arg PROFILE=glyphbyte .
# The build context must include the nostrdb submodule:
#   git submodule update --init --recursive

# Base images are pinned by digest (the multi-arch index), so a rebuild uses
# exactly the image that was reviewed even if the tag is re-pushed. The tag is
# kept for readability; Docker uses only the digest. To update: read the new
# index digest (`docker buildx imagetools inspect golang:1.23-alpine`), paste
# it here, rebuild, smoke-test.

# ── builder ────────────────────────────────────────────────────────
FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f AS builder

RUN apk add --no-cache git bash curl tar gcc musl-dev make autoconf automake libtool libstdc++ libgcc

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN find server/db/nostrdb -type f \! -name '*.o' \! -name '*.a' \! -name '*.png' \! -name '*.pdf' \
        -exec sed -i 's/\r$//' {} + \
    && rm -rf server/db/nostrdb/lib server/db/nostrdb/include \
    && cd server/db/nostrdb && bash build.sh

# Dashboard assets, as in docs/docker/Dockerfile.dev, but with a fixed Tailwind
# release whose binary is checked against its sha256 before it runs (the
# build used to fetch releases/latest and execute it unchecked). To update:
# take the version and the `digest` of the tailwindcss-linux-x64-musl asset
# from `gh api repos/tailwindlabs/tailwindcss/releases/tags/<version>`.
ARG TAILWIND_VERSION=v4.3.5
ARG TAILWIND_SHA256=bb050edd13f15006d872a9bb1772b908618a8df6806d30bf095cba26a09e640b
RUN curl -fsSL -o /tmp/tailwindcss \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64-musl" \
    && echo "${TAILWIND_SHA256}  /tmp/tailwindcss" | sha256sum -c - \
    && chmod +x /tmp/tailwindcss \
    && (cd www/style && /tmp/tailwindcss -i input.css -o tailwind.min.css --minify) \
    && sed -i 's|<script src="https://cdn.tailwindcss.com"></script>|<link rel="stylesheet" href="/style/tailwind.min.css?v={{assetVersion}}">|g' \
        www/views/templates/layout.html \
    && rm /tmp/tailwindcss
ARG MILL_VERSION=1.8.2
RUN mkdir -p www/static/mill \
    && curl -fsSL -o www/static/mill/mill.umd.min.js \
        "https://cdn.jsdelivr.net/npm/nostr-mill@${MILL_VERSION}/dist/mill.umd.min.js"
RUN mkdir -p docs/openapi && [ -s docs/openapi/swagger.json ] \
    || echo '{"swagger":"2.0","info":{"title":"grain","version":"fork"},"paths":{}}' > docs/openapi/swagger.json

# musl gives new threads a small default stack (128 KB); nostrdb's threads overflow it
# (grain --import segfaulted on the droplet, 2026-11-04). Ask the linker for 8 MB,
# which musl uses as the default for every thread it creates.
RUN CGO_ENABLED=1 go build -buildvcs=false -ldflags "-linkmode external -extldflags -Wl,-z,stack-size=8388608" -o /out/grain .

# ── runtime ────────────────────────────────────────────────────────
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache ca-certificates libstdc++ libgcc wget su-exec \
    && addgroup -g 1001 grain && adduser -D -s /bin/sh -u 1001 -G grain grain

ARG PROFILE
WORKDIR /app
COPY --from=builder /out/grain /app/grain
COPY deploy/${PROFILE}/ /app/profile/
COPY deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV GRAIN_DATA_DIR=/data
EXPOSE 8181
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8181/ || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
