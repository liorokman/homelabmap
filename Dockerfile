# Two images from one build: --target web and --target scanner.

FROM golang:1.27.4-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/liorokman/homelabmap/internal/scanner.Version=${VERSION}" \
      -o /out/ ./cmd/homelabmap-web ./cmd/homelabmap-scanner ./cmd/homelabmap-listen

FROM alpine:3.24.4 AS base
LABEL org.opencontainers.image.source="https://github.com/liorokman/homelabmap" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://github.com/liorokman/homelabmap"

# --- UI, API, scheduler, SQLite. No special privileges. ---
FROM base AS web
LABEL org.opencontainers.image.title="homelabmap-web" \
      org.opencontainers.image.description="homelabmap web UI, API and topology inference"
RUN adduser -D -H -u 65532 homelabmap && mkdir /data && chown 65532:65532 /data
COPY --from=build /out/homelabmap-web /usr/local/bin/homelabmap-web
USER 65532:65532
VOLUME /data
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -qO /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/homelabmap-web"]

# --- Scanner: host network. Non-root; only nmap and the passive listener
# (homelabmap-listen, raw sockets only) carry capabilities.
# The container must be started with cap_add NET_RAW, NET_ADMIN (and may
# drop everything else): file caps outside the bounding set make exec fail.
FROM base AS scanner
LABEL org.opencontainers.image.title="homelabmap-scanner" \
      org.opencontainers.image.description="homelabmap network scanner (host network, nmap, SNMP, APIs)"
COPY --from=build /out/homelabmap-scanner /out/homelabmap-listen /usr/local/bin/
RUN apk add --no-cache nmap && \
    apk add --no-cache --virtual .caps libcap-utils && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap && \
    setcap cap_net_raw+ep /usr/local/bin/homelabmap-listen && \
    apk del .caps && \
    adduser -D -H -u 65532 homelabmap
ENV HOMELABMAP_NMAP_PRIVILEGED=true
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/homelabmap-scanner"]
