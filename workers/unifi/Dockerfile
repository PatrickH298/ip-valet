# syntax=docker/dockerfile:1

# Build context: this directory (workers/unifi/).
#   docker build -t ip-valet-unifi \
#     --build-arg VERSION=0.1.0 --build-arg COMMIT=$(git rev-parse --short HEAD) \
#     --build-arg DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) .

FROM golang:1.27.4-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/PatrickH298/ip-valet/workers/unifi/internal/app.Version=${VERSION} \
        -X github.com/PatrickH298/ip-valet/workers/unifi/internal/app.Commit=${COMMIT} \
        -X github.com/PatrickH298/ip-valet/workers/unifi/internal/app.Date=${DATE}" \
      -o /out/ipvalet-unifi ./cmd/ipvalet-unifi \
 && mkdir -p /out/data

# Static, non-root, no shell. The only writable path is /data, which holds
# the cached desired state; a new volume there takes its owner from the image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ipvalet-unifi /usr/local/bin/ipvalet-unifi
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/ipvalet-unifi"]
CMD ["run"]
