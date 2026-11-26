# syntax=docker/dockerfile:1

# Build context: this directory (api/).
#   docker build -t ip-valet-api \
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
        -X github.com/PatrickH298/ip-valet/api/internal/app.Version=${VERSION} \
        -X github.com/PatrickH298/ip-valet/api/internal/app.Commit=${COMMIT} \
        -X github.com/PatrickH298/ip-valet/api/internal/app.Date=${DATE}" \
      -o /out/ipvalet-api ./cmd/ipvalet-api

# Static, non-root, no shell; the server needs no writable filesystem. It runs
# as uid 65532 unless started as another user (docker run --user, Compose user:).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ipvalet-api /usr/local/bin/ipvalet-api
USER nonroot:nonroot
# API (behind a TLS-terminating proxy); admin API and metrics (keep both off the proxy).
EXPOSE 8080 8081 9090
ENTRYPOINT ["/usr/local/bin/ipvalet-api"]
CMD ["serve"]
