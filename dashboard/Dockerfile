# syntax=docker/dockerfile:1

# Build context: this directory (dashboard/).
#   docker build -t ip-valet-dashboard \
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
        -X github.com/PatrickH298/ip-valet/dashboard/internal/app.Version=${VERSION} \
        -X github.com/PatrickH298/ip-valet/dashboard/internal/app.Commit=${COMMIT} \
        -X github.com/PatrickH298/ip-valet/dashboard/internal/app.Date=${DATE}" \
      -o /out/ipvalet-dashboard ./cmd/ipvalet-dashboard

# Static, non-root, no shell; the dashboard needs no writable filesystem.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ipvalet-dashboard /usr/local/bin/ipvalet-dashboard
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/ipvalet-dashboard"]
CMD ["serve"]
