# syntax=docker/dockerfile:1

# Build context: this directory (clients/sso-web/).
#   docker build -t ip-valet-sso-web \
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
        -X github.com/PatrickH298/ip-valet/clients/sso-web/internal/app.Version=${VERSION} \
        -X github.com/PatrickH298/ip-valet/clients/sso-web/internal/app.Commit=${COMMIT} \
        -X github.com/PatrickH298/ip-valet/clients/sso-web/internal/app.Date=${DATE}" \
      -o /out/ipvalet-sso-web ./cmd/ipvalet-sso-web

# Static, non-root, no shell; the site needs no writable filesystem (sessions
# live in memory). It runs as uid 65532 unless started as another user
# (docker run --user, Compose user:).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ipvalet-sso-web /usr/local/bin/ipvalet-sso-web
USER nonroot:nonroot
# The site; address detection on its own port (optional).
EXPOSE 8091 8092
ENTRYPOINT ["/usr/local/bin/ipvalet-sso-web"]
CMD ["serve"]
