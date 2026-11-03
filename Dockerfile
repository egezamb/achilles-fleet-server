# syntax=docker/dockerfile:1
FROM golang:1.27.2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# modernc.org/sqlite is pure Go, so the binary is static and needs no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/fleet-server ./cmd/fleet-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fleet-server /fleet-server
# Owned by the runtime user, so a new named volume mounted here is writable.
COPY --from=build --chown=65532:65532 /out/data /data
ENV FLEET_DB=/data/fleet.db
VOLUME /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/fleet-server"]
