# Build a static cinc-server-ng binary and ship it on distroless.
# Base images are pinned by digest; Dependabot keeps them current.
FROM golang:1.26@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS build
WORKDIR /src
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE} -s -w" -o /cinc-server-ng ./cmd/cinc-server-ng
# An empty /data for --storage sqlite; a named volume mounted there inherits
# its ownership, so the unprivileged user below can write to it.
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /cinc-server-ng /cinc-server-ng
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
EXPOSE 8889
ENTRYPOINT ["/cinc-server-ng"]
CMD ["--addr", "0.0.0.0:8889"]
