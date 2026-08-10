# Build a static cinc-server-ng binary and ship it on distroless.
FROM golang:1.26 AS build
WORKDIR /src
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE} -s -w" -o /cinc-server-ng ./cmd/cinc-server-ng

FROM gcr.io/distroless/static-debian12
COPY --from=build /cinc-server-ng /cinc-server-ng
EXPOSE 8889
ENTRYPOINT ["/cinc-server-ng"]
CMD ["--addr", "0.0.0.0:8889"]
