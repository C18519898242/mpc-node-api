# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY main.go ./
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/mpc-node-api .

FROM alpine:3.23
COPY --from=build /out/mpc-node-api /usr/local/bin/mpc-node-api
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/mpc-node-api"]
CMD ["-config", "/etc/mpc-node/node.json"]
