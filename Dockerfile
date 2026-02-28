FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/remnanode-watchdog ./cmd/remnanode-watchdog

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata coreutils docker-cli nftables
COPY --from=builder /out/remnanode-watchdog /usr/local/bin/remnanode-watchdog
ENTRYPOINT ["/usr/local/bin/remnanode-watchdog"]