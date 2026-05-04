FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/wgmgr ./cmd/wgmgr

FROM alpine:3.20

RUN apk add --no-cache wireguard-tools ca-certificates

COPY --from=builder /out/wgmgr /usr/local/bin/wgmgr

EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/wgmgr"]
