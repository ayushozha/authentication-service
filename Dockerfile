# --- Build stage ---
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /auth-server ./cmd/server

# --- Runtime stage ---
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -u 1000 appuser

WORKDIR /app

COPY --from=builder /auth-server /app/auth-server
COPY public/ /app/public/

USER appuser

ENV PORT=8080
ENV GRPC_PORT=9090
ENV PUBLIC_DIR=/app/public
EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/auth-server"]
