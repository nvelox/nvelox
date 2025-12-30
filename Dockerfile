# Build Stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy Source
COPY . .

# Build Static Binary
# CGO_ENABLED=0 for static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o nvelox main.go

# Final Stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies (e.g. ca-certificates for TLS)
RUN apk add --no-cache ca-certificates tzdata

# Create nvelox user/group
RUN addgroup -S nvelox && adduser -S nvelox -G nvelox

# Copy Binary
COPY --from=builder /app/nvelox /usr/local/bin/nvelox

# Copy Example Config as Default
COPY nvelox.example.yaml /etc/nvelox/nvelox.conf

# Create Config and Log Directories
RUN mkdir -p /etc/nvelox/config.d && \
    mkdir -p /var/log/nvelox && \
    chown -R nvelox:nvelox /etc/nvelox /var/log/nvelox

# Use nvelox user (Security Best Practice)
USER nvelox

# Expose ports (Documentary)
EXPOSE 80 443 8080

# Entrypoint
ENTRYPOINT ["/usr/local/bin/nvelox"]
CMD ["-config", "/etc/nvelox/nvelox.conf"]
