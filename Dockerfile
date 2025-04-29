FROM golang:1.23 AS builder

WORKDIR /app

# Copy the source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o teamspace-operator

# Use a minimal base image
FROM alpine:3.17

# Install necessary packages
RUN apk --no-cache add ca-certificates

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /app/teamspace-operator /teamspace-operator

# Run as non-root user
RUN adduser -D -u 1001 teamspace
USER 1001

# Command to run
ENTRYPOINT ["/teamspace-operator"] 