FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/auth-service ./cmd

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates
ENV GIN_MODE=debug
ENV LOG_LEVEL=debug

COPY --from=builder /out/auth-service /app/main

EXPOSE 8080
CMD ["/app/main"]
