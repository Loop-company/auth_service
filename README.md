# Auth Service

gRPC service for registration, email verification, login, token refresh, logout, and access token validation.

## Architecture Role

- Receives calls from HTTP Gateway over gRPC.
- Stores users and refresh sessions in PostgreSQL.
- Stores pending email verification codes in Redis.
- Publishes auth events to Kafka.
- Publishes `user.registered` events to `user.events` so User Service can create a profile.

## Kafka Events

Auth Service publishes the shared analytics event envelope:

```json
{
  "event_id": "uuid",
  "user_id": "user-guid",
  "event_type": "user.logged_in",
  "source_service": "auth-service",
  "payload": {
    "email": "user@example.com"
  },
  "occurred_at": "2026-05-07T12:00:00Z"
}
```

Topics:

- `auth.events` for auth activity.
- `user.events` for user registration events consumed by User Service and Analytics Service.

## Configuration

```env
GRPC_PORT=50051
AUTH_SECRET=change-me
ACCESS_TTL=15m
REFRESH_TTL=720h
POSTGRES_HOST=db-auth
POSTGRES_PORT=5432
POSTGRES_USER=auth
POSTGRES_PASSWORD=auth_password
POSTGRES_DB=authdb
POSTGRES_SSLMODE=disable
REDIS_ADDR=redis-auth:6379
KAFKA_BROKERS=kafka:9092
```

## CI

The GitHub Actions workflow runs build, golangci-lint, tests with coverage, Docker build, and Docker push.
