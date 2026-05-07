# Auth Service

Auth Service отвечает за регистрацию, подтверждение email, логин, refresh/logout и проверку access token. Снаружи к нему обращается только HTTP Gateway по gRPC; прямого HTTP API у сервиса нет.

## Место в архитектуре

```text
Client -> HTTP Gateway -> Auth Service (gRPC)
                            |
                            +-> PostgreSQL: users, refresh sessions
                            +-> Redis: verification codes
                            +-> Kafka: auth.events, user.events
```

Auth Service:

- принимает gRPC-вызовы от HTTP Gateway;
- хранит пользователей и refresh-сессии в PostgreSQL;
- временно хранит коды подтверждения email в Redis;
- публикует события в Kafka для User Service и Analytics Service.

## gRPC API

Сервис описан в `auth/proto/auth.proto`.

- `Register(email, password)` - создает pending-регистрацию и отправляет код подтверждения.
- `Verify(email, code)` - подтверждает код, создает пользователя и возвращает `guid`.
- `Login(email, password)` - возвращает `guid`, `access_token`, `refresh_token` и сроки жизни токенов.
- `Refresh(refresh_token, access_token)` - перевыпускает пару токенов.
- `Logout()` - удаляет refresh-сессию текущего пользователя.
- `GetProfileGUID()` - возвращает `guid` из metadata, которую прокидывает gateway.
- `ValidateToken(access_token)` - валидирует access token и возвращает `guid`, `session_id`.

Gateway передает в metadata:

- `user-agent` и `x-real-ip` / `x-forwarded-for` для login/refresh;
- `user_guid` для protected logout/profile flows.

## Kafka events

Все события отправляются в общей envelope-структуре:

```json
{
  "event_id": "uuid",
  "user_id": "user-guid",
  "event_type": "user.registered",
  "source_service": "auth-service",
  "payload": {
    "email": "user@example.com"
  },
  "occurred_at": "2026-05-07T12:00:00Z"
}
```

Топики:

- `user.events`: `user.registered`. User Service читает это событие и создает профиль пользователя. Analytics Service тоже читает этот топик.
- `auth.events`: `user.logged_in`. Analytics Service использует событие для отчетов по логинам.

## Переменные окружения

Минимальный набор:

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

SMTP нужен для реальной отправки кода:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user
SMTP_PASSWORD=password
SMTP_FROM=noreply@example.com
```

Если SMTP не настроен, сервис можно запускать с logging email client в локальном окружении, но production flow должен использовать реальную почту.

## Запуск

Рекомендуемый способ для всего проекта:

```powershell
cd C:\Users\kira4\Loop-company\http_gateway
docker compose up --build
```

Этот compose поднимает HTTP Gateway, Auth Service, User Service, Analytics Service, PostgreSQL, Redis, Kafka и нужные Kafka topics.

Локальный запуск только Auth Service:

```powershell
cd C:\Users\kira4\Loop-company\auth_service\auth
go run ./cmd
```

Перед локальным запуском должны быть доступны PostgreSQL, Redis и Kafka, а переменные окружения должны указывать на них. Для service-only Docker Compose:

```powershell
cd C:\Users\kira4\Loop-company\auth_service
docker compose up --build
```

Этот compose поднимает auth, PostgreSQL и Redis. Kafka для публикации событий должна быть доступна отдельно по `KAFKA_BROKERS`.

## Проверки

```powershell
cd C:\Users\kira4\Loop-company\auth_service\auth
go test ./...
go test "-coverprofile=coverage.out" "-covermode=atomic" "-coverpkg=./internal/..." ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4 run --config ..\.golangci.yml
```
