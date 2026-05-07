# Auth Service

Auth Service отвечает за регистрацию, подтверждение email, логин, refresh/logout и проверку access token. Снаружи к сервису обращается HTTP Gateway по gRPC; прямого HTTP API у Auth Service нет.

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

Контракт описан в `auth/proto/auth.proto`.

- `Register(email, password)` - создает pending-регистрацию и отправляет код подтверждения.
- `Verify(email, code)` - подтверждает код, создает пользователя и возвращает `guid`.
- `Login(email, password)` - возвращает `guid`, `access_token`, `refresh_token` и сроки жизни токенов.
- `Refresh(refresh_token, access_token)` - перевыпускает пару токенов.
- `Logout()` - удаляет refresh-сессию пользователя.
- `GetProfileGUID()` - возвращает `guid` из gRPC metadata.
- `ValidateToken(access_token)` - валидирует access token и возвращает `guid`, `session_id`.

HTTP Gateway передает в metadata:

- `user-agent` и `x-real-ip` / `x-forwarded-for` для login/refresh;
- `user_guid` для protected logout/profile flows.

## Kafka events

События отправляются в общей envelope-структуре:

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

- `user.events`: `user.registered`. User Service читает событие и создает профиль пользователя. Analytics Service тоже читает этот топик.
- `auth.events`: `user.logged_in`. Analytics Service использует событие для отчетов по логинам.

## Переменные окружения

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

SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user
SMTP_PASSWORD=password
SMTP_FROM=noreply@example.com
```

## Запуск

Для запуска Auth Service через Docker Compose из корня репозитория:

```bash
docker compose up --build
```

Этот compose поднимает Auth Service, PostgreSQL и Redis. Для полноценной работы событий Kafka должна быть доступна по адресу из `KAFKA_BROKERS`.

Для запуска всего backend-стека используется Docker Compose в репозитории HTTP Gateway:

```bash
docker compose up --build
```
