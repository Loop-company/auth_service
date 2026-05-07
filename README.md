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

- `user.events`: `user.registered`. User Service читает событие и создает профиль пользователя.
- `auth.events`: `user.logged_in`. Analytics Service использует событие для отчетов по логинам.

## Запуск

Docker Compose для локального запуска вынесен в репозиторий `loop_infra`.

Из корня `loop_infra`:

```bash
docker compose up --build
```

В этом репозитории остается код сервиса, `Dockerfile` и пример переменных окружения `auth/.env.example`.
