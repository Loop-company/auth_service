### 0. Что это за проект

REST API сервис аутентификации на Go.
Запускается в Docker через три контейнера:

- `auth-service` - приложение
- `db-auth` - PostgreSQL
- `redis-auth` - Redis

Снаружи доступен только API на `localhost:8080`.

### 1. Dockerfile приложения

В проекте есть `auth/Dockerfile`.

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /src

COPY ../go.mod go.sum ./
RUN go mod download

COPY .. .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/auth-service ./auth/cmd

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/auth-service /app/main

EXPOSE 8080
CMD ["/app/main"]
```

### 2. Файл docker-compose.yml

В корне проекта есть `docker-compose.yml`.

Что важно:

1. В `POSTGRES_HOST` должен быть не `localhost`, а имя сервиса базы: `jwt-auth-db`
2. В `REDIS_ADDR` должен быть не `localhost`, а имя сервиса Redis: `jwt-auth-redis:6379`
3. Наружу публикуем только API:
   `8080:8080`
4. PostgreSQL не пробрасываем наружу
5. Для PostgreSQL есть volume:
   `postgres_data:/var/lib/postgresql/data`
6. Все контейнеры находятся в одной bridge-сети

### 3. Файл .env

Локально в корне проекта нужен `.env`.
Он не пушится в git, потому что добавлен в `.gitignore`.

Текущий набор переменных:

```env
ACCESS_TTL=15m
REFRESH_TTL=168h
HTTP_PORT=:8080
AUTH_SECRET=change-secret
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-gmail
SMTP_PASSWORD=your-gmail-app-password
SMTP_FROM=Auth Service <your-gmail@gmail.com>
POSTGRES_HOST=jwt-auth-db
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=change-password
POSTGRES_DB=jwt_db
POSTGRES_SSLMODE=disable
REDIS_ADDR=jwt-auth-redis:6379
```

### 4. Запуск проекта

Сборка:

```powershell
docker compose build
```

Запуск:

```powershell
docker compose up -d
```

Проверка контейнеров:

```powershell
docker compose ps
```

Остановка:

```powershell
docker compose down
```

### 5. Что можно проверять в Postman

Базовый адрес:

```text
http://localhost:8080
```

Маршруты:

- `POST /auth/register`
- `POST /auth/verification`
- `POST /auth/login`
- `GET /auth/me`
- `GET /auth/tokens`
- `POST /auth/refresh`
- `POST /auth/logout`

### 6. Что сделано по требованиям лабы

- организована Docker-сеть в `docker-compose.yml`
- контейнер приложения собирается из исходников на любом окружении
- Dockerfile разбит на stages
- снаружи доступен только API
- у PostgreSQL нет port-forwarding
- у PostgreSQL есть volume
- в Dockerfile и docker-compose нет паролей и токенов
- приложение получает секреты из переменных окружения
- `.gitignore` настроен
