# Auth Service

Auth service for registration, email verification, login, token refresh, and logout.

## Project layout

- `auth/` - Go application source code
- `.github/workflows/ci.yml` - CI/CD pipeline for the lab
- `docker-compose.yml` - local infrastructure for the service

## Local run

1. Create environment variables for the service.
2. Build the containers:

```powershell
docker compose build
```

3. Start the stack:

```powershell
docker compose up -d
```

4. Check containers:

```powershell
docker compose ps
```

5. Stop the stack:

```powershell
docker compose down
```

## Required environment variables

Example values:

```env
ACCESS_TTL=15m
REFRESH_TTL=168h
HTTP_PORT=:8080
AUTH_SECRET=change-me
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email
SMTP_PASSWORD=your-app-password
SMTP_FROM=Auth Service <your-email@example.com>
POSTGRES_HOST=jwt-auth-db
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=change-me
POSTGRES_DB=jwt_db
POSTGRES_SSLMODE=disable
REDIS_ADDR=jwt-auth-redis:6379
```

## API

Base URL:

```text
http://localhost:8080
```

Available routes:

- `POST /auth/register`
- `POST /auth/verification`
- `POST /auth/login`
- `GET /auth/me`
- `GET /auth/tokens`
- `POST /auth/refresh`
- `POST /auth/logout`

## CI/CD for the lab

The GitHub Actions pipeline contains the required jobs:

- `build`
- `lint`
- `test`
- `docker_build`
- `docker_push`

The `test` job produces a coverage artifact and fails if coverage is below `50%`.
The `docker_push` job uses GitHub secrets and never stores Docker Hub credentials in the repository.

## GitHub secrets and variables

Add these repository secrets before pushing Docker images:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
