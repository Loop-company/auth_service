package config

import (
	"reflect"
	"testing"
	"time"
)

func TestLoadReadsEnvironment(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("ACCESS_TTL", "15m")
	t.Setenv("REFRESH_TTL", "720h")
	t.Setenv("GRPC_PORT", "50052")
	t.Setenv("AUTH_SECRET", "secret")
	t.Setenv("POSTGRES_HOST", "postgres")
	t.Setenv("POSTGRES_PORT", "5433")
	t.Setenv("POSTGRES_USER", "auth")
	t.Setenv("POSTGRES_PASSWORD", "password")
	t.Setenv("POSTGRES_DB", "auth_db")
	t.Setenv("POSTGRES_SSLMODE", "disable")
	t.Setenv("SMTP_HOST", "smtp")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("SMTP_USER", "mailer")
	t.Setenv("SMTP_PASSWORD", "smtp-pass")
	t.Setenv("SMTP_FROM", "noreply@example.com")
	t.Setenv("REDIS_ADDR", "redis:6379")
	t.Setenv("KAFKA_BROKERS", "kafka:9092,kafka2:9092")

	cfg := Load()

	if cfg.Env != "test" || cfg.Secret != "secret" || cfg.GRPC.Port != "50052" {
		t.Fatalf("unexpected top-level config: %+v", cfg)
	}
	if cfg.AccessTokenTTL != 15*time.Minute || cfg.RefreshTokenTTL != 720*time.Hour {
		t.Fatalf("unexpected ttl config: access=%v refresh=%v", cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	}
	if cfg.DB.Host != "postgres" || cfg.DB.Port != "5433" || cfg.DB.Dbname != "auth_db" || cfg.DB.Sslmode != "disable" {
		t.Fatalf("unexpected db config: %+v", cfg.DB)
	}
	if cfg.SMTP.Host != "smtp" || cfg.SMTP.Port != 2525 || cfg.SMTP.From != "noreply@example.com" {
		t.Fatalf("unexpected smtp config: %+v", cfg.SMTP)
	}
	if cfg.RedisAddress != "redis:6379" {
		t.Fatalf("redis addr = %q", cfg.RedisAddress)
	}
	if !reflect.DeepEqual(cfg.Kafka.Brokers, []string{"kafka:9092", "kafka2:9092"}) {
		t.Fatalf("kafka brokers = %#v", cfg.Kafka.Brokers)
	}
}
