package app

import (
	"io"
	"log/slog"
	"testing"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/config"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/email"
)

func TestBuildEmailClientReturnsLoggingClientWhenSMTPIsIncomplete(t *testing.T) {
	cfg := &config.Config{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	client := buildEmailClient(cfg, logger)

	if _, ok := client.(*email.LoggingClient); !ok {
		t.Fatalf("expected LoggingClient, got %T", client)
	}
}

func TestBuildEmailClientReturnsSMTPClientWhenSMTPIsConfigured(t *testing.T) {
	cfg := &config.Config{}
	cfg.SMTP.Host = "smtp.example.com"
	cfg.SMTP.Port = 587
	cfg.SMTP.User = "user"
	cfg.SMTP.Password = "pass"
	cfg.SMTP.From = "from@example.com"

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := buildEmailClient(cfg, logger)

	if _, ok := client.(*email.SMTPClient); !ok {
		t.Fatalf("expected SMTPClient, got %T", client)
	}
}
