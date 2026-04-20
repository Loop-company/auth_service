package cache

import (
	"context"
	"testing"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
)

func TestSaveCodeValidatesEmail(t *testing.T) {
	storage := NewRedisVerificationStorage(nil)

	err := storage.SaveCode(context.Background(), entity.PendingUser{}, time.Minute)
	if err == nil {
		t.Fatal("expected SaveCode to reject empty email")
	}
}

func TestSaveCodeValidatesTTL(t *testing.T) {
	storage := NewRedisVerificationStorage(nil)

	err := storage.SaveCode(context.Background(), entity.PendingUser{Email: "user@example.com"}, 0)
	if err == nil {
		t.Fatal("expected SaveCode to reject non-positive ttl")
	}
}
