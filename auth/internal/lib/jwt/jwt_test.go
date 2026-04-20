package jwt

import (
	"testing"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
)

func TestNewTokenPairAndParseToken(t *testing.T) {
	user := entity.User{GUID: "user-1", Email: "user@example.com"}
	tokenPair, err := NewTokenPair(user, time.Minute, "secret-key", "session-1")
	if err != nil {
		t.Fatalf("NewTokenPair returned error: %v", err)
	}

	if tokenPair.AccessToken == "" {
		t.Fatal("expected access token to be generated")
	}
	if tokenPair.RefreshToken == "" {
		t.Fatal("expected refresh token to be generated")
	}
	if tokenPair.RefreshTokenHash == "" {
		t.Fatal("expected refresh token hash to be generated")
	}

	claims, err := ParseToken(tokenPair.AccessToken, "secret-key")
	if err != nil {
		t.Fatalf("ParseToken returned error: %v", err)
	}

	if claims.GUID != user.GUID {
		t.Fatalf("expected GUID %q, got %q", user.GUID, claims.GUID)
	}
	if claims.SessionID != "session-1" {
		t.Fatalf("expected session ID %q, got %q", "session-1", claims.SessionID)
	}
}

func TestVerifyRefreshToken(t *testing.T) {
	user := entity.User{GUID: "user-2"}
	tokenPair, err := NewTokenPair(user, time.Minute, "secret-key", "session-2")
	if err != nil {
		t.Fatalf("NewTokenPair returned error: %v", err)
	}

	if err := VerifyRefreshToken(tokenPair.RefreshToken, tokenPair.RefreshTokenHash); err != nil {
		t.Fatalf("VerifyRefreshToken returned error: %v", err)
	}
	if err := VerifyRefreshToken("wrong-token", tokenPair.RefreshTokenHash); err == nil {
		t.Fatal("expected VerifyRefreshToken to fail for invalid token")
	}
}

func TestParseTokenRejectsInvalidToken(t *testing.T) {
	if _, err := ParseToken("not-a-token", "secret-key"); err == nil {
		t.Fatal("expected ParseToken to fail for malformed token")
	}
}
