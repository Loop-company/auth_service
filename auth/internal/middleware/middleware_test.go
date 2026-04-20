package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	jwtlib "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/lib/jwt"
	"github.com/gin-gonic/gin"
)

func TestExtractTokenFromHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{name: "valid bearer token", header: "Bearer token-123", want: "token-123"},
		{name: "empty header", header: "", want: ""},
		{name: "wrong schema", header: "Basic token-123", want: ""},
		{name: "missing token", header: "Bearer", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractTokenFromHeader(tt.header); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestAuthMiddlewareRejectsMissingToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(AuthMiddleware("secret"))
	router.GET("/private", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestAuthMiddlewareSetsContextValues(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(AuthMiddleware("secret"))
	router.GET("/private", func(c *gin.Context) {
		body := map[string]string{
			"user_guid":  c.GetString("user_guid"),
			"session_id": c.GetString("session_id"),
		}
		c.JSON(http.StatusOK, body)
	})

	tokenPair, err := jwtlib.NewTokenPair(entity.User{GUID: "user-42"}, time.Minute, "secret", "session-42")
	if err != nil {
		t.Fatalf("NewTokenPair returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set("Authorization", "Bearer "+tokenPair.AccessToken)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if body["user_guid"] != "user-42" {
		t.Fatalf("expected user_guid to be set, got %q", body["user_guid"])
	}
	if body["session_id"] != "session-42" {
		t.Fatalf("expected session_id to be set, got %q", body["session_id"])
	}
}
