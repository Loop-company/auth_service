package routes

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/handlers"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type tokenRepoMock struct{}

func (m *tokenRepoMock) SaveToken(ctx context.Context, token *entity.RefreshToken) error {
	return nil
}

func (m *tokenRepoMock) GetRefreshTokenByUserGUID(ctx context.Context, guid string) (*entity.RefreshToken, error) {
	return nil, nil
}

func (m *tokenRepoMock) DeleteTokenByUserGUID(ctx context.Context, guid string) error {
	return nil
}

type userRepoMock struct {
	getUserByEmailFunc func(ctx context.Context, email string) (entity.User, error)
}

func (m *userRepoMock) SaveUser(ctx context.Context, email string, passHash []byte) (string, error) {
	return "", nil
}

func (m *userRepoMock) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	if m.getUserByEmailFunc != nil {
		return m.getUserByEmailFunc(ctx, email)
	}
	return entity.User{}, nil
}

func (m *userRepoMock) GetUserByGUID(ctx context.Context, guid string) (entity.User, error) {
	return entity.User{}, nil
}

func (m *userRepoMock) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	return false, nil
}

type redisStorageMock struct{}

func (m *redisStorageMock) SaveCode(ctx context.Context, data entity.PendingUser, ttl time.Duration) error {
	return nil
}

func (m *redisStorageMock) GetCode(ctx context.Context, email string) (entity.PendingUser, error) {
	return entity.PendingUser{}, nil
}

func (m *redisStorageMock) DeleteCode(ctx context.Context, email string) error {
	return nil
}

type emailClientMock struct{}

func (m *emailClientMock) SendVerificationCode(to, code string) error {
	return nil
}

func TestRegisterRoutesAddsPublicAndProtectedEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	authService := services.NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{},
		&userRepoMock{
			getUserByEmailFunc: func(ctx context.Context, email string) (entity.User, error) {
				return entity.User{GUID: "guid-1", Email: email, PassHash: passwordHash}, nil
			},
		},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	router := gin.New()
	group := router.Group("/auth")
	RegisterRoutes(group, handlers.NewAuthHandler(authService), "secret")

	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"email":"user@example.com","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	router.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected login route to be registered, got status %d", loginRec.Code)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meRec := httptest.NewRecorder()
	router.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected protected route to be registered, got status %d", meRec.Code)
	}
}
