package handlers

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
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	"github.com/gin-gonic/gin"
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
	userExistsByEmailFunc func(ctx context.Context, email string) (bool, error)
	saveUserFunc          func(ctx context.Context, email string, passHash []byte) (string, error)
	getUserByEmailFunc    func(ctx context.Context, email string) (entity.User, error)
	getUserByGUIDFunc     func(ctx context.Context, guid string) (entity.User, error)
}

func (m *userRepoMock) SaveUser(ctx context.Context, email string, passHash []byte) (string, error) {
	if m.saveUserFunc != nil {
		return m.saveUserFunc(ctx, email, passHash)
	}
	return "", nil
}

func (m *userRepoMock) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	if m.getUserByEmailFunc != nil {
		return m.getUserByEmailFunc(ctx, email)
	}
	return entity.User{}, nil
}

func (m *userRepoMock) GetUserByGUID(ctx context.Context, guid string) (entity.User, error) {
	if m.getUserByGUIDFunc != nil {
		return m.getUserByGUIDFunc(ctx, guid)
	}
	return entity.User{}, nil
}

func (m *userRepoMock) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	if m.userExistsByEmailFunc != nil {
		return m.userExistsByEmailFunc(ctx, email)
	}
	return false, nil
}

type redisStorageMock struct {
	getCodeFunc func(ctx context.Context, email string) (entity.PendingUser, error)
}

func (m *redisStorageMock) SaveCode(ctx context.Context, data entity.PendingUser, ttl time.Duration) error {
	return nil
}

func (m *redisStorageMock) GetCode(ctx context.Context, email string) (entity.PendingUser, error) {
	if m.getCodeFunc != nil {
		return m.getCodeFunc(ctx, email)
	}
	return entity.PendingUser{}, nil
}

func (m *redisStorageMock) DeleteCode(ctx context.Context, email string) error {
	return nil
}

type emailClientMock struct{}

func (m *emailClientMock) SendVerificationCode(to, code string) error {
	return nil
}

func newHandler(auth *services.Auth) *AuthHandler {
	return NewAuthHandler(auth)
}

func newAuthService(userRepo services.UserRepository, redisStorage services.RedisStorage) *services.Auth {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return services.NewAuth(
		logger,
		&tokenRepoMock{},
		userRepo,
		redisStorage,
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)
}

func TestSendEmailWithCodeRejectsInvalidBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString(`{"email":"bad"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := newHandler(newAuthService(&userRepoMock{}, &redisStorageMock{}))
	handler.SendEmailWithCode(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestSendEmailWithCodeReturnsAccepted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString(`{"email":"user@example.com","password":"secret123"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := newHandler(newAuthService(
		&userRepoMock{
			userExistsByEmailFunc: func(ctx context.Context, email string) (bool, error) {
				return false, nil
			},
		},
		&redisStorageMock{},
	))

	handler.SendEmailWithCode(ctx)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, recorder.Code)
	}
}

func TestVerifyEmailReturnsUnauthorizedForInvalidCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/auth/verification", bytes.NewBufferString(`{"email":"user@example.com","code":"123456"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := newHandler(newAuthService(
		&userRepoMock{},
		&redisStorageMock{
			getCodeFunc: func(ctx context.Context, email string) (entity.PendingUser, error) {
				return entity.PendingUser{Email: email, Code: "654321"}, nil
			},
		},
	))

	handler.VerifyEmail(ctx)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestLoginRejectsInvalidBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"email":"user@example.com"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := newHandler(newAuthService(&userRepoMock{}, &redisStorageMock{}))
	handler.Login(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestGetCurrentUserGUIDReturnsOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("user_guid", "guid-123")

	handler := newHandler(newAuthService(&userRepoMock{}, &redisStorageMock{}))
	handler.GetCurrentUserGUID(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestLogoutReturnsNoContent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := newHandler(newAuthService(&userRepoMock{}, &redisStorageMock{}))
	router := gin.New()
	router.POST("/auth/logout", func(c *gin.Context) {
		c.Set("user_guid", "guid-123")
		handler.Logout(c)
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, recorder.Code)
	}
}

func TestGetTokenPairByUserGUIDRejectsInvalidBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/auth/tokens", bytes.NewBufferString(`{}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := newHandler(newAuthService(&userRepoMock{}, &redisStorageMock{}))
	handler.GetTokenPairByUserGUID(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestRefreshTokensRejectsInvalidBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBufferString(`{}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler := newHandler(newAuthService(&userRepoMock{}, &redisStorageMock{}))
	handler.RefreshTokens(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}
