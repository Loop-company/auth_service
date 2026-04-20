package services

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/lib/jwt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type tokenRepoMock struct {
	saveTokenFunc               func(ctx context.Context, token *entity.RefreshToken) error
	getRefreshTokenByUserGUIDFn func(ctx context.Context, guid string) (*entity.RefreshToken, error)
	deleteTokenByUserGUIDFunc   func(ctx context.Context, guid string) error
}

func (m *tokenRepoMock) SaveToken(ctx context.Context, token *entity.RefreshToken) error {
	if m.saveTokenFunc != nil {
		return m.saveTokenFunc(ctx, token)
	}
	return nil
}

func (m *tokenRepoMock) GetRefreshTokenByUserGUID(ctx context.Context, guid string) (*entity.RefreshToken, error) {
	if m.getRefreshTokenByUserGUIDFn != nil {
		return m.getRefreshTokenByUserGUIDFn(ctx, guid)
	}
	return nil, nil
}

func (m *tokenRepoMock) DeleteTokenByUserGUID(ctx context.Context, guid string) error {
	if m.deleteTokenByUserGUIDFunc != nil {
		return m.deleteTokenByUserGUIDFunc(ctx, guid)
	}
	return nil
}

type userRepoMock struct {
	saveUserFunc          func(ctx context.Context, email string, passHash []byte) (string, error)
	getUserByEmailFunc    func(ctx context.Context, email string) (entity.User, error)
	getUserByGUIDFunc     func(ctx context.Context, guid string) (entity.User, error)
	userExistsByEmailFunc func(ctx context.Context, email string) (bool, error)
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
	saveCodeFunc   func(ctx context.Context, data entity.PendingUser, ttl time.Duration) error
	getCodeFunc    func(ctx context.Context, email string) (entity.PendingUser, error)
	deleteCodeFunc func(ctx context.Context, email string) error
}

func (m *redisStorageMock) SaveCode(ctx context.Context, data entity.PendingUser, ttl time.Duration) error {
	if m.saveCodeFunc != nil {
		return m.saveCodeFunc(ctx, data, ttl)
	}
	return nil
}

func (m *redisStorageMock) GetCode(ctx context.Context, email string) (entity.PendingUser, error) {
	if m.getCodeFunc != nil {
		return m.getCodeFunc(ctx, email)
	}
	return entity.PendingUser{}, nil
}

func (m *redisStorageMock) DeleteCode(ctx context.Context, email string) error {
	if m.deleteCodeFunc != nil {
		return m.deleteCodeFunc(ctx, email)
	}
	return nil
}

type emailClientMock struct {
	sendVerificationCodeFunc func(to, code string) error
}

func (m *emailClientMock) SendVerificationCode(to, code string) error {
	if m.sendVerificationCodeFunc != nil {
		return m.sendVerificationCodeFunc(to, code)
	}
	return nil
}

func newTestAuth() *Auth {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewAuth(
		logger,
		&tokenRepoMock{},
		&userRepoMock{},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)
}

func TestGenerateCode(t *testing.T) {
	code, err := generateCode()
	if err != nil {
		t.Fatalf("generateCode returned error: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6 digits, got %q", code)
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			t.Fatalf("expected numeric code, got %q", code)
		}
	}
}

func TestSendingEmailWithCodeSuccess(t *testing.T) {
	var saved entity.PendingUser
	var sentEmail string
	var sentCode string

	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{},
		&userRepoMock{
			userExistsByEmailFunc: func(ctx context.Context, email string) (bool, error) {
				return false, nil
			},
		},
		&redisStorageMock{
			saveCodeFunc: func(ctx context.Context, data entity.PendingUser, ttl time.Duration) error {
				saved = data
				if ttl != 10*time.Minute {
					t.Fatalf("expected ttl 10m, got %s", ttl)
				}
				return nil
			},
		},
		&emailClientMock{
			sendVerificationCodeFunc: func(to, code string) error {
				sentEmail = to
				sentCode = code
				return nil
			},
		},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	if err := auth.SendingEmailWithCode(context.Background(), "user@example.com", "secret123"); err != nil {
		t.Fatalf("SendingEmailWithCode returned error: %v", err)
	}

	if saved.Email != "user@example.com" {
		t.Fatalf("expected email to be saved, got %q", saved.Email)
	}
	if len(saved.PassHash) == 0 {
		t.Fatal("expected password hash to be saved")
	}
	if err := bcrypt.CompareHashAndPassword(saved.PassHash, []byte("secret123")); err != nil {
		t.Fatalf("saved password hash does not match password: %v", err)
	}
	if sentEmail != "user@example.com" {
		t.Fatalf("expected verification email to %q, got %q", "user@example.com", sentEmail)
	}
	if sentCode != saved.Code {
		t.Fatalf("expected sent code %q to match saved code %q", sentCode, saved.Code)
	}
}

func TestSendingEmailWithCodeReturnsUserExistsError(t *testing.T) {
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{},
		&userRepoMock{
			userExistsByEmailFunc: func(ctx context.Context, email string) (bool, error) {
				return true, nil
			},
		},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	if err := auth.SendingEmailWithCode(context.Background(), "user@example.com", "secret123"); err == nil {
		t.Fatal("expected SendingEmailWithCode to return an error")
	}
}

func TestSendingEmailWithCodeSwallowsEmailErrors(t *testing.T) {
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{},
		&userRepoMock{
			userExistsByEmailFunc: func(ctx context.Context, email string) (bool, error) {
				return false, nil
			},
		},
		&redisStorageMock{},
		&emailClientMock{
			sendVerificationCodeFunc: func(to, code string) error {
				return errors.New("smtp failed")
			},
		},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	if err := auth.SendingEmailWithCode(context.Background(), "user@example.com", "secret123"); err != nil {
		t.Fatalf("expected email errors to be swallowed, got %v", err)
	}
}

func TestConfirmVerificationCode(t *testing.T) {
	pending := entity.PendingUser{
		Email:    "user@example.com",
		PassHash: []byte("hash"),
		Code:     "123456",
	}

	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{},
		&userRepoMock{
			saveUserFunc: func(ctx context.Context, email string, passHash []byte) (string, error) {
				if email != pending.Email {
					t.Fatalf("expected email %q, got %q", pending.Email, email)
				}
				return "guid-1", nil
			},
		},
		&redisStorageMock{
			getCodeFunc: func(ctx context.Context, email string) (entity.PendingUser, error) {
				return pending, nil
			},
			deleteCodeFunc: func(ctx context.Context, email string) error {
				if email != pending.Email {
					t.Fatalf("expected delete for %q, got %q", pending.Email, email)
				}
				return nil
			},
		},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	guid, err := auth.ConfirmVerificationCode(context.Background(), pending.Email, pending.Code)
	if err != nil {
		t.Fatalf("ConfirmVerificationCode returned error: %v", err)
	}
	if guid != "guid-1" {
		t.Fatalf("expected guid %q, got %q", "guid-1", guid)
	}
}

func TestConfirmVerificationCodeRejectsInvalidCode(t *testing.T) {
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{},
		&userRepoMock{},
		&redisStorageMock{
			getCodeFunc: func(ctx context.Context, email string) (entity.PendingUser, error) {
				return entity.PendingUser{Email: email, Code: "654321"}, nil
			},
		},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	if _, err := auth.ConfirmVerificationCode(context.Background(), "user@example.com", "123456"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expected ErrInvalidCode, got %v", err)
	}
}

func TestGetCurrentUserGUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("user_guid", "guid-123")

	auth := newTestAuth()

	guid, err := auth.GetCurrentUserGUID(ctx)
	if err != nil {
		t.Fatalf("GetCurrentUserGUID returned error: %v", err)
	}
	if guid != "guid-123" {
		t.Fatalf("expected guid %q, got %q", "guid-123", guid)
	}
}

func TestLogoutDeletesToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("user_guid", "guid-logout")

	var deletedGUID string
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{
			deleteTokenByUserGUIDFunc: func(ctx context.Context, guid string) error {
				deletedGUID = guid
				return nil
			},
		},
		&userRepoMock{},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	if err := auth.Logout(ctx); err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}
	if deletedGUID != "guid-logout" {
		t.Fatalf("expected deleted guid %q, got %q", "guid-logout", deletedGUID)
	}
}

func TestLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "127.0.0.1:12345"
	ctx.Request = req

	hash, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to create password hash: %v", err)
	}

	var savedToken *entity.RefreshToken
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{
			saveTokenFunc: func(ctx context.Context, token *entity.RefreshToken) error {
				savedToken = token
				return nil
			},
		},
		&userRepoMock{
			getUserByEmailFunc: func(ctx context.Context, email string) (entity.User, error) {
				return entity.User{
					GUID:     "guid-login",
					Email:    email,
					PassHash: hash,
				}, nil
			},
		},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	tokenPair, guid, err := auth.Login(ctx, "user@example.com", "secret123")
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if guid != "guid-login" {
		t.Fatalf("expected guid %q, got %q", "guid-login", guid)
	}
	if tokenPair.AccessToken == "" || tokenPair.RefreshToken == "" {
		t.Fatal("expected token pair to be returned")
	}
	if savedToken == nil {
		t.Fatal("expected refresh token to be saved")
	}
	if savedToken.UserGUID != "guid-login" {
		t.Fatalf("expected saved token guid %q, got %q", "guid-login", savedToken.UserGUID)
	}
}

func TestGetTokenPairByUserGUIDRejectsAnotherUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("user_guid", "guid-1")

	auth := newTestAuth()

	if _, err := auth.GetTokenPairByUserGUID(ctx, "guid-2"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got %v", err)
	}
}

func TestGetTokenPairByUserGUIDSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest("GET", "/auth/tokens", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "127.0.0.1:12345"
	ctx.Request = req
	ctx.Set("user_guid", "guid-1")

	var savedToken *entity.RefreshToken
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{
			saveTokenFunc: func(ctx context.Context, token *entity.RefreshToken) error {
				savedToken = token
				return nil
			},
		},
		&userRepoMock{
			getUserByGUIDFunc: func(ctx context.Context, guid string) (entity.User, error) {
				return entity.User{GUID: guid, Email: "user@example.com"}, nil
			},
		},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	tokenPair, err := auth.GetTokenPairByUserGUID(ctx, "guid-1")
	if err != nil {
		t.Fatalf("GetTokenPairByUserGUID returned error: %v", err)
	}
	if tokenPair.AccessToken == "" || tokenPair.RefreshToken == "" {
		t.Fatal("expected token pair to be returned")
	}
	if savedToken == nil {
		t.Fatal("expected refresh token to be saved")
	}
}

func TestRefreshTokensRejectsMissingSessionID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("user_guid", "guid-1")
	ctx.Request = httptest.NewRequest("POST", "/auth/refresh", nil)

	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{
			getRefreshTokenByUserGUIDFn: func(ctx context.Context, guid string) (*entity.RefreshToken, error) {
				return &entity.RefreshToken{
					UserGUID:  guid,
					TokenHash: "$2a$10$abcdefghijklmnopqrstuv",
					UserAgent: "",
					SessionID: "session-1",
					ExpiresAt: time.Now().Add(time.Hour),
				}, nil
			},
		},
		&userRepoMock{},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	if _, err := auth.RefreshTokens(ctx, "refresh-token"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestRefreshTokensRejectsExpiredToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("user_guid", "guid-1")
	ctx.Set("session_id", "session-1")
	ctx.Request = httptest.NewRequest("POST", "/auth/refresh", nil)

	loggedOut := false
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{
			getRefreshTokenByUserGUIDFn: func(ctx context.Context, guid string) (*entity.RefreshToken, error) {
				return &entity.RefreshToken{
					UserGUID:  guid,
					TokenHash: "hash",
					UserAgent: "",
					SessionID: "session-1",
					ExpiresAt: time.Now().Add(-time.Minute),
				}, nil
			},
			deleteTokenByUserGUIDFunc: func(ctx context.Context, guid string) error {
				loggedOut = true
				return nil
			},
		},
		&userRepoMock{},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	if _, err := auth.RefreshTokens(ctx, "refresh-token"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if !loggedOut {
		t.Fatal("expected Logout to be called for expired token")
	}
}

func TestRefreshTokensSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Set("user_guid", "guid-1")
	ctx.Set("session_id", "session-1")
	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "127.0.0.1:12345"
	ctx.Request = req

	tokenPair, err := jwt.NewTokenPair(entity.User{GUID: "guid-1"}, time.Minute, "secret", "session-1")
	if err != nil {
		t.Fatalf("failed to create token pair: %v", err)
	}

	var savedToken *entity.RefreshToken
	auth := NewAuth(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&tokenRepoMock{
			getRefreshTokenByUserGUIDFn: func(ctx context.Context, guid string) (*entity.RefreshToken, error) {
				return &entity.RefreshToken{
					UserGUID:  guid,
					TokenHash: tokenPair.RefreshTokenHash,
					UserAgent: "test-agent",
					SessionID: "session-1",
					ExpiresAt: time.Now().Add(time.Hour),
				}, nil
			},
			saveTokenFunc: func(ctx context.Context, token *entity.RefreshToken) error {
				savedToken = token
				return nil
			},
		},
		&userRepoMock{
			getUserByGUIDFunc: func(ctx context.Context, guid string) (entity.User, error) {
				return entity.User{GUID: guid, Email: "user@example.com"}, nil
			},
		},
		&redisStorageMock{},
		&emailClientMock{},
		"secret",
		time.Minute,
		24*time.Hour,
	)

	refreshedPair, err := auth.RefreshTokens(ctx, tokenPair.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens returned error: %v", err)
	}
	if refreshedPair.AccessToken == "" || refreshedPair.RefreshToken == "" {
		t.Fatal("expected refreshed token pair to be returned")
	}
	if savedToken == nil {
		t.Fatal("expected refreshed token to be saved")
	}
	if savedToken.SessionID != "session-1" {
		t.Fatalf("expected session ID %q, got %q", "session-1", savedToken.SessionID)
	}
}
