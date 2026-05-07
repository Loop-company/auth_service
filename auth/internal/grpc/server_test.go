package grpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	authjwt "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/lib/jwt"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	authpb "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/proto"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const testSecret = "test-secret"

type tokenRepoMock struct {
	saveFunc   func(context.Context, *entity.RefreshToken) error
	getFunc    func(context.Context, string) (*entity.RefreshToken, error)
	deleteFunc func(context.Context, string) error
}

func (m tokenRepoMock) SaveToken(ctx context.Context, token *entity.RefreshToken) error {
	if m.saveFunc != nil {
		return m.saveFunc(ctx, token)
	}
	return nil
}

func (m tokenRepoMock) GetRefreshTokenByUserGUID(ctx context.Context, guid string) (*entity.RefreshToken, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, guid)
	}
	return nil, errors.New("not found")
}

func (m tokenRepoMock) DeleteTokenByUserGUID(ctx context.Context, guid string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, guid)
	}
	return nil
}

type userRepoMock struct {
	saveUserFunc      func(context.Context, string, []byte) (string, error)
	getByEmailFunc    func(context.Context, string) (entity.User, error)
	getByGUIDFunc     func(context.Context, string) (entity.User, error)
	userExistsByEmail func(context.Context, string) (bool, error)
}

func (m userRepoMock) SaveUser(ctx context.Context, email string, passHash []byte) (string, error) {
	if m.saveUserFunc != nil {
		return m.saveUserFunc(ctx, email, passHash)
	}
	return "guid-1", nil
}

func (m userRepoMock) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	if m.getByEmailFunc != nil {
		return m.getByEmailFunc(ctx, email)
	}
	return entity.User{}, services.ErrUserNotFound
}

func (m userRepoMock) GetUserByGUID(ctx context.Context, guid string) (entity.User, error) {
	if m.getByGUIDFunc != nil {
		return m.getByGUIDFunc(ctx, guid)
	}
	return entity.User{}, services.ErrUserNotFound
}

func (m userRepoMock) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	if m.userExistsByEmail != nil {
		return m.userExistsByEmail(ctx, email)
	}
	return false, nil
}

type redisStorageMock struct {
	saveFunc   func(context.Context, entity.PendingUser, time.Duration) error
	getFunc    func(context.Context, string) (entity.PendingUser, error)
	deleteFunc func(context.Context, string) error
}

func (m redisStorageMock) SaveCode(ctx context.Context, data entity.PendingUser, ttl time.Duration) error {
	if m.saveFunc != nil {
		return m.saveFunc(ctx, data, ttl)
	}
	return nil
}

func (m redisStorageMock) GetCode(ctx context.Context, email string) (entity.PendingUser, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, email)
	}
	return entity.PendingUser{}, errors.New("missing")
}

func (m redisStorageMock) DeleteCode(ctx context.Context, email string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, email)
	}
	return nil
}

type emailClientMock struct {
	sendFunc func(string, string) error
}

func (m emailClientMock) SendVerificationCode(to, code string) error {
	if m.sendFunc != nil {
		return m.sendFunc(to, code)
	}
	return nil
}

type eventBusMock struct {
	registered func(context.Context, string, string)
	loggedIn   func(context.Context, string, string)
}

func (m eventBusMock) SendUserRegistered(ctx context.Context, userID, email string) {
	if m.registered != nil {
		m.registered(ctx, userID, email)
	}
}

func (m eventBusMock) SendUserLoggedIn(ctx context.Context, userID, email string) {
	if m.loggedIn != nil {
		m.loggedIn(ctx, userID, email)
	}
}

func newTestServer(
	tokenRepo services.TokenRepository,
	userRepo services.UserRepository,
	redisStorage services.RedisStorage,
	emailClient services.EmailClient,
	eventBus services.EventBus,
) *AuthServer {
	if tokenRepo == nil {
		tokenRepo = tokenRepoMock{}
	}
	if userRepo == nil {
		userRepo = userRepoMock{}
	}
	if redisStorage == nil {
		redisStorage = redisStorageMock{}
	}
	if emailClient == nil {
		emailClient = emailClientMock{}
	}
	if eventBus == nil {
		eventBus = eventBusMock{}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth := services.NewAuth(logger, tokenRepo, userRepo, redisStorage, emailClient, eventBus, testSecret, time.Hour, 24*time.Hour)
	return NewAuthServer(auth)
}

func hashPassword(t *testing.T, password string) []byte {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return hash
}

func TestRegisterSendsVerificationCode(t *testing.T) {
	var savedCode, sentCode string
	server := newTestServer(nil, userRepoMock{}, redisStorageMock{
		saveFunc: func(_ context.Context, data entity.PendingUser, ttl time.Duration) error {
			savedCode = data.Code
			if data.Email != "user@example.com" {
				t.Fatalf("saved email = %q", data.Email)
			}
			if len(data.PassHash) == 0 {
				t.Fatal("password hash was not saved")
			}
			if ttl != 10*time.Minute {
				t.Fatalf("ttl = %v", ttl)
			}
			return nil
		},
	}, emailClientMock{
		sendFunc: func(to string, code string) error {
			if to != "user@example.com" {
				t.Fatalf("email to = %q", to)
			}
			sentCode = code
			return nil
		},
	}, nil)

	resp, err := server.Register(context.Background(), &authpb.RegisterRequest{
		Email:    "user@example.com",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if resp.GetMessage() == "" {
		t.Fatal("Register response message is empty")
	}
	if savedCode == "" || savedCode != sentCode {
		t.Fatalf("saved code %q, sent code %q", savedCode, sentCode)
	}
}

func TestRegisterReturnsInternalWhenUserExists(t *testing.T) {
	server := newTestServer(nil, userRepoMock{
		userExistsByEmail: func(context.Context, string) (bool, error) {
			return true, nil
		},
	}, nil, nil, nil)

	_, err := server.Register(context.Background(), &authpb.RegisterRequest{
		Email:    "taken@example.com",
		Password: "password",
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Internal)
	}
}

func TestVerifyMapsServiceResults(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var deletedEmail, eventUserID string
		server := newTestServer(nil, userRepoMock{}, redisStorageMock{
			getFunc: func(context.Context, string) (entity.PendingUser, error) {
				return entity.PendingUser{Email: "user@example.com", Code: "123456", PassHash: []byte("hash")}, nil
			},
			deleteFunc: func(_ context.Context, email string) error {
				deletedEmail = email
				return nil
			},
		}, nil, eventBusMock{
			registered: func(_ context.Context, userID, _ string) {
				eventUserID = userID
			},
		})

		resp, err := server.Verify(context.Background(), &authpb.VerifyRequest{
			Email: "user@example.com",
			Code:  "123456",
		})
		if err != nil {
			t.Fatalf("Verify returned error: %v", err)
		}
		if resp.GetGuid() != "guid-1" || deletedEmail != "user@example.com" || eventUserID != "guid-1" {
			t.Fatalf("unexpected verify side effects: guid=%q deleted=%q event=%q", resp.GetGuid(), deletedEmail, eventUserID)
		}
	})

	t.Run("invalid code", func(t *testing.T) {
		server := newTestServer(nil, nil, redisStorageMock{
			getFunc: func(context.Context, string) (entity.PendingUser, error) {
				return entity.PendingUser{}, errors.New("missing")
			},
		}, nil, nil)

		_, err := server.Verify(context.Background(), &authpb.VerifyRequest{Email: "user@example.com", Code: "bad"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.InvalidArgument)
		}
	})

	t.Run("user exists", func(t *testing.T) {
		server := newTestServer(nil, userRepoMock{
			saveUserFunc: func(context.Context, string, []byte) (string, error) {
				return "", services.ErrUserExists
			},
		}, redisStorageMock{
			getFunc: func(context.Context, string) (entity.PendingUser, error) {
				return entity.PendingUser{Email: "user@example.com", Code: "123456"}, nil
			},
		}, nil, nil)

		_, err := server.Verify(context.Background(), &authpb.VerifyRequest{Email: "user@example.com", Code: "123456"})
		if status.Code(err) != codes.AlreadyExists {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.AlreadyExists)
		}
	})
}

func TestLoginUsesMetadataAndMapsCredentialErrors(t *testing.T) {
	user := entity.User{GUID: "guid-1", Email: "user@example.com", PassHash: hashPassword(t, "password")}
	var savedToken *entity.RefreshToken
	var eventUserID string
	server := newTestServer(tokenRepoMock{
		saveFunc: func(_ context.Context, token *entity.RefreshToken) error {
			saved := *token
			savedToken = &saved
			return nil
		},
	}, userRepoMock{
		getByEmailFunc: func(context.Context, string) (entity.User, error) {
			return user, nil
		},
	}, nil, nil, eventBusMock{
		loggedIn: func(_ context.Context, userID, _ string) {
			eventUserID = userID
		},
	})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("user-agent", "desktop", "x-real-ip", "10.0.0.10"))

	resp, err := server.Login(ctx, &authpb.LoginRequest{Email: user.Email, Password: "password"})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if resp.GetGuid() != user.GUID || resp.GetAccessToken() == "" || resp.GetRefreshToken() == "" {
		t.Fatalf("unexpected login response: %+v", resp)
	}
	if savedToken == nil || savedToken.UserAgent != "desktop" || savedToken.IP != "10.0.0.10" {
		t.Fatalf("saved token = %+v", savedToken)
	}
	if eventUserID != user.GUID {
		t.Fatalf("login event user = %q", eventUserID)
	}

	_, err = server.Login(ctx, &authpb.LoginRequest{Email: user.Email, Password: "wrong"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}

func TestRefreshUsesAccessTokenFallbackAndMetadata(t *testing.T) {
	const sessionID = "session-1"
	user := entity.User{GUID: "guid-1", Email: "user@example.com", PassHash: hashPassword(t, "password")}
	initialPair, err := authjwt.NewTokenPairWithRefreshTTL(user, time.Hour, 24*time.Hour, testSecret, sessionID)
	if err != nil {
		t.Fatalf("create token pair: %v", err)
	}

	var savedToken *entity.RefreshToken
	server := newTestServer(tokenRepoMock{
		getFunc: func(_ context.Context, guid string) (*entity.RefreshToken, error) {
			if guid != user.GUID {
				t.Fatalf("guid = %q", guid)
			}
			return &entity.RefreshToken{
				UserGUID:  user.GUID,
				TokenHash: initialPair.RefreshTokenHash,
				UserAgent: "desktop",
				IP:        "10.0.0.1",
				SessionID: sessionID,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		saveFunc: func(_ context.Context, token *entity.RefreshToken) error {
			saved := *token
			savedToken = &saved
			return nil
		},
	}, userRepoMock{
		getByGUIDFunc: func(_ context.Context, guid string) (entity.User, error) {
			if guid != user.GUID {
				t.Fatalf("guid = %q", guid)
			}
			return user, nil
		},
	}, nil, nil, nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("user-agent", "desktop", "x-forwarded-for", "10.0.0.20"))

	resp, err := server.Refresh(ctx, &authpb.RefreshRequest{
		RefreshToken: initialPair.RefreshToken,
		AccessToken:  initialPair.AccessToken,
	})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	if resp.GetAccessToken() == "" || resp.GetRefreshToken() == "" {
		t.Fatalf("unexpected refresh response: %+v", resp)
	}
	if savedToken == nil || savedToken.IP != "10.0.0.20" || savedToken.SessionID != sessionID {
		t.Fatalf("saved token = %+v", savedToken)
	}
}

func TestRefreshRejectsMissingAccessContext(t *testing.T) {
	server := newTestServer(nil, nil, nil, nil, nil)

	_, err := server.Refresh(context.Background(), &authpb.RefreshRequest{RefreshToken: "refresh"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}

func TestLogoutAndGetProfileGUIDRequireUserMetadata(t *testing.T) {
	server := newTestServer(tokenRepoMock{
		deleteFunc: func(_ context.Context, guid string) error {
			if guid != "guid-1" {
				t.Fatalf("deleted guid = %q", guid)
			}
			return nil
		},
	}, nil, nil, nil, nil)

	_, err := server.Logout(context.Background(), &authpb.LogoutRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("logout without metadata code = %v", status.Code(err))
	}

	emptyMD := metadata.NewIncomingContext(context.Background(), metadata.Pairs("user-agent", "desktop"))
	_, err = server.GetProfileGUID(emptyMD, &authpb.GetProfileGUIDRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("profile without guid code = %v", status.Code(err))
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("user_guid", "guid-1"))
	if _, err := server.Logout(ctx, &authpb.LogoutRequest{}); err != nil {
		t.Fatalf("Logout returned error: %v", err)
	}

	resp, err := server.GetProfileGUID(ctx, &authpb.GetProfileGUIDRequest{})
	if err != nil {
		t.Fatalf("GetProfileGUID returned error: %v", err)
	}
	if resp.GetGuid() != "guid-1" {
		t.Fatalf("guid = %q", resp.GetGuid())
	}
}

func TestValidateToken(t *testing.T) {
	user := entity.User{GUID: "guid-1", Email: "user@example.com"}
	tokenPair, err := authjwt.NewTokenPairWithRefreshTTL(user, time.Hour, time.Hour, testSecret, "session-1")
	if err != nil {
		t.Fatalf("create token pair: %v", err)
	}
	server := newTestServer(nil, nil, nil, nil, nil)

	resp, err := server.ValidateToken(context.Background(), &authpb.ValidateTokenRequest{AccessToken: tokenPair.AccessToken})
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
	if resp.GetGuid() != user.GUID || resp.GetSessionId() != "session-1" {
		t.Fatalf("unexpected claims response: %+v", resp)
	}

	_, err = server.ValidateToken(context.Background(), &authpb.ValidateTokenRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}

func TestExtractMetadata(t *testing.T) {
	userAgent, ip := extractMetadata(context.Background())
	if userAgent != "" || ip != "" {
		t.Fatalf("empty metadata got userAgent=%q ip=%q", userAgent, ip)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("user-agent", "desktop", "x-forwarded-for", "10.0.0.20"))
	userAgent, ip = extractMetadata(ctx)
	if userAgent != "desktop" || ip != "10.0.0.20" {
		t.Fatalf("metadata got userAgent=%q ip=%q", userAgent, ip)
	}
}
