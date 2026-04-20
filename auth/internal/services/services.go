package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/lib/jwt"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/repo"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrAccessDenied       = errors.New("access denied")
	ErrInvalidCode        = errors.New("invalid verification code")
)

type TokenRepository interface {
	SaveToken(ctx context.Context, token *entity.RefreshToken) error
	GetRefreshTokenByUserGUID(ctx context.Context, guid string) (*entity.RefreshToken, error)
	DeleteTokenByUserGUID(ctx context.Context, guid string) error
}

type UserRepository interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (guid string, err error)
	GetUserByEmail(ctx context.Context, email string) (user entity.User, err error)
	GetUserByGUID(ctx context.Context, guid string) (entity.User, error)
	UserExistsByEmail(ctx context.Context, email string) (bool, error)
}

type RedisStorage interface {
	SaveCode(ctx context.Context, data entity.PendingUser, ttl time.Duration) error
	GetCode(ctx context.Context, email string) (entity.PendingUser, error)
	DeleteCode(ctx context.Context, email string) error
}

type EmailClient interface {
	SendVerificationCode(to, code string) error
}

type Auth struct {
	log             *slog.Logger
	tokenRepo       TokenRepository
	userRepo        UserRepository
	redisStorage    RedisStorage
	emailClient     EmailClient
	jwtSecret       string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewAuth(log *slog.Logger,
	tokenRepo TokenRepository,
	userRepo UserRepository,
	redisStorage RedisStorage,
	emailClient EmailClient,
	jwtSecret string,
	accessTokenTTL,
	refreshTokenTTL time.Duration) *Auth {
	return &Auth{
		log:             log,
		tokenRepo:       tokenRepo,
		userRepo:        userRepo,
		redisStorage:    redisStorage,
		emailClient:     emailClient,
		jwtSecret:       jwtSecret,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func generateCode() (string, error) {
	minDigit := int64(100000)
	rangeSize := int64(900000)

	n, err := rand.Int(rand.Reader, big.NewInt(rangeSize))
	if err != nil {
		return "", err
	}

	code := minDigit + n.Int64()
	return fmt.Sprintf("%d", code), nil
}

func (auth *Auth) SendingEmailWithCode(ctx context.Context, email, password string) error {
	const op = "auth.sending_email_with_code"

	log := auth.log.With(slog.String("operation", op))
	log.Info("Sending email with code...")

	exists, err := auth.userRepo.UserExistsByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to check user existence: %w", err)
	}
	if exists {
		return fmt.Errorf("user with email %s already exists", email)
	}

	// хэш пароля + соль
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", "error", err)
		return fmt.Errorf("%s: %w", op, err)
	}

	code, err := generateCode()
	if err != nil {
		log.Error("failed to generate verification code", "error", err)
		return fmt.Errorf("%s: %w", op, err)
	}

	pendingUser := entity.PendingUser{
		Email:    email,
		PassHash: passHash,
		Code:     code,
	}

	err = auth.redisStorage.SaveCode(ctx, pendingUser, 10*time.Minute)
	if err != nil {
		log.Error("failed to save code", "error", err)
		return fmt.Errorf("%s: %w", op, err)
	}

	// ошибку не возвращаем, клиенту нельзя знать
	err = auth.emailClient.SendVerificationCode(pendingUser.Email, code)
	if err != nil {
		auth.log.Warn("failed to send verification code", "error", err)
	}

	return nil
}

func (auth *Auth) ConfirmVerificationCode(ctx context.Context, email, code string) (string, error) {
	const op = "auth.confirm_verification_code"

	log := auth.log.With(slog.String("operation", op))
	log.Info("Confirming verification code...")

	// getcode from redis
	pending, err := auth.redisStorage.GetCode(ctx, email)
	if err != nil {
		log.Warn("verification code not found or storage error", "error", err)
		return "", ErrInvalidCode
	}

	if pending.Code != code {
		log.Warn("invalid verification code provided")
		return "", ErrInvalidCode
	}

	// register new user
	guid, err := auth.userRepo.SaveUser(ctx, pending.Email, pending.PassHash)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			log.Warn("user already exists", "error", err)
			return "", ErrUserExists
		}
		log.Error("failed to save user", "error", err)
		return "", fmt.Errorf("%s: %w", op, err)
	}

	// удаляем данные из redis
	if err := auth.redisStorage.DeleteCode(ctx, email); err != nil {
		log.Warn("failed to delete code", "error", err)
	}

	log.Info("User successfully verified and created", "user_guid", guid)
	return guid, nil
}

func (auth *Auth) Login(ctx *gin.Context, email string, password string) (jwt.TokenPair, string, error) {
	const op = "auth.Login"

	log := auth.log.With(slog.String("op", op), slog.String("email", email))
	log.Info("attempting to login user")

	user, err := auth.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			log.Info("user not found")
			return jwt.TokenPair{}, "", ErrUserNotFound
		}

		log.Error("failed to find user", "error", err)
		return jwt.TokenPair{}, "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", "error", err)
		return jwt.TokenPair{}, "", ErrInvalidCredentials
	}

	log.Info("successfully logged in")

	sessionID := uuid.New().String()

	tokenPair, err := jwt.NewTokenPair(user, auth.accessTokenTTL, auth.jwtSecret, sessionID)
	if err != nil {
		log.Error("failed to generate token pair", "error", err)
		return jwt.TokenPair{}, "", fmt.Errorf("%s: %w", op, err)
	}

	userAgent := ctx.GetHeader("User-Agent")
	ip := ctx.ClientIP()

	refreshToken := entity.RefreshToken{
		UserGUID:  user.GUID,
		TokenHash: tokenPair.RefreshTokenHash,
		UserAgent: userAgent,
		IP:        ip,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(auth.refreshTokenTTL),
		CreatedAt: time.Now(),
	}

	errTokenSave := auth.tokenRepo.SaveToken(ctx, &refreshToken)
	if errTokenSave != nil {
		log.Error("failed to save refresh token", "error", errTokenSave)
		return jwt.TokenPair{}, "", fmt.Errorf("%s: failed to store refresh token: %w", op, errTokenSave)
	}

	return jwt.TokenPair{AccessToken: tokenPair.AccessToken, RefreshToken: tokenPair.RefreshToken, RefreshTokenHash: tokenPair.RefreshTokenHash}, user.GUID, nil
}

func (auth *Auth) GetTokenPairByUserGUID(ctx *gin.Context, guid string) (jwt.TokenPair, error) {
	const op = "auth.GetTokenPairByUserGUID"

	log := auth.log.With(slog.String("op", op), slog.String("guid", guid))
	log.Info("getting token pair by user guid")

	currentUserGUID, err := auth.GetCurrentUserGUID(ctx)
	if err != nil {
		log.Error("failed to get current user GUID", "error", err)
		return jwt.TokenPair{}, fmt.Errorf("%s: %w", op, err)
	}

	if currentUserGUID != guid {
		log.Error("invalid user GUID")
		return jwt.TokenPair{}, ErrAccessDenied
	}

	user, err := auth.userRepo.GetUserByGUID(ctx, guid)
	if err != nil {
		if errors.Is(err, repo.ErrUserNotFound) {
			return jwt.TokenPair{}, ErrUserNotFound
		}
		log.Error("failed to get token pair", "error", err)
		return jwt.TokenPair{}, err
	}

	sessionID := uuid.New().String()

	newTokenPair, err := jwt.NewTokenPair(user, auth.accessTokenTTL, auth.jwtSecret, sessionID)
	if err != nil {
		log.Error("failed to generate token pair", "error", err)
		return jwt.TokenPair{}, fmt.Errorf("%s: %w", op, err)
	}

	userAgent := ctx.GetHeader("User-Agent")
	ip := ctx.ClientIP()

	refreshToken := entity.RefreshToken{
		UserGUID:  user.GUID,
		TokenHash: newTokenPair.RefreshTokenHash,
		UserAgent: userAgent,
		IP:        ip,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(auth.refreshTokenTTL),
		CreatedAt: time.Now(),
	}

	errTokenSave := auth.tokenRepo.SaveToken(ctx, &refreshToken)
	if errTokenSave != nil {
		log.Error("failed to save refresh token", "error", errTokenSave)
		return jwt.TokenPair{}, fmt.Errorf("%s: failed to store refresh token: %w", op, errTokenSave)
	}

	log.Info("successfully retrieved token pair")

	return jwt.TokenPair{AccessToken: newTokenPair.AccessToken, RefreshToken: newTokenPair.RefreshToken, RefreshTokenHash: newTokenPair.RefreshTokenHash}, nil
}

func (auth *Auth) GetCurrentUserGUID(ctx *gin.Context) (string, error) {
	const op = "auth.GetCurrentUserGuid"

	log := auth.log.With(slog.String("op", op))
	log.Info("getting current user guid")

	guid, exists := ctx.Get("user_guid")
	if !exists {
		return "", ErrUserNotFound
	}

	userGUID, ok := guid.(string)
	if !ok {
		return "", ErrInvalidToken
	}

	log.Info("got current user guid")

	return userGUID, nil
}

func (auth *Auth) RefreshTokens(ctx *gin.Context, refreshToken string) (jwt.TokenPair, error) {
	const op = "auth.RefreshTokens"

	log := auth.log.With(slog.String("op", op))
	log.Info("refreshing tokens")

	userGUID, err := auth.GetCurrentUserGUID(ctx)
	if err != nil {
		log.Warn("missing user guid in context")
		return jwt.TokenPair{}, ErrUserNotFound
	}

	savedRefreshToken, err := auth.tokenRepo.GetRefreshTokenByUserGUID(ctx, userGUID)
	if err != nil {
		log.Error("failed to get refresh token from DB", "error", err)
		return jwt.TokenPair{}, ErrInvalidToken
	}

	if time.Now().After(savedRefreshToken.ExpiresAt) {
		log.Warn("refresh token is expired")

		logoutError := auth.Logout(ctx)
		if logoutError != nil {
			log.Error("failed to logout", "error", logoutError)
			return jwt.TokenPair{}, logoutError
		}

		return jwt.TokenPair{}, ErrInvalidToken
	}

	err = jwt.VerifyRefreshToken(refreshToken, savedRefreshToken.TokenHash)
	if err != nil {
		log.Error("failed to verify refresh token", "error", err)

		logoutError := auth.Logout(ctx)
		if logoutError != nil {
			log.Error("failed to logout", "error", logoutError)
			return jwt.TokenPair{}, logoutError
		}

		return jwt.TokenPair{}, ErrInvalidToken
	}

	sessionValue, exists := ctx.Get("session_id")
	if !exists {
		log.Warn("missing session_id in context")
		return jwt.TokenPair{}, ErrInvalidToken
	}

	sessionID, ok := sessionValue.(string)
	if !ok {
		log.Warn("invalid session_id in context")
		return jwt.TokenPair{}, ErrInvalidToken
	}

	if sessionID != savedRefreshToken.SessionID {
		log.Warn("invalid session_id in context")
		return jwt.TokenPair{}, ErrInvalidToken
	}

	incomingUserAgent := ctx.GetHeader("User-Agent")
	if incomingUserAgent != savedRefreshToken.UserAgent {
		log.Warn("user agent does not match")

		logoutError := auth.Logout(ctx)
		if logoutError != nil {
			log.Error("failed to logout", "error", logoutError)
			return jwt.TokenPair{}, logoutError
		}

		return jwt.TokenPair{}, ErrInvalidToken
	}

	incomingIP := ctx.ClientIP()

	user, err := auth.userRepo.GetUserByGUID(ctx, userGUID)
	if err != nil {
		log.Error("failed to get user by GUID", "error", err)
		return jwt.TokenPair{}, ErrUserNotFound
	}

	newTokenPair, err := jwt.NewTokenPair(user, auth.accessTokenTTL, auth.jwtSecret, savedRefreshToken.SessionID)
	if err != nil {
		log.Error("failed to generate token pair", "error", err)
		return jwt.TokenPair{}, err
	}

	newRefreshToken := entity.RefreshToken{
		UserGUID:  user.GUID,
		TokenHash: newTokenPair.RefreshTokenHash,
		UserAgent: incomingUserAgent,
		IP:        incomingIP,
		SessionID: savedRefreshToken.SessionID,
		ExpiresAt: time.Now().Add(auth.refreshTokenTTL),
		CreatedAt: time.Now(),
	}

	if err := auth.tokenRepo.SaveToken(ctx, &newRefreshToken); err != nil {
		log.Error("failed to save refresh token", "error", err)
		return jwt.TokenPair{}, err
	}

	log.Info("successfully refreshed token")

	return jwt.TokenPair{AccessToken: newTokenPair.AccessToken, RefreshToken: newTokenPair.RefreshToken, RefreshTokenHash: newTokenPair.RefreshTokenHash}, nil
}

func (auth *Auth) Logout(ctx *gin.Context) error {
	const op = "auth.Logout"

	log := auth.log.With(slog.String("op", op))

	userGUID, err := auth.GetCurrentUserGUID(ctx)
	if err != nil {
		log.Error("failed to get current user GUID in context", "error", err)
		return ErrUserNotFound
	}

	err = auth.tokenRepo.DeleteTokenByUserGUID(ctx, userGUID)
	if err != nil {
		log.Error("failed to delete token by GUID in context", "error", err)
		return err
	}

	log.Info("successfully logged out")

	return nil
}
