package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("expired token")
)

type CustomClaims struct {
	GUID      string `json:"guid"`
	SessionID string `json:"session_id"`
	Type      string `json:"type"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	RefreshTokenHash string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

func NewTokenPair(user entity.User, tokenTTL time.Duration, secret string, sessionID string) (*TokenPair, error) {
	return NewTokenPairWithRefreshTTL(user, tokenTTL, 0, secret, sessionID)
}

func NewTokenPairWithRefreshTTL(user entity.User, accessTTL, refreshTTL time.Duration, secret string, sessionID string) (*TokenPair, error) {
	now := time.Now()
	accessExpiresAt := now.Add(accessTTL)

	accessToken, err := generateAccessToken(user, sessionID, accessExpiresAt, secret, now)
	if err != nil {
		return nil, err
	}

	refreshToken, hash, err := generateSecureRefreshToken()
	if err != nil {
		return nil, err
	}

	tokenPair := &TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshTokenHash: hash,
		AccessExpiresAt:  accessExpiresAt,
	}
	if refreshTTL > 0 {
		tokenPair.RefreshExpiresAt = now.Add(refreshTTL)
	}

	return tokenPair, nil
}

func generateAccessToken(user entity.User, sessionID string, expiresAt time.Time, secret string, issuedAt time.Time) (string, error) {
	claims := CustomClaims{
		GUID:      user.GUID,
		SessionID: sessionID,
		Type:      "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   user.GUID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(secret))
}

func generateSecureRefreshToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}

	token := base64.StdEncoding.EncodeToString(raw)

	hashed, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return token, string(hashed), nil
}

// сравнение приходящего токена с хешем из базы, при этом защищает от подделки
func VerifyRefreshToken(token string, hashed string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(token))
}

func ParseToken(tokenStr string, secret string) (*CustomClaims, error) {
	return parseToken(tokenStr, secret, false)
}

func ParseTokenAllowExpired(tokenStr string, secret string) (*CustomClaims, error) {
	return parseToken(tokenStr, secret, true)
}

func parseToken(tokenStr string, secret string, allowExpired bool) (*CustomClaims, error) {
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}),
	}
	if allowExpired {
		parserOptions = append(parserOptions, jwt.WithoutClaimsValidation())
	}

	token, err := jwt.NewParser(parserOptions...).ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Type != "access" || claims.GUID == "" || claims.SessionID == "" || claims.ID == "" || claims.ExpiresAt == nil {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
