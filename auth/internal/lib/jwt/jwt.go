package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidToken = errors.New("invalid or expired token")

type CustomClaims struct {
	GUID      string `json:"guid"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	RefreshTokenHash string
}

func NewTokenPair(user entity.User, tokenTTL time.Duration, secret string, sessionID string) (*TokenPair, error) {
	accessToken, err := generateAccessToken(user, sessionID, tokenTTL, secret)
	if err != nil {
		return nil, err
	}

	refreshToken, hash, err := generateSecureRefreshToken()
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshTokenHash: hash,
	}, nil
}

func generateAccessToken(user entity.User, sessionID string, ttl time.Duration, secret string) (string, error) {
	claims := CustomClaims{
		GUID:      user.GUID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
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
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
