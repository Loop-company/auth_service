package middleware

import (
	"context"
	"net/http"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/httpauth"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/lib/jwt"
	"github.com/gin-gonic/gin"
)

type TokenService interface {
	ValidateAccessToken(ctx context.Context, accessToken string) (*jwt.CustomClaims, error)
}

func AuthMiddleware(tokenValidator any) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Expose-Headers", "X-New-Access-Token, X-New-Refresh-Token")

		accessToken := httpauth.ExtractAccessToken(c)
		if accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing access token"})
			return
		}

		claims, err := validateToken(c.Request.Context(), tokenValidator, accessToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("user_guid", claims.GUID)
		c.Set("session_id", claims.SessionID)
		c.Set("access_token_id", claims.ID)
		c.Set("access_token_raw", accessToken)

		c.Next()
	}
}

func extractTokenFromHeader(header string) string {
	return httpauth.ExtractBearerToken(header)
}

func validateToken(ctx context.Context, tokenValidator any, accessToken string) (*jwt.CustomClaims, error) {
	switch validator := tokenValidator.(type) {
	case string:
		return jwt.ParseToken(accessToken, validator)
	case TokenService:
		return validator.ValidateAccessToken(ctx, accessToken)
	default:
		return nil, jwt.ErrInvalidToken
	}
}
