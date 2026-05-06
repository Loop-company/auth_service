package httpauth

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	AccessCookieName  = "access_token"
	RefreshCookieName = "refresh_token"
)

type CookieConfig struct {
	RefreshTTL time.Duration
	Secure     bool
}

func SetTokenCookies(c *gin.Context, cfg CookieConfig, accessToken, refreshToken string) {
	maxAge := int(cfg.RefreshTTL.Seconds())
	setCookie(c, AccessCookieName, accessToken, maxAge, cfg.Secure)
	setCookie(c, RefreshCookieName, refreshToken, maxAge, cfg.Secure)
}

func ClearTokenCookies(c *gin.Context, cfg CookieConfig) {
	setCookie(c, AccessCookieName, "", -1, cfg.Secure)
	setCookie(c, RefreshCookieName, "", -1, cfg.Secure)
}

func ExtractAccessToken(c *gin.Context) string {
	if token := ExtractBearerToken(c.GetHeader("Authorization")); token != "" {
		return token
	}

	token, _ := c.Cookie(AccessCookieName)
	return token
}

func ExtractRefreshToken(c *gin.Context) string {
	token, _ := c.Cookie(RefreshCookieName)
	return token
}

func ExtractBearerToken(header string) string {
	if header == "" {
		return ""
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}

	return parts[1]
}

func setCookie(c *gin.Context, name, value string, maxAge int, secure bool) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}
