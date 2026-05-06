package handlers

import (
	"errors"
	"net/http"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/httpauth"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	auth         *services.Auth
	cookieConfig httpauth.CookieConfig
}

func NewAuthHandler(auth *services.Auth, cookieConfig ...httpauth.CookieConfig) *AuthHandler {
	cfg := httpauth.CookieConfig{}
	if len(cookieConfig) > 0 {
		cfg = cookieConfig[0]
	}
	return &AuthHandler{auth: auth, cookieConfig: cfg}
}

func (h *AuthHandler) SendEmailWithCode(ctx *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	err := h.auth.SendingEmailWithCode(ctx, req.Email, req.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusAccepted, gin.H{
		"message": "If email is valid, a verification code has been sent",
	})
}

func (h *AuthHandler) VerifyEmail(ctx *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		Code  string `json:"code" binding:"required,len=6"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	guid, err := h.auth.ConfirmVerificationCode(ctx, req.Email, req.Code)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCode) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired verification code"})
		} else if errors.Is(err, services.ErrUserExists) {
			ctx.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"guid": guid})
}

func (h *AuthHandler) Login(ctx *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userAgent := ctx.GetHeader("User-Agent")
	ip := ctx.ClientIP()

	tokenPair, guid, err := h.auth.Login(ctx, req.Email, req.Password, userAgent, ip)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCredentials), errors.Is(err, services.ErrUserNotFound):
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authorize user"})
		}
		return
	}

	httpauth.SetTokenCookies(ctx, h.cookieConfig, tokenPair.AccessToken, tokenPair.RefreshToken)
	ctx.JSON(http.StatusOK, gin.H{
		"guid":               guid,
		"access_token":       tokenPair.AccessToken,
		"refresh_token":      tokenPair.RefreshToken,
		"access_expires_at":  tokenPair.AccessExpiresAt,
		"refresh_expires_at": tokenPair.RefreshExpiresAt,
	})
}

func (h *AuthHandler) Logout(ctx *gin.Context) {
	userGUID, exists := ctx.Get("user_guid")
	if !exists {
		accessToken := httpauth.ExtractAccessToken(ctx)
		claims, err := h.auth.ValidateAccessToken(ctx, accessToken)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		userGUID = claims.GUID
	}

	err := h.auth.Logout(ctx, userGUID.(string))
	httpauth.ClearTokenCookies(ctx, h.cookieConfig)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func (h *AuthHandler) GetCurrentUserGUID(ctx *gin.Context) {
	guid, exists := ctx.Get("user_guid")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"guid": guid})
}

func (h *AuthHandler) GetTokenPairByUserGUID(ctx *gin.Context) {
	var req struct {
		GUID string `json:"guid" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	currentUserGUID, exists := ctx.Get("user_guid")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userAgent := ctx.GetHeader("User-Agent")
	ip := ctx.ClientIP()

	tokenPair, err := h.auth.GetTokenPairByUserGUID(ctx, req.GUID, currentUserGUID.(string), userAgent, ip)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	httpauth.SetTokenCookies(ctx, h.cookieConfig, tokenPair.AccessToken, tokenPair.RefreshToken)
	ctx.JSON(http.StatusOK, gin.H{
		"access_token":       tokenPair.AccessToken,
		"refresh_token":      tokenPair.RefreshToken,
		"access_expires_at":  tokenPair.AccessExpiresAt,
		"refresh_expires_at": tokenPair.RefreshExpiresAt,
	})
}

func (h *AuthHandler) RefreshTokens(ctx *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	userGUID, exists := ctx.Get("user_guid")
	sessionID, sExists := ctx.Get("session_id")

	if !exists || !sExists {
		accessToken := httpauth.ExtractAccessToken(ctx)
		claims, err := h.auth.ParseTokenAllowExpired(accessToken)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access token"})
			return
		}
		userGUID = claims.GUID
		sessionID = claims.SessionID
	}

	userAgent := ctx.GetHeader("User-Agent")
	ip := ctx.ClientIP()

	tokenPair, err := h.auth.RefreshTokens(ctx, req.RefreshToken, userGUID.(string), sessionID.(string), userAgent, ip)
	if err != nil {
		httpauth.ClearTokenCookies(ctx, h.cookieConfig)
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	httpauth.SetTokenCookies(ctx, h.cookieConfig, tokenPair.AccessToken, tokenPair.RefreshToken)
	ctx.JSON(http.StatusOK, gin.H{
		"access_token":       tokenPair.AccessToken,
		"refresh_token":      tokenPair.RefreshToken,
		"access_expires_at":  tokenPair.AccessExpiresAt,
		"refresh_expires_at": tokenPair.RefreshExpiresAt,
	})
}
