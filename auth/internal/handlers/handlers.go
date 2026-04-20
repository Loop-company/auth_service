package handlers

import (
	"errors"
	"net/http"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	auth *services.Auth
}

func NewAuthHandler(auth *services.Auth) *AuthHandler {
	return &AuthHandler{auth: auth}
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

	tokenPair, guid, err := h.auth.Login(ctx, req.Email, req.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"guid": guid, "access_token": tokenPair.AccessToken, "refresh_token": tokenPair.RefreshToken})
}

func (h *AuthHandler) Logout(ctx *gin.Context) {
	err := h.auth.Logout(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func (h *AuthHandler) GetCurrentUserGUID(ctx *gin.Context) {
	guid, err := h.auth.GetCurrentUserGUID(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
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

	tokenPair, err := h.auth.GetTokenPairByUserGUID(ctx, req.GUID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"access_token": tokenPair.AccessToken, "refresh_token": tokenPair.RefreshToken})
}

func (h *AuthHandler) RefreshTokens(ctx *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tokenPair, err := h.auth.RefreshTokens(ctx, req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"access_token": tokenPair.AccessToken, "refresh_token": tokenPair.RefreshToken})
}
