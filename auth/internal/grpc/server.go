package grpc

import (
	"context"
	"errors"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	authpb "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	authpb.UnimplementedAuthServiceServer
	auth *services.Auth
}

func NewAuthServer(auth *services.Auth) *AuthServer {
	return &AuthServer{auth: auth}
}

func (s *AuthServer) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	err := s.auth.SendingEmailWithCode(ctx, req.Email, req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authpb.RegisterResponse{
		Message: "If email is valid, a verification code has been sent",
	}, nil
}

func (s *AuthServer) Verify(ctx context.Context, req *authpb.VerifyRequest) (*authpb.VerifyResponse, error) {
	guid, err := s.auth.ConfirmVerificationCode(ctx, req.Email, req.Code)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCode) {
			return nil, status.Error(codes.InvalidArgument, "Invalid or expired verification code")
		}
		if errors.Is(err, services.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "User already exists")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authpb.VerifyResponse{
		Guid: guid,
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	userAgent, ip := extractMetadata(ctx)

	tokenPair, guid, err := s.auth.Login(ctx, req.Email, req.Password, userAgent, ip)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) || errors.Is(err, services.ErrUserNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authpb.LoginResponse{
		Guid:             guid,
		AccessToken:      tokenPair.AccessToken,
		RefreshToken:     tokenPair.RefreshToken,
		AccessExpiresAt:  tokenPair.AccessExpiresAt.Unix(),
		RefreshExpiresAt: tokenPair.RefreshExpiresAt.Unix(),
	}, nil
}

func (s *AuthServer) Refresh(ctx context.Context, req *authpb.RefreshRequest) (*authpb.LoginResponse, error) {
	userAgent, ip := extractMetadata(ctx)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}

	var userGUID, sessionID string
	if guids := md.Get("user_guid"); len(guids) > 0 {
		userGUID = guids[0]
	}
	if sessions := md.Get("session_id"); len(sessions) > 0 {
		sessionID = sessions[0]
	}

	if userGUID == "" || sessionID == "" {
		accessToken := req.AccessToken
		if accessToken == "" {
			if tokens := md.Get("access_token"); len(tokens) > 0 {
				accessToken = tokens[0]
			}
		}

		claims, err := s.auth.ParseTokenAllowExpired(accessToken)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid access token")
		}
		userGUID = claims.GUID
		sessionID = claims.SessionID
	}

	tokenPair, err := s.auth.RefreshTokens(ctx, req.RefreshToken, userGUID, sessionID, userAgent, ip)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &authpb.LoginResponse{
		AccessToken:      tokenPair.AccessToken,
		RefreshToken:     tokenPair.RefreshToken,
		AccessExpiresAt:  tokenPair.AccessExpiresAt.Unix(),
		RefreshExpiresAt: tokenPair.RefreshExpiresAt.Unix(),
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.AuthEmpty, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	var userGUID string
	if guids := md.Get("user_guid"); len(guids) > 0 {
		userGUID = guids[0]
	}

	if userGUID == "" {
		return nil, status.Error(codes.Unauthenticated, "missing user_guid")
	}

	err := s.auth.Logout(ctx, userGUID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authpb.AuthEmpty{}, nil
}

func (s *AuthServer) GetProfileGUID(ctx context.Context, req *authpb.GetProfileGUIDRequest) (*authpb.GetProfileGUIDResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	var userGUID string
	if guids := md.Get("user_guid"); len(guids) > 0 {
		userGUID = guids[0]
	}

	if userGUID == "" {
		return nil, status.Error(codes.Unauthenticated, "missing user_guid")
	}

	return &authpb.GetProfileGUIDResponse{
		Guid: userGUID,
	}, nil
}

func (s *AuthServer) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	claims, err := s.auth.ValidateAccessToken(ctx, req.AccessToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &authpb.ValidateTokenResponse{
		Guid:      claims.GUID,
		SessionId: claims.SessionID,
	}, nil
}

func extractMetadata(ctx context.Context) (userAgent, ip string) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ""
	}

	if ua := md.Get("user-agent"); len(ua) > 0 {
		userAgent = ua[0]
	}
	if ips := md.Get("x-real-ip"); len(ips) > 0 {
		ip = ips[0]
	} else if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
		ip = ips[0]
	}

	return userAgent, ip
}
