package app

import (
	"log/slog"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/cache"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/config"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/email"
	authgrpc "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/grpc"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/handlers"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/httpauth"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/repo"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/routes"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/storage"
	authpb "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/proto"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

type App struct {
	HTTPServer *gin.Engine
	GRPCServer *grpc.Server
}

func NewApp(cfg *config.Config) (*App, error) {
	logger := slog.Default()

	database, err := storage.InitDB(cfg)
	if err != nil {
		return nil, err
	}

	repository := repo.NewRepository(database)
	emailClient := buildEmailClient(cfg, logger)

	redisClient := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddress,
	})
	redisStorage := cache.NewRedisVerificationStorage(redisClient)

	service := services.NewAuth(logger, repository, repository, redisStorage, emailClient, cfg.Secret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	cookieCfg := httpauth.CookieConfig{
		RefreshTTL: cfg.RefreshTokenTTL,
		Secure:     cfg.Env == "prod",
	}
	handler := handlers.NewAuthHandler(service, cookieCfg)

	r := gin.Default()
	auth := r.Group("/auth")
	routes.RegisterRoutes(auth, handler, service)

	grpcServer := grpc.NewServer()
	authServer := authgrpc.NewAuthServer(service)
	authpb.RegisterAuthServiceServer(grpcServer, authServer)

	return &App{
		HTTPServer: r,
		GRPCServer: grpcServer,
	}, nil
}

func buildEmailClient(cfg *config.Config, logger *slog.Logger) services.EmailClient {
	if cfg.SMTP.User == "" || cfg.SMTP.Password == "" || cfg.SMTP.From == "" {
		logger.Warn("SMTP is not configured, verification codes will be logged only")
		return email.NewLoggingClient()
	}

	return email.NewSMTPClient(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.User, cfg.SMTP.Password, cfg.SMTP.From)
}
