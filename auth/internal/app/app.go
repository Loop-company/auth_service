package app

import (
	"log/slog"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/cache"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/config"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/email"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/handlers"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/repo"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/routes"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func NewApp(cfg *config.Config) (*gin.Engine, error) {
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
	handler := handlers.NewAuthHandler(service)

	r := gin.Default()
	auth := r.Group("/auth")
	routes.RegisterRoutes(auth, handler, cfg.Secret)

	return r, nil
}

func buildEmailClient(cfg *config.Config, logger *slog.Logger) services.EmailClient {
	if cfg.SMTP.User == "" || cfg.SMTP.Password == "" || cfg.SMTP.From == "" {
		logger.Warn("SMTP is not configured, verification codes will be logged only")
		return email.NewLoggingClient()
	}

	return email.NewSMTPClient(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.User, cfg.SMTP.Password, cfg.SMTP.From)
}
