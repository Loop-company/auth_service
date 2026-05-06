package app

import (
	"log/slog"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/cache"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/config"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/email"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/eventbus"
	authgrpc "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/grpc"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/repo"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/services"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/storage"
	authpb "github.com/Egor4iksls4/DiscordEquivalent/backend/auth/proto"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
)

type App struct {
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

	kafkaProducer := eventbus.NewKafkaProducer(cfg.Kafka.Brokers, logger)

	service := services.NewAuth(logger, repository, repository, redisStorage, emailClient, kafkaProducer, cfg.Secret, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	grpcServer := grpc.NewServer()
	authServer := authgrpc.NewAuthServer(service)
	authpb.RegisterAuthServiceServer(grpcServer, authServer)

	return &App{
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
