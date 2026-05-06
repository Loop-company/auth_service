package main

import (
	"log"
	"net"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/app"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/config"
)

func main() {
	cfg := config.Load()

	a, err := app.NewApp(cfg)
	if err != nil {
		log.Fatalf("failed to init app: %v", err)
	}

	// Start gRPC server
	lis, err := net.Listen("tcp", ":"+cfg.GRPC.Port)
	if err != nil {
		log.Fatalf("failed to listen for gRPC: %v", err)
	}

	go func() {
		log.Printf("Starting gRPC server on :%s", cfg.GRPC.Port)
		if err := a.GRPCServer.Serve(lis); err != nil {
			log.Fatalf("gRPC server error: %v", err)
		}
	}()

	// Start HTTP server
	log.Printf("Starting HTTP server on :%s", cfg.HTTP.Port)
	if err := a.HTTPServer.Run(":" + cfg.HTTP.Port); err != nil {
		log.Fatalf("HTTP server error: %v", err)
	}
}
