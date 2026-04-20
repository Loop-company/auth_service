package storage

import (
	"fmt"
	"log"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/config"
	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

func InitDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		cfg.DB.Host, cfg.DB.User, cfg.DB.Password,
		cfg.DB.Dbname, cfg.DB.Port, cfg.DB.Sslmode)

	var err error

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Could not connect to database: %v", err)
	}

	if err := db.AutoMigrate(&entity.User{}, &entity.RefreshToken{}); err != nil {
		log.Fatalf("Could not migrate table: %v", err)
	}

	return db, nil
}
