package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env             string        `yaml:"env" env:"APP_ENV" env-default:"local"`
	AccessTokenTTL  time.Duration `yaml:"access_ttl" env:"ACCESS_TTL"`
	RefreshTokenTTL time.Duration `yaml:"refresh_ttl" env:"REFRESH_TTL"`
	HTTP            HTTPConfig    `yaml:"http"`
	Secret          string        `yaml:"secret" env:"AUTH_SECRET"`
	DB              DBConfig      `yaml:"postgres"`
	SMTP            SMTPConfig    `yaml:"smtp"`
	RedisAddress    string        `yaml:"redis_addr" env:"REDIS_ADDR"`
}

type HTTPConfig struct {
	Port string `yaml:"port" env:"HTTP_PORT"`
}

type DBConfig struct {
	Host     string `yaml:"host" env:"POSTGRES_HOST"`
	Port     string `yaml:"port" env:"POSTGRES_PORT"`
	User     string `yaml:"user" env:"POSTGRES_USER"`
	Password string `yaml:"password" env:"POSTGRES_PASSWORD"`
	Dbname   string `yaml:"dbname" env:"POSTGRES_DB"`
	Sslmode  string `yaml:"sslmode" env:"POSTGRES_SSLMODE"`
}

type SMTPConfig struct {
	Host     string `yaml:"host" env:"SMTP_HOST"`
	Port     int    `yaml:"port" env:"SMTP_PORT"`
	User     string `yaml:"user" env:"SMTP_USER"`
	Password string `yaml:"password" env:"SMTP_PASSWORD"`
	From     string `yaml:"from" env:"SMTP_FROM"`
}

func Load() *Config {
	var config Config
	if err := cleanenv.ReadEnv(&config); err != nil {
		log.Fatalf("cannot read env config: %s", err)
	}
	return &config
}
