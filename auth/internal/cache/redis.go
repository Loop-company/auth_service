package cache

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"github.com/redis/go-redis/v9"
)

var ErrCodeNotFound = errors.New("Code not found!")

type RedisVerificationStorage struct {
	client *redis.Client
}

func NewRedisVerificationStorage(client *redis.Client) *RedisVerificationStorage {
	return &RedisVerificationStorage{client: client}
}

func (r *RedisVerificationStorage) SaveCode(ctx context.Context, data entity.PendingUser, ttl time.Duration) error {
	if data.Email == "" {
		return errors.New("email is required")
	}

	if ttl <= 0 {
		return errors.New("ttl must be positive")
	}

	userData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	key := "verify:email:" + data.Email

	err = r.client.Set(ctx, key, userData, ttl).Err()
	if err != nil {
		return err
	}

	return nil
}

func (r *RedisVerificationStorage) GetCode(ctx context.Context, email string) (entity.PendingUser, error) {
	var pending entity.PendingUser
	key := "verify:email:" + email

	result, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return pending, ErrCodeNotFound
		}

		return pending, err
	}

	err = json.Unmarshal([]byte(result), &pending)
	return pending, err
}

func (r *RedisVerificationStorage) DeleteCode(ctx context.Context, email string) error {
	key := "verify:email:" + email
	return r.client.Del(ctx, key).Err()
}
