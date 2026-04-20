package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/Egor4iksls4/DiscordEquivalent/backend/auth/internal/entity"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type Repo struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repo {
	return &Repo{db: db}
}

// SaveToken сохраняет refresh-токен, предварительно удаляя старые токены пользователя.
// Использует транзакцию для предотвращения race condition.
func (r *Repo) SaveToken(ctx context.Context, token *entity.RefreshToken) error {
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return tx.Error
	}

	// Удаляем все существующие токены пользователя
	if err := tx.Where("user_guid = ?", token.UserGUID).Delete(&entity.RefreshToken{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Create(token).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// GetRefreshTokenByUserGUID возвращает **актуальный** refresh-токен пользователя.
// Предполагается, что у пользователя только один активный токен (благодаря SaveToken).
func (r *Repo) GetRefreshTokenByUserGUID(ctx context.Context, guid string) (*entity.RefreshToken, error) {
	var token entity.RefreshToken
	err := r.db.WithContext(ctx).Where("user_guid = ?", guid).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &token, nil
}

// DeleteTokenByUserGUID удаляет все refresh-токены пользователя.
func (r *Repo) DeleteTokenByUserGUID(ctx context.Context, guid string) error {
	return r.db.WithContext(ctx).Where("user_guid = ?", guid).Delete(&entity.RefreshToken{}).Error
}

// SaveUser создаёт нового пользователя.
// Возвращает ErrUserAlreadyExists, если email уже занят.
func (r *Repo) SaveUser(ctx context.Context, email string, passHash []byte) (string, error) {
	user := &entity.User{
		GUID:     uuid.NewString(),
		Email:    email,
		PassHash: passHash,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // unique
			return "", ErrUserAlreadyExists
		}
		return "", err
	}

	return user.GUID, nil
}

// GetUserByEmail ищет пользователя по email.
func (r *Repo) GetUserByEmail(ctx context.Context, email string) (entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return entity.User{}, ErrUserNotFound
		}
		return entity.User{}, err
	}
	return user, nil
}

// GetUserByGUID ищет пользователя по GUID.
func (r *Repo) GetUserByGUID(ctx context.Context, guid string) (entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).Where("guid = ?", guid).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return entity.User{}, ErrUserNotFound
		}
		return entity.User{}, err
	}
	return user, nil
}

func (r *Repo) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	fmt.Printf("=== DEBUG UserExistsByEmail: checking email: %s ===\n", email)

	var count int64
	err := r.db.WithContext(ctx).Model(&entity.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		fmt.Printf("=== DEBUG UserExistsByEmail: ERROR: %v ===\n", err)
		return false, err
	}

	fmt.Printf("=== DEBUG UserExistsByEmail: count for %s: %d ===\n", email, count)
	return count > 0, nil
}
