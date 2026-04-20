package entity

import "time"

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"`
	UserGUID  string    `gorm:"index;not null"`
	User      User      `gorm:"foreignKey:UserGUID;references:GUID;constraint:OnDelete:CASCADE"`
	TokenHash string    `gorm:"type:text;not null"`
	UserAgent string    `gorm:"not null"`
	IP        string    `gorm:"not null"`
	SessionID string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	CreatedAt time.Time
}
