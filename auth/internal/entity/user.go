package entity

type User struct {
	GUID     string `gorm:"primaryKey"`
	Email    string `gorm:"uniqueIndex;not null"`
	PassHash []byte
}
