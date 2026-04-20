package entity

type PendingUser struct {
	Email    string
	PassHash []byte
	Code     string
}
