package model

import "time"

type User struct {
	ID           int64
	Email        string
	Nickname     string
	PasswordHash string
	CreatedAt    time.Time
}
