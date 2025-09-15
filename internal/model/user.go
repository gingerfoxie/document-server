package model

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Login        string    `json:"login" db:"login"`
	PasswordHash string    `json:"-" db:"password_hash"` // Не сериализуем в JSON
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}
