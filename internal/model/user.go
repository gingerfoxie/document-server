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

// RegisterRequest represents the request body for /api/register
// swagger:model RegisterRequest
type RegisterRequest struct {
	// Admin token required for registration
	// required: true
	Token string `json:"token"`
	// User login (min 8 chars, latin letters and digits)
	// required: true
	// minLength: 8
	// pattern: ^[a-zA-Z0-9]+$
	Login string `json:"login"`
	// User password (min 8 chars, 2 letters different case, 1 digit, 1 special char)
	// required: true
	// minLength: 8
	Password string `json:"pswd"` // Используем Password вместо Pswd для соответствия аннотации
}

// AuthRequest represents the request body for /api/auth
// swagger:model AuthRequest
type AuthRequest struct {
	// User login
	// required: true
	Login string `json:"login"`
	// User password
	// required: true
	Password string `json:"pswd"` // Используем Password вместо Pswd для соответствия аннотации
}

// AuthResponse represents the response body for /api/auth
// swagger:model AuthResponse
type AuthResponse struct {
	// JWT token
	Token string `json:"token"`
}
