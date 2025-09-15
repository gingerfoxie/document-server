package model

import (
	"time"

	"github.com/google/uuid"
)

type Document struct {
	ID        uuid.UUID `json:"id" db:"id"`
	OwnerID   uuid.UUID `json:"owner_id" db:"owner_id"`
	Name      string    `json:"name" db:"name"`
	MimeType  string    `json:"mime" db:"mime_type"`
	IsFile    bool      `json:"file" db:"is_file"`
	IsPublic  bool      `json:"public" db:"is_public"`
	JSONData  *string   `json:"json,omitempty" db:"json_data"` // Указатель для возможности NULL
	FilePath  *string   `json:"-" db:"file_path"`              // Не сериализуем путь в JSON ответ
	CreatedAt time.Time `json:"created" db:"created_at"`
	Grant     []string  `json:"grant" db:"-"` // Заполняется отдельно
}

// Для входящих данных при создании
type CreateDocumentRequest struct {
	Name     string   `json:"name"`
	IsFile   bool     `json:"file"`
	IsPublic bool     `json:"public"`
	Token    string   `json:"token"`
	Mime     string   `json:"mime"`
	Grant    []string `json:"grant"`
	// JSONData будет передаваться отдельно как часть multipart/form-data
	// File будет передаваться отдельно как часть multipart/form-data
}

// Для ответа на GET /api/docs/<id> если это JSON
type GetDocumentJSONResponse struct {
	Data interface{} `json:"data"` // JSON данные
}

// Для ответа на GET /api/docs/<id> если это файл
// Файл отдаётся напрямую, без обёртки

// Для ответа на DELETE /api/docs/<id>
type DeleteDocumentResponse struct {
	Response map[string]bool `json:"response"`
}
