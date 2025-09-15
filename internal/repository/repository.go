package repository

import (
	"context"

	"document-server/internal/model"

	"github.com/google/uuid"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user model.User) error
	GetUserByLogin(ctx context.Context, login string) (model.User, error)
	// GetUserByID(ctx context.Context, id uuid.UUID) (model.User, error) // Может понадобиться
}

type DocumentRepository interface {
	CreateDocument(ctx context.Context, doc model.Document) (model.Document, error)
	GetDocuments(ctx context.Context, ownerID uuid.UUID, limit int, key, value string) ([]model.Document, error)
	GetDocumentByID(ctx context.Context, docID uuid.UUID) (model.Document, error)
	DeleteDocument(ctx context.Context, docID uuid.UUID) error
	AddGrants(ctx context.Context, docID uuid.UUID, logins []string) error
	GetGrants(ctx context.Context, docID uuid.UUID) ([]string, error)
	// GetDocumentWithOwnerCheck // Метод для проверки владельца при удалении/обновлении
}

// Для простоты, кэш будет реализован в сервисе, используя Redis напрямую
// type CacheRepository interface {
//     GetDocumentList(ctx context.Context, key string) ([]byte, error)
//     SetDocumentList(ctx context.Context, key string, data []byte, ttl time.Duration) error
//     GetDocumentItem(ctx context.Context, key string) ([]byte, error)
//     SetDocumentItem(ctx context.Context, key string, data []byte, ttl time.Duration) error
//     InvalidateDocumentList(ctx context.Context, pattern string) error // Для инвалидации при создании/удалении
//     InvalidateDocumentItem(ctx context.Context, key string) error
// }
