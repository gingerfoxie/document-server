package repository

import (
	"context"

	"document-server/internal/model"

	"github.com/google/uuid"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user model.User) error
	GetUserByLogin(ctx context.Context, login string) (model.User, error)
}

type DocumentRepository interface {
	CreateDocument(ctx context.Context, doc model.Document) (model.Document, error)
	GetDocuments(ctx context.Context, ownerID uuid.UUID, limit int, key, value string) ([]model.Document, error)
	GetDocumentByID(ctx context.Context, docID uuid.UUID) (model.Document, error)
	DeleteDocument(ctx context.Context, docID uuid.UUID) error
	AddGrants(ctx context.Context, docID uuid.UUID, logins []string) error
	GetGrants(ctx context.Context, docID uuid.UUID) ([]string, error)
}
