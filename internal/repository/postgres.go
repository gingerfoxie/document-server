package repository

import (
	"context"
	"fmt"

	"document-server/internal/model"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	db *pgxpool.Pool
}

func NewPostgres(db *pgxpool.Pool) *Postgres {
	return &Postgres{db: db}
}

// --- User Repository ---

func (p *Postgres) CreateUser(ctx context.Context, user model.User) error {
	query := `INSERT INTO users (id, login, password_hash, created_at) VALUES ($1, $2, $3, $4)`
	_, err := p.db.Exec(ctx, query, user.ID, user.Login, user.PasswordHash, user.CreatedAt)
	return err
}

func (p *Postgres) GetUserByLogin(ctx context.Context, login string) (model.User, error) {
	var user model.User
	query := `SELECT id, login, password_hash, created_at FROM users WHERE login = $1`
	err := p.db.QueryRow(ctx, query, login).Scan(&user.ID, &user.Login, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		return user, err
	}
	return user, nil
}

// --- Document Repository ---

func (p *Postgres) CreateDocument(ctx context.Context, doc model.Document) (model.Document, error) {
	// Начинаем транзакцию
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return doc, err
	}
	defer tx.Rollback(ctx) // Откат при любой ошибке после этой строки

	query := `INSERT INTO documents (id, owner_id, name, mime_type, is_file, is_public, json_data, file_path, created_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`
	var docID uuid.UUID
	err = tx.QueryRow(ctx, query, doc.ID, doc.OwnerID, doc.Name, doc.MimeType, doc.IsFile, doc.IsPublic, doc.JSONData, doc.FilePath, doc.CreatedAt).Scan(&docID)
	if err != nil {
		return doc, err
	}

	// Добавляем гранты, если они есть
	if len(doc.Grant) > 0 {
		grantQuery := `INSERT INTO document_grants (document_id, user_login) VALUES ($1, $2)`
		batch := &pgx.Batch{}
		for _, login := range doc.Grant {
			batch.Queue(grantQuery, docID, login)
		}
		br := tx.SendBatch(ctx, batch)
		// Исполняем все команды в батче
		for i := 0; i < len(doc.Grant); i++ {
			_, err := br.Exec()
			if err != nil {
				// Сохраняем ошибку, но продолжаем закрывать батч
				execErr := err
				br.Close() // Закрываем батч
				return doc, fmt.Errorf("failed to add grant: %w", execErr)
			}
		}
		// Закрываем батч после всех операций
		if err := br.Close(); err != nil {
			return doc, fmt.Errorf("failed to close batch: %w", err)
		}
	}

	// Коммитим транзакцию
	err = tx.Commit(ctx)
	if err != nil {
		return doc, err
	}

	// Перезагружаем документ с ID
	doc.ID = docID
	return doc, nil
}

func (p *Postgres) GetDocuments(ctx context.Context, ownerID uuid.UUID, limit int, key, value string) ([]model.Document, error) {
	var docs []model.Document

	// Базовый запрос
	baseQuery := `
		SELECT d.id, d.owner_id, d.name, d.mime_type, d.is_file, d.is_public, d.json_data, d.file_path, d.created_at
		FROM documents d
		WHERE d.owner_id = $1 OR d.is_public = TRUE
	`

	// Добавляем фильтрацию
	args := []interface{}{ownerID}
	argCount := 2
	filterQuery := ""
	if key != "" && value != "" {
		// Предполагаем, что key это имя колонки. В реальном приложении нужно валидировать.
		// Для простоты фильтруем по имени.
		if key == "name" {
			filterQuery = fmt.Sprintf(" AND d.name ILIKE $%d", argCount)
			args = append(args, "%"+value+"%")
			argCount++
		}
		// Можно добавить фильтрацию по другим полям
	}

	// Добавляем сортировку и лимит
	orderLimitQuery := fmt.Sprintf(" ORDER BY d.name ASC, d.created_at DESC LIMIT $%d", argCount)
	args = append(args, limit)

	fullQuery := baseQuery + filterQuery + orderLimitQuery

	rows, err := p.db.Query(ctx, fullQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var doc model.Document
		err := rows.Scan(&doc.ID, &doc.OwnerID, &doc.Name, &doc.MimeType, &doc.IsFile, &doc.IsPublic, &doc.JSONData, &doc.FilePath, &doc.CreatedAt)
		if err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}

	// Загружаем гранты для каждого документа
	for i := range docs {
		grants, err := p.GetGrants(ctx, docs[i].ID)
		if err != nil {
			// Логируем ошибку, но не прерываем выполнение
			fmt.Printf("Error getting grants for doc %s: %v\n", docs[i].ID, err)
		}
		docs[i].Grant = grants
	}

	return docs, rows.Err()
}

func (p *Postgres) GetDocumentByID(ctx context.Context, docID uuid.UUID) (model.Document, error) {
	var doc model.Document
	query := `SELECT d.id, d.owner_id, d.name, d.mime_type, d.is_file, d.is_public, d.json_data, d.file_path, d.created_at
	          FROM documents d WHERE d.id = $1`
	err := p.db.QueryRow(ctx, query, docID).Scan(&doc.ID, &doc.OwnerID, &doc.Name, &doc.MimeType, &doc.IsFile, &doc.IsPublic, &doc.JSONData, &doc.FilePath, &doc.CreatedAt)
	if err != nil {
		return doc, err
	}

	// Загружаем гранты
	grants, err := p.GetGrants(ctx, doc.ID)
	if err != nil {
		return doc, err // Или продолжить без грантов?
	}
	doc.Grant = grants

	return doc, nil
}

func (p *Postgres) DeleteDocument(ctx context.Context, docID uuid.UUID) error {
	// Удаление из document_grants происходит каскадно
	query := `DELETE FROM documents WHERE id = $1`
	_, err := p.db.Exec(ctx, query, docID)
	return err
}

func (p *Postgres) AddGrants(ctx context.Context, docID uuid.UUID, logins []string) error {
	if len(logins) == 0 {
		return nil
	}
	query := `INSERT INTO document_grants (document_id, user_login) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	batch := &pgx.Batch{}
	for _, login := range logins {
		batch.Queue(query, docID, login)
	}
	br := p.db.SendBatch(ctx, batch)
	// defer br.Close() // Отложенный вызов не гарантирует закрытие до return в случае ошибки внутри цикла
	// Лучше закрыть вручную после цикла или в блоке defer, но после обработки ошибок.

	// Используем range снова для выполнения и обработки ошибок
	var execErr error
	for _, login := range logins { // <-- Используем range
		_, err := br.Exec()
		if err != nil {
			execErr = fmt.Errorf("failed to add grant for login %s: %w", login, err) // Сохраняем ошибку
			break                                                                    // Прерываем цикл при первой ошибке
		}
	}

	// Важно закрыть батч, даже если была ошибка выполнения
	// br.Close() возвращает ошибку закрытия, которую тоже стоит проверить.
	closeErr := br.Close()

	// Возвращаем первую ошибку (выполнения или закрытия)
	if execErr != nil {
		return execErr
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close batch: %w", closeErr)
	}

	return nil
}

func (p *Postgres) GetGrants(ctx context.Context, docID uuid.UUID) ([]string, error) {
	var logins []string
	query := `SELECT user_login FROM document_grants WHERE document_id = $1`
	rows, err := p.db.Query(ctx, query, docID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var login string
		err := rows.Scan(&login)
		if err != nil {
			return nil, err
		}
		logins = append(logins, login)
	}
	return logins, rows.Err()
}
