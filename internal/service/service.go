package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"document-server/internal/cache"
	"document-server/internal/model"
	"document-server/internal/repository"
	"document-server/pkg/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	userRepo   repository.UserRepository
	docRepo    repository.DocumentRepository
	cache      *cache.RedisCache
	jwtSecret  []byte
	adminToken string
	uploadDir  string // Каталог для загрузки файлов
}

func NewService(userRepo repository.UserRepository, docRepo repository.DocumentRepository, cache *cache.RedisCache, jwtSecret, adminToken, uploadDir string) *Service {
	// Убедимся, что директория для загрузок существует
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		// Лучше обработать это на старте приложения
		panic(fmt.Sprintf("Failed to create upload directory: %v", err))
	}
	return &Service{
		userRepo:   userRepo,
		docRepo:    docRepo,
		cache:      cache,
		jwtSecret:  []byte(jwtSecret),
		adminToken: adminToken,
		uploadDir:  uploadDir,
	}
}

// --- User Service ---

func (s *Service) Register(ctx context.Context, adminToken, login, password string) error {
	if adminToken != s.adminToken {
		return errors.New("invalid admin token")
	}

	if err := utils.ValidateLogin(login); err != nil {
		return err
	}
	if err := utils.ValidatePassword(password); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user := model.User{
		ID:           uuid.New(),
		Login:        login,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	err = s.userRepo.CreateUser(ctx, user)
	if err != nil {
		// Проверить на уникальность логина
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			return errors.New("user with this login already exists")
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (s *Service) Authenticate(ctx context.Context, login, password string) (string, error) {
	user, err := s.userRepo.GetUserByLogin(ctx, login)
	if err != nil {
		return "", errors.New("invalid login or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return "", errors.New("invalid login or password")
	}

	// Генерируем JWT токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID.String(),
		"login":   user.Login,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // Токен действует 24 часа
	})

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (s *Service) ValidateToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
}

func (s *Service) GetUserIDFromToken(tokenString string) (uuid.UUID, error) {
	token, err := s.ValidateToken(tokenString)
	if err != nil {
		return uuid.Nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if userIDStr, ok := claims["user_id"].(string); ok {
			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				return uuid.Nil, errors.New("invalid user ID in token")
			}
			return userID, nil
		}
	}
	return uuid.Nil, errors.New("invalid token claims")
}

// --- Document Service ---

// handleFileUpload обрабатывает загрузку файла из multipart/form-data
func (s *Service) handleFileUpload(fileHeader *multipart.FileHeader) (string, string, error) {
	if fileHeader == nil {
		return "", "", errors.New("no file provided")
	}

	src, err := fileHeader.Open()
	if err != nil {
		return "", "", fmt.Errorf("failed to open uploaded file: %w", err)
	}
	defer src.Close()

	// Генерируем уникальное имя файла
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	uniqueFileName := hex.EncodeToString(randomBytes) + "_" + fileHeader.Filename

	// Определяем путь сохранения
	filePath := filepath.Join(s.uploadDir, uniqueFileName)

	// Создаем файл на диске
	dst, err := os.Create(filePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create file on disk: %w", err)
	}
	defer dst.Close()

	// Копируем содержимое
	if _, err := io.Copy(dst, src); err != nil {
		return "", "", fmt.Errorf("failed to copy file content: %w", err)
	}

	// Определяем MIME тип (можно улучшить)
	mime := fileHeader.Header.Get("Content-Type")
	if mime == "" {
		// Попытка определить по содержимому или расширению
		// Для простоты оставим пустым или возьмем из запроса
	}

	return filePath, mime, nil
}

func (s *Service) CreateDocument(ctx context.Context, meta model.CreateDocumentRequest, jsonData *string, fileHeader *multipart.FileHeader) (model.Document, error) {
	userID, err := s.GetUserIDFromToken(meta.Token)
	if err != nil {
		return model.Document{}, errors.New("unauthorized")
	}

	doc := model.Document{
		ID:        uuid.New(),
		OwnerID:   userID,
		Name:      meta.Name,
		IsFile:    meta.IsFile,
		IsPublic:  meta.IsPublic,
		JSONData:  jsonData,
		MimeType:  meta.Mime,
		CreatedAt: time.Now(),
		Grant:     meta.Grant,
	}

	if meta.IsFile {
		if fileHeader == nil {
			return model.Document{}, errors.New("file is required for file documents")
		}
		filePath, detectedMime, err := s.handleFileUpload(fileHeader)
		if err != nil {
			return model.Document{}, fmt.Errorf("file upload failed: %w", err)
		}
		doc.FilePath = &filePath
		if meta.Mime == "" {
			doc.MimeType = detectedMime // Используем определенный MIME если не передан
		}
	}

	createdDoc, err := s.docRepo.CreateDocument(ctx, doc)
	if err != nil {
		// Если файл был создан, удаляем его
		if doc.FilePath != nil {
			os.Remove(*doc.FilePath)
		}
		return model.Document{}, fmt.Errorf("failed to create document: %w", err)
	}

	// Инвалидируем кэш списков документов
	go s.cache.InvalidateDocumentLists(context.Background()) // Не блокируем основной поток

	return createdDoc, nil
}

func (s *Service) GetDocuments(ctx context.Context, tokenString, loginFilter, key, value string, limit int) ([]model.Document, error) {
	userID, err := s.GetUserIDFromToken(tokenString)
	if err != nil {
		return nil, errors.New("unauthorized")
	}

	// Определяем, чьи документы запрашивать
	targetUserID := userID
	if loginFilter != "" {
		// Проверяем, существует ли пользователь с таким логином
		_, err := s.userRepo.GetUserByLogin(ctx, loginFilter)
		if err != nil {
			return nil, errors.New("user not found") // Или просто возвращаем пустой список?
		}
		// Здесь можно добавить проверку, разрешено ли текущему пользователю видеть документы другого пользователя
		// Пока просто возвращаем свои
		// targetUserID = ... // ID пользователя loginFilter
		// Для простоты, если login указан, возвращаем только публичные документы этого пользователя
		// Это требует изменения логики в репозитории
		// Пока оставим как есть - возвращаем свои
	}

	// Формируем ключ кэша
	cacheKey := fmt.Sprintf("doclist:%s:%s:%s:%d", userID.String(), key, value, limit) // Упрощенный ключ

	// Пытаемся получить из кэша
	if cachedData, err := s.cache.GetDocumentList(ctx, cacheKey); err == nil {
		var docs []model.Document
		if json.Unmarshal(cachedData, &docs) == nil {
			return docs, nil // Возвращаем из кэша
		}
	}

	// Получаем из БД
	docs, err := s.docRepo.GetDocuments(ctx, targetUserID, limit, key, value)
	if err != nil {
		return nil, fmt.Errorf("failed to get documents: %w", err)
	}

	// Сохраняем в кэш
	if data, err := json.Marshal(docs); err == nil {
		go s.cache.SetDocumentList(context.Background(), cacheKey, data) // Не блокируем
	}

	return docs, nil
}

func (s *Service) GetDocumentByID(ctx context.Context, tokenString, docIDStr string) (model.Document, error) {
	userID, err := s.GetUserIDFromToken(tokenString)
	if err != nil {
		return model.Document{}, errors.New("unauthorized")
	}

	docID, err := uuid.Parse(docIDStr)
	if err != nil {
		return model.Document{}, errors.New("invalid document ID")
	}

	// Формируем ключ кэша
	cacheKey := fmt.Sprintf("docitem:%s", docIDStr)

	// Пытаемся получить из кэша
	if cachedData, err := s.cache.GetDocumentItem(ctx, cacheKey); err == nil {
		var doc model.Document
		if json.Unmarshal(cachedData, &doc) == nil {
			return doc, nil // Возвращаем из кэша
		}
	}

	// Получаем из БД
	doc, err := s.docRepo.GetDocumentByID(ctx, docID)
	if err != nil {
		return model.Document{}, errors.New("document not found")
	}

	// Проверяем права доступа
	if doc.OwnerID != userID && !doc.IsPublic {
		// Проверяем, есть ли грант
		grants, _ := s.docRepo.GetGrants(ctx, doc.ID) // Игнорируем ошибку, если грантов нет
		hasAccess := false
		// Получаем логин текущего пользователя из токена
		token, _ := s.ValidateToken(tokenString)
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if login, ok := claims["login"].(string); ok {
				for _, grantedLogin := range grants {
					if grantedLogin == login {
						hasAccess = true
						break
					}
				}
			}
		}
		if !hasAccess {
			return model.Document{}, errors.New("access denied")
		}
	}

	// Сохраняем в кэш
	if data, err := json.Marshal(doc); err == nil {
		go s.cache.SetDocumentItem(context.Background(), cacheKey, data) // Не блокируем
	}

	return doc, nil
}

func (s *Service) DeleteDocument(ctx context.Context, tokenString, docIDStr string) error {
	userID, err := s.GetUserIDFromToken(tokenString)
	if err != nil {
		return errors.New("unauthorized")
	}

	docID, err := uuid.Parse(docIDStr)
	if err != nil {
		return errors.New("invalid document ID")
	}

	// Получаем документ для проверки владельца
	doc, err := s.docRepo.GetDocumentByID(ctx, docID)
	if err != nil {
		return errors.New("document not found")
	}

	if doc.OwnerID != userID {
		return errors.New("access denied")
	}

	// Удаляем файл с диска, если он есть
	if doc.FilePath != nil {
		os.Remove(*doc.FilePath) // Игнорируем ошибку удаления файла
	}

	err = s.docRepo.DeleteDocument(ctx, docID)
	if err != nil {
		return fmt.Errorf("failed to delete document: %w", err)
	}

	// Инвалидируем кэш
	go s.cache.InvalidateDocumentLists(context.Background())
	go s.cache.InvalidateDocumentItem(context.Background(), fmt.Sprintf("docitem:%s", docIDStr))

	return nil
}

func (s *Service) Logout(tokenString string) error {
	// В данном случае, так как токены JWT самодостаточны,
	// "выход" означает просто прекращение использования токена клиентом.
	// Для немедленной инвалидации можно реализовать блэклист токенов в Redis.
	// token, err := s.ValidateToken(tokenString)
	// if err != nil {
	// 	return err
	// }
	// if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
	// 	exp, _ := claims.GetExpirationTime()
	// 	if exp != nil {
	// 		// Добавляем токен в блэклист с временем жизни равным времени жизни токена
	// 		// hash := utils.HashToken(tokenString) // Нужна функция хэширования
	// 		// return s.cache.BlacklistToken(context.Background(), hash, time.Until(exp.Time))
	// 	}
	// }
	return nil
}
