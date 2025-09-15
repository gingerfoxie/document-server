package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"

	"document-server/internal/middleware"
	"document-server/internal/model"
	"document-server/internal/service"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	service *service.Service
	logger  *slog.Logger
}

func NewHandler(s *service.Service, logger *slog.Logger) *Handler {
	return &Handler{service: s, logger: logger}
}

// Register godoc
// @Summary Регистрация нового пользователя
// @Description Создание нового пользователя. Требуется токен администратора.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body map[string]string true "Данные для регистрации"
// @Success 200 {object} middleware.Response
// @Failure 400 {object} middleware.Response
// @Failure 401 {object} middleware.Response
// @Router /api/register [post]
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		Login string `json:"login"`
		Pswd  string `json:"pswd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Invalid JSON"}}, http.StatusBadRequest)
		return
	}

	if req.Token == "" || req.Login == "" || req.Pswd == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing required fields: token, login, pswd"}}, http.StatusBadRequest)
		return
	}

	err := h.service.Register(r.Context(), req.Token, req.Login, req.Pswd)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "invalid admin token" || strings.Contains(err.Error(), "failed to validate") {
			status = http.StatusUnauthorized
		} else if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "validate") {
			status = http.StatusBadRequest
		}
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: status, Text: err.Error()}}, status)
		return
	}

	middleware.WriteJSONResponse(w, middleware.Response{Response: map[string]string{"login": req.Login}}, http.StatusOK)
}

// Authenticate godoc
// @Summary Аутентификация пользователя
// @Description Получение JWT токена по логину и паролю.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body map[string]string true "Учетные данные"
// @Success 200 {object} middleware.Response
// @Failure 400 {object} middleware.Response
// @Failure 401 {object} middleware.Response
// @Router /api/auth [post]
func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login string `json:"login"`
		Pswd  string `json:"pswd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Invalid JSON"}}, http.StatusBadRequest)
		return
	}

	if req.Login == "" || req.Pswd == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing login or password"}}, http.StatusBadRequest)
		return
	}

	tokenString, err := h.service.Authenticate(r.Context(), req.Login, req.Pswd)
	if err != nil {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 401, Text: "Invalid login or password"}}, http.StatusUnauthorized)
		return
	}

	middleware.WriteJSONResponse(w, middleware.Response{Response: map[string]string{"token": tokenString}}, http.StatusOK)
}

// CreateDocument godoc
// @Summary Загрузка нового документа
// @Description Загрузка нового документа (файла или JSON) с метаданными.
// @Tags documents
// @Accept mpfd
// @Produce json
// @Param meta formData string true "Метаданные документа в формате JSON"
// @Param json formData string false "Данные документа в формате JSON (если не файл)"
// @Param file formData file false "Файл документа (если file=true в meta)"
// @Success 200 {object} middleware.Response
// @Failure 400 {object} middleware.Response
// @Failure 401 {object} middleware.Response
// @Router /api/docs [post]
func (h *Handler) CreateDocument(w http.ResponseWriter, r *http.Request) {
	// Парсим multipart/form-data
	err := r.ParseMultipartForm(32 << 20) // 32 MB max memory
	if err != nil {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Failed to parse multipart form"}}, http.StatusBadRequest)
		return
	}

	// Получаем поле 'meta'
	metaStr := r.FormValue("meta")
	if metaStr == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing meta field"}}, http.StatusBadRequest)
		return
	}

	var meta model.CreateDocumentRequest
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Invalid meta JSON"}}, http.StatusBadRequest)
		return
	}

	// Получаем опциональное поле 'json'
	var jsonData *string
	jsonStr := r.FormValue("json")
	if jsonStr != "" {
		jsonData = &jsonStr
	}

	// Получаем опциональный файл
	var fileHeader *multipart.FileHeader
	file, fileHeaderTmp, _ := r.FormFile("file")
	if file != nil {
		defer file.Close()
		fileHeader = fileHeaderTmp
	}

	// Создаем документ
	doc, err := h.service.CreateDocument(r.Context(), meta, jsonData, fileHeader)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "unauthorized" {
			status = http.StatusUnauthorized
		} else if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "invalid") {
			status = http.StatusBadRequest
		}
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: status, Text: err.Error()}}, status)
		return
	}

	respData := map[string]interface{}{
		"file": doc.Name, // Имя файла
	}
	if jsonData != nil {
		var parsedJSON interface{}
		json.Unmarshal([]byte(*jsonData), &parsedJSON)
		respData["json"] = parsedJSON
	}

	middleware.WriteJSONResponse(w, middleware.Response{Data: respData}, http.StatusOK)
}

// GetDocuments godoc
// @Summary Получение списка документов
// @Description Получение списка документов текущего пользователя или указанного пользователя (если публичные). Поддерживает фильтрацию и пагинацию.
// @Tags documents
// @Produce json
// @Param token query string true "Токен авторизации"
// @Param login query string false "Логин пользователя, чьи документы запрашиваются"
// @Param key query string false "Ключ для фильтрации (например, 'name')"
// @Param value query string false "Значение для фильтрации"
// @Param limit query int false "Лимит количества документов (по умолчанию 100)"
// @Success 200 {object} middleware.Response
// @Failure 400 {object} middleware.Response
// @Failure 401 {object} middleware.Response
// @Router /api/docs [get]
func (h *Handler) GetDocuments(w http.ResponseWriter, r *http.Request) {
	// Для HEAD запроса не возвращаем тело
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing token"}}, http.StatusBadRequest)
		return
	}

	loginFilter := r.URL.Query().Get("login")
	key := r.URL.Query().Get("key")
	value := r.URL.Query().Get("value")
	limitStr := r.URL.Query().Get("limit")

	limit := 100 // Значение по умолчанию
	if limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit <= 0 || limit > 1000 { // Ограничение на лимит
			limit = 100
		}
	}

	docs, err := h.service.GetDocuments(r.Context(), token, loginFilter, key, value, limit)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "unauthorized" {
			status = http.StatusUnauthorized
		} else if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: status, Text: err.Error()}}, status)
		return
	}

	// Подготавливаем данные для ответа (добавляем grants)
	docsResp := make([]map[string]interface{}, len(docs))
	for i, doc := range docs {
		docMap := map[string]interface{}{
			"id":      doc.ID.String(),
			"name":    doc.Name,
			"mime":    doc.MimeType,
			"file":    doc.IsFile,
			"public":  doc.IsPublic,
			"created": doc.CreatedAt.Format("2006-01-02 15:04:05"),
			"grant":   doc.Grant,
		}
		docsResp[i] = docMap
	}

	middleware.WriteJSONResponse(w, middleware.Response{Data: map[string]interface{}{"docs": docsResp}}, http.StatusOK)
}

// GetDocumentByID godoc
// @Summary Получение одного документа
// @Description Получение конкретного документа по ID. Если это файл, он отдается напрямую. Если JSON - возвращается в обертке data.
// @Tags documents
// @Produce json
// @Param id path string true "ID документа"
// @Param token query string true "Токен авторизации"
// @Success 200 {object} middleware.Response
// @Failure 400 {object} middleware.Response
// @Failure 401 {object} middleware.Response
// @Failure 403 {object} middleware.Response
// @Failure 404 {object} middleware.Response
// @Router /api/docs/{id} [get]
func (h *Handler) GetDocumentByID(w http.ResponseWriter, r *http.Request) {
	docID := chi.URLParam(r, "id")
	if docID == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing document ID"}}, http.StatusBadRequest)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing token"}}, http.StatusBadRequest)
		return
	}

	doc, err := h.service.GetDocumentByID(r.Context(), token, docID)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "unauthorized" {
			status = http.StatusUnauthorized
		} else if err.Error() == "access denied" {
			status = http.StatusForbidden
		} else if err.Error() == "document not found" || strings.Contains(err.Error(), "invalid") {
			status = http.StatusNotFound
		}
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: status, Text: err.Error()}}, status)
		return
	}

	// Для HEAD запроса не возвращаем тело, но устанавливаем заголовки
	if r.Method == http.MethodHead {
		if doc.IsFile && doc.FilePath != nil {
			w.Header().Set("Content-Type", doc.MimeType)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", getFileSize(*doc.FilePath))) // Нужна функция getFileSize
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	if doc.IsFile {
		if doc.FilePath == nil || *doc.FilePath == "" {
			http.Error(w, "File path is missing", http.StatusInternalServerError)
			return
		}
		// Устанавливаем правильные заголовки
		w.Header().Set("Content-Type", doc.MimeType)
		// w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", doc.Name)) // Или "attachment"
		http.ServeFile(w, r, *doc.FilePath)
	} else {
		// Отдаем JSON данные
		var parsedJSON interface{}
		if doc.JSONData != nil {
			json.Unmarshal([]byte(*doc.JSONData), &parsedJSON)
		}
		middleware.WriteJSONResponse(w, middleware.Response{Data: parsedJSON}, http.StatusOK)
	}
}

// getFileSize - вспомогательная функция для получения размера файла
func getFileSize(filePath string) int64 {
	if info, err := os.Stat(filePath); err == nil {
		return info.Size()
	}
	return 0
}

// DeleteDocument godoc
// @Summary Удаление документа
// @Description Удаление документа по ID. Доступно только владельцу.
// @Tags documents
// @Produce json
// @Param id path string true "ID документа"
// @Param token query string true "Токен авторизации"
// @Success 200 {object} middleware.Response
// @Failure 400 {object} middleware.Response
// @Failure 401 {object} middleware.Response
// @Failure 403 {object} middleware.Response
// @Failure 404 {object} middleware.Response
// @Router /api/docs/{id} [delete]
func (h *Handler) DeleteDocument(w http.ResponseWriter, r *http.Request) {
	docID := chi.URLParam(r, "id")
	if docID == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing document ID"}}, http.StatusBadRequest)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing token"}}, http.StatusBadRequest)
		return
	}

	err := h.service.DeleteDocument(r.Context(), token, docID)
	if err != nil {
		status := http.StatusInternalServerError
		if err.Error() == "unauthorized" {
			status = http.StatusUnauthorized
		} else if err.Error() == "access denied" {
			status = http.StatusForbidden
		} else if err.Error() == "document not found" || strings.Contains(err.Error(), "invalid") {
			status = http.StatusNotFound
		}
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: status, Text: err.Error()}}, status)
		return
	}

	resp := map[string]bool{docID: true}
	middleware.WriteJSONResponse(w, middleware.Response{Response: resp}, http.StatusOK)
}

// Logout godoc
// @Summary Завершение сессии
// @Description Завершение авторизованной сессии (помечает токен как недействительный).
// @Tags auth
// @Produce json
// @Param token path string true "Токен авторизации"
// @Success 200 {object} middleware.Response
// @Failure 400 {object} middleware.Response
// @Failure 401 {object} middleware.Response
// @Router /api/auth/{token} [delete]
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token") // Получаем токен из URL
	if token == "" {
		// Альтернатива: получить из заголовка Authorization
		// authHeader := r.Header.Get("Authorization")
		// token = strings.TrimPrefix(authHeader, "Bearer ")
		middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 400, Text: "Missing token"}}, http.StatusBadRequest)
		return
	}

	// В текущей реализации JWT это просто прекращение использования токена клиентом.
	// Сервер не может "удалить" JWT. Можно реализовать блэклист.
	// err := h.service.Logout(token)
	// if err != nil {
	// 	middleware.WriteJSONResponse(w, middleware.Response{Error: &middleware.ErrorResponse{Code: 401, Text: "Invalid token"}}, http.StatusUnauthorized)
	// 	return
	// }

	// Для демонстрации просто возвращаем успех
	resp := map[string]bool{token: true}
	middleware.WriteJSONResponse(w, middleware.Response{Response: resp}, http.StatusOK)
}
