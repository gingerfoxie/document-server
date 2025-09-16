package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"document-server/internal/service"

	"github.com/go-chi/chi/v5/middleware"
)

type Middleware struct {
	service *service.Service
	logger  *slog.Logger
}

func NewMiddleware(s *service.Service, logger *slog.Logger) *Middleware {
	return &Middleware{service: s, logger: logger}
}

// Response структура для ответа
// swagger:model Response
type Response struct {
	Error    *ErrorResponse `json:"error,omitempty"`
	Response interface{}    `json:"response,omitempty"`
	Data     interface{}    `json:"data,omitempty"`
}

// swagger:model ErrorResponse
type ErrorResponse struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

// WriteJSONResponse записывает структурированный JSON ответ
func WriteJSONResponse(w http.ResponseWriter, resp Response, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("Failed to encode JSON response", "error", err)
		// Отправляем минимальный ответ в случае ошибки кодирования
		http.Error(w, `{"error":{"code":500,"text":"Internal Server Error"}}`, http.StatusInternalServerError)
	}
}

// AuthRequired проверяет JWT токен
func (m *Middleware) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			WriteJSONResponse(w, Response{Error: &ErrorResponse{Code: 401, Text: "Authorization header missing"}}, http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			WriteJSONResponse(w, Response{Error: &ErrorResponse{Code: 401, Text: "Bearer token required"}}, http.StatusUnauthorized)
			return
		}

		_, err := m.service.ValidateToken(tokenString)
		if err != nil {
			WriteJSONResponse(w, Response{Error: &ErrorResponse{Code: 401, Text: "Invalid or expired token"}}, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Logging логирует запросы
func (m *Middleware) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		defer func() {
			m.logger.Info("Request",
				"method", r.Method,
				"url", r.URL.Path,
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
				"status", ww.Status(),
				"took", time.Since(start),
			)
		}()
		next.ServeHTTP(ww, r)
	})
}

// CacheControl добавляет заголовки кэширования
func (m *Middleware) CacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Для GET/HEAD запросов добавляем Cache-Control
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			// Можно настроить разные TTL для разных путей
			w.Header().Set("Cache-Control", "public, max-age=60") // 1 минута
		} else {
			// Для других запросов запрещаем кэширование
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		next.ServeHTTP(w, r)
	})
}

// Recover восстанавливается от паник
func (m *Middleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				m.logger.Error("Panic recovered", "panic", rvr, "stack", string(debug.Stack()))
				WriteJSONResponse(w, Response{Error: &ErrorResponse{Code: 500, Text: "Internal Server Error"}}, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
