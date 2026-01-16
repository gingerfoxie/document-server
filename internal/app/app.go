package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"document-server/internal/cache"
	"document-server/internal/config"
	"document-server/internal/handler"
	myMiddleware "document-server/internal/middleware" // Импортируем наш пакет middleware
	"document-server/internal/repository"
	"document-server/internal/service"

	_ "document-server/docs"

	httpSwagger "github.com/swaggo/http-swagger" // Swagger UI
)

type App struct {
	server *http.Server
	logger *zap.Logger
}

func NewApp(cfg config.Config) (*App, error) {
	// Logger
	//logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger, err := initLogger(cfg)
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// Database
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName, cfg.DBSSLMode)
	dbPool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Redis Client
	redisOptions := &redis.Options{
		Addr: cfg.RedisAddr,
		// Password: cfg.RedisPass, // Если пароль установлен
		DB: cfg.RedisDB,
	}
	redisClient := redis.NewClient(redisOptions)

	// Repositories
	userRepo := repository.NewPostgres(dbPool)
	docRepo := repository.NewPostgres(dbPool)

	// Cache
	cacheRepo := cache.NewRedisCache(redisClient, cfg.CacheTTLList, cfg.CacheTTLItem, logger)

	// Service
	svc := service.NewService(userRepo, docRepo, cacheRepo, cfg.JWTSecret, cfg.AdminToken, "./uploads", logger)

	// Handler
	h := handler.NewHandler(svc, logger)

	// Middleware
	mw := myMiddleware.NewMiddleware(svc, logger)

	// Router
	r := chi.NewRouter()

	// Global Middlewares
	r.Use(mw.Logging)
	r.Use(mw.Recover)
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(mw.CacheControl)           // Добавляем контроль кэша
	r.Use(chiMiddleware.Compress(5)) // Сжатие ответов

	// Routes
	r.Post("/api/register", h.Register)
	r.Post("/api/auth", h.Authenticate)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(mw.AuthRequired)
		r.Post("/api/docs", h.CreateDocument)
		r.Get("/api/docs", h.GetDocuments)           // Уровень 1, 2
		r.Head("/api/docs", h.GetDocuments)          // Уровень 1, 2
		r.Get("/api/docs/{id}", h.GetDocumentByID)   // Уровень 1, 2
		r.Head("/api/docs/{id}", h.GetDocumentByID)  // Уровень 1, 2
		r.Delete("/api/docs/{id}", h.DeleteDocument) // Уровень 2
		r.Delete("/api/auth/{token}", h.Logout)      // Уровень 3
	})

	// Server
	srv := &http.Server{
		Addr:         ":" + cfg.ServerPort,
		Handler:      r,
		ReadTimeout:  time.Duration(cfg.ServerReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.ServerWriteTimeout) * time.Second,
	}

	// Docs
	r.Get("/swagger/*", httpSwagger.Handler())

	return &App{
		server: srv,
		logger: logger,
	}, nil
}

func (a *App) Run() error {
	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.Error("Server failed", zap.Error(err))
		}
	}()
	a.logger.Info("Server started", zap.String("addr", a.server.Addr))

	<-done
	a.logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.server.Shutdown(ctx); err != nil {
		a.logger.Error("Server shutdown failed", zap.Error(err))
		return err
	}
	a.logger.Info("Server exited")
	return nil
}

func initLogger(cfg config.Config) (*zap.Logger, error) {
	// Преобразуем строку в zap level
	var level zapcore.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = zap.DebugLevel
	case "info":
		level = zap.InfoLevel
	case "warn", "warning":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	default:
		level = zap.InfoLevel
	}

	// Конфигурация
	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(level),
		Development: false,
		Encoding:    "json", // или "console" для удобства разработки
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return config.Build()
}
