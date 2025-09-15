// Package main Document Server API.
// @title Document Server API
// @version 1.0
// @description Веб-сервер для сохранения и раздачи электронных документов с кэшированием.
// @host localhost:8080
// @BasePath /api/v1
// @schemes http https
package main

import (
	"log"

	"document-server/internal/app"
	"document-server/internal/config"
)

func main() {
	cfg, err := config.LoadConfig(".")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	application, err := app.NewApp(cfg)
	if err != nil {
		log.Fatalf("Failed to create app: %v", err)
	}

	if err := application.Run(); err != nil {
		log.Fatalf("Application failed: %v", err)
	}
}
