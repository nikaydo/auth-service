package main

import (
	"os"
)

// migrationsDir возвращает путь к каталогу миграций.
//
// Путь задаётся переменной окружения, чтобы работал и локальный запуск из
// корня репозитория, и запуск в контейнере, где рабочим каталогом является /app.
func migrationsDir() string {
	if dir := os.Getenv("MIGRATIONS_DIR"); dir != "" {
		return dir
	}
	return "db/migrations"
}
