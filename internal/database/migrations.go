package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations применяет миграции из каталога dir.
//
// Схема управляется миграциями, а не вызовами CREATE TABLE IF NOT EXISTS
// в коде: иначе невозможно изменить существующую таблицу и откатить
// изменение.
func RunMigrations(ctx context.Context, databaseURL, dir string) error {
	m, err := migrate.New("file://"+dir, databaseURL)
	if err != nil {
		return fmt.Errorf("не удалось инициализировать миграции: %w", err)
	}
	defer func() {
		if sourceErr, dbErr := m.Close(); sourceErr != nil {
			fmt.Printf("ошибка закрытия источника миграций: %v\n", sourceErr)
		} else if dbErr != nil {
			fmt.Printf("ошибка закрытия соединения миграций: %v\n", dbErr)
		}
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("не удалось применить миграции: %w", err)
	}
	return nil
}
