package config

import (
	"strings"
	"testing"
	"time"
)

// baseEnv возвращает набор переменных, проходящих валидацию.
func baseEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL": "postgres://user:pass@localhost:5432/db?sslmode=disable",
		"JWT_SECRET":   strings.Repeat("a", 48),
	}
}

func TestLoadAcceptsValidConfig(t *testing.T) {
	for k, v := range baseEnv() {
		t.Setenv(k, v)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load вернул ошибку: %v", err)
	}

	if cfg.Port != 50051 {
		t.Errorf("Port = %d, ожидалось 50051", cfg.Port)
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %v, ожидалось 15m", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 720*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, ожидалось 720h", cfg.RefreshTokenTTL)
	}
	if cfg.BcryptCost != 12 {
		t.Errorf("BcryptCost = %d, ожидалось 12", cfg.BcryptCost)
	}
	if cfg.Addr() != "0.0.0.0:50051" {
		t.Errorf("Addr = %q", cfg.Addr())
	}
}

func TestValidateRejectsPlaceholderSecret(t *testing.T) {
	for k, v := range baseEnv() {
		t.Setenv(k, v)
	}
	t.Setenv("JWT_SECRET", "CHANGE_ME")

	_, err := Load()
	if err == nil {
		t.Fatal("приложение не должно запускаться с заглушкой")
	}
	if !strings.Contains(err.Error(), "JWT_SECRET") {
		t.Errorf("ошибка не упоминает поле: %v", err)
	}
}

func TestValidateRejectsShortSecret(t *testing.T) {
	for k, v := range baseEnv() {
		t.Setenv(k, v)
	}
	t.Setenv("JWT_SECRET", "short")

	_, err := Load()
	if err == nil {
		t.Fatal("короткий секрет не должен приниматься")
	}
	if !strings.Contains(err.Error(), "минимум 32") {
		t.Errorf("ошибка не объясняет требование: %v", err)
	}
}

func TestValidateRejectsTemplateDatabaseURL(t *testing.T) {
	for k, v := range baseEnv() {
		t.Setenv(k, v)
	}

	for _, url := range []string{
		"CHANGE_ME",
		"postgres://USER:PASSWORD@localhost:5432/db",
		"postgres://appuser:password@db:5432/user",
	} {
		t.Run(url, func(t *testing.T) {
			t.Setenv("DATABASE_URL", url)
			if _, err := Load(); err == nil {
				t.Fatalf("шаблон %q не должен приниматься", url)
			}
		})
	}
}

func TestValidateRejectsRefreshTTLShorterThanAccess(t *testing.T) {
	for k, v := range baseEnv() {
		t.Setenv(k, v)
	}
	t.Setenv("ACCESS_TOKEN_TTL", "2h")
	t.Setenv("REFRESH_TOKEN_TTL", "1h")

	if _, err := Load(); err == nil {
		t.Fatal("refresh-токен должен жить дольше access-токена")
	}
}

func TestValidateRejectsInvalidPort(t *testing.T) {
	for _, port := range []string{"0", "70000", "-1"} {
		t.Run(port, func(t *testing.T) {
			for k, v := range baseEnv() {
				t.Setenv(k, v)
			}
			t.Setenv("PORT", port)

			if _, err := Load(); err == nil {
				t.Fatalf("порт %s не должен приниматься", port)
			}
		})
	}
}

func TestValidateRejectsUnsafeBcryptCost(t *testing.T) {
	for _, cost := range []string{"4", "9", "32", "99"} {
		t.Run(cost, func(t *testing.T) {
			for k, v := range baseEnv() {
				t.Setenv(k, v)
			}
			t.Setenv("BCRYPT_COST", cost)

			// Стоимость ниже 10 упрощает перебор, выше 31 избыточна.
			if _, err := Load(); err == nil {
				t.Fatalf("стоимость %s не должна приниматься", cost)
			}
		})
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("a", 48))

	if _, err := Load(); err == nil {
		t.Fatal("отсутствие DATABASE_URL должно приводить к ошибке")
	}
}
