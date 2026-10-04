// Package config загружает и проверяет конфигурацию сервиса.
//
// Значения читаются из системного окружения с подгрузкой из .env.
// Конфигурация валидируется при старте: незаполненное значение обнаруживается
// сразу, а не при первом обращении к базе.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// placeholder — значение-заглушка из .env.example.
const placeholder = "CHANGE_ME"

// Config содержит конфигурацию сервиса.
type Config struct {
	// Хранилище.
	DatabaseURL string `env:"DATABASE_URL,required"`

	// JWT. Access-токен живёт минуты, refresh — дни.
	JWTSecret       string        `env:"JWT_SECRET,required"`
	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL"  envDefault:"15m"`
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"720h"`
	Issuer          string        `env:"JWT_ISSUER"        envDefault:"video-platform"`

	// gRPC.
	Host string `env:"HOST" envDefault:"0.0.0.0"`
	Port int    `env:"PORT" envDefault:"50051"`

	// Ограничения запросов.
	MaxMessageBytes int           `env:"MAX_MESSAGE_BYTES" envDefault:"1048576"`
	RequestTimeout  time.Duration `env:"REQUEST_TIMEOUT"   envDefault:"10s"`

	// Стоимость bcrypt для хеширования паролей.
	BcryptCost int `env:"BCRYPT_COST" envDefault:"12"`
}

// Addr возвращает адрес gRPC-сервера.
func (c Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// Load читает конфигурацию и проверяет её.
func Load() (Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Stat(".env"); statErr == nil {
			return Config{}, fmt.Errorf("не удалось прочитать .env: %w", err)
		}
	}

	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return Config{}, fmt.Errorf("не удалось разобрать конфигурацию: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate проверяет значения, которые env-парсер не может проверить сам.
func (c Config) Validate() error {
	var problems []string

	for _, f := range []struct{ name, value string }{
		{"JWT_SECRET", c.JWTSecret},
	} {
		switch {
		case f.value == "":
			problems = append(problems, f.name+" не задан")
		case f.value == placeholder:
			problems = append(problems, fmt.Sprintf("%s остался со значением-заглушкой %s", f.name, placeholder))
		case len(f.value) < 32:
			problems = append(problems, fmt.Sprintf("%s слишком короткий (%d символа), нужно минимум 32", f.name, len(f.value)))
		}
	}

	if c.DatabaseURL == "" {
		problems = append(problems, "DATABASE_URL не задан")
	}
	if c.DatabaseURL == placeholder || containsPlaceholderCredentials(c.DatabaseURL) {
		problems = append(problems, "DATABASE_URL остался шаблоном из .env.example")
	}
	if c.AccessTokenTTL <= 0 {
		problems = append(problems, "ACCESS_TOKEN_TTL должен быть больше нуля")
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL {
		problems = append(problems, "REFRESH_TOKEN_TTL должен быть больше ACCESS_TOKEN_TTL")
	}
	if c.Port < 1 || c.Port > 65535 {
		problems = append(problems, fmt.Sprintf("PORT=%d вне диапазона 1-65535", c.Port))
	}
	if c.BcryptCost < 10 || c.BcryptCost > 31 {
		// Ниже 10 — слишком быстро для перебора, выше 31 — избыточно долго.
		problems = append(problems, "BCRYPT_COST должен быть в диапазоне 10-31")
	}

	if len(problems) > 0 {
		return fmt.Errorf("некорректная конфигурация:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// containsPlaceholderCredentials сообщает, остались ли в строке подключения
// логин и пароль из шаблона.
func containsPlaceholderCredentials(url string) bool {
	switch {
	case url == "":
		return false
	case url == placeholder:
		return true
	default:
		for _, template := range []string{"USER:PASSWORD@", "user:password@", "appuser:password@"} {
			if strings.Contains(url, template) {
				return true
			}
		}
		return false
	}
}
