package database_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nikaydo/auth-service/internal/database"
)

// testStore открывает подключение к тестовой базе.
//
// Тесты интеграционные: им нужна настоящая PostgreSQL, потому что проверяют
// поведение запросов, а не текст SQL. База задаётся TEST_DATABASE_URL; если
// переменная не задана, тесты пропускаются, чтобы go test ./... проходил без
// внешних зависимостей.
func testStore(t *testing.T) *database.Store {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL не задан: интеграционные тесты пропущены")
	}

	ctx := context.Background()
	if err := database.RunMigrations(ctx, url, migrationsDir(t)); err != nil {
		t.Fatalf("миграции не применились: %v", err)
	}

	store, err := database.New(ctx, url)
	if err != nil {
		t.Fatalf("не удалось подключиться к базе: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("TEST_MIGRATIONS_DIR"); dir != "" {
		return dir
	}
	return "../../db/migrations"
}

// uniqueLogin даёт логину уникальное имя на каждый запуск: тесты выполняются
// против общей базы, и фиксированные имена конфликтовали бы с прошлыми прогонами.
func uniqueLogin(t *testing.T, prefix string) string {
	t.Helper()
	return prefix + "-" + time.Now().Format("150405.000000")
}

// TestCreateUserReturnsRealID — регрессия на критичный дефект.
//
// Метод отбрасывал результат вставки и возвращал константу 1. Из-за этого
// все пользователи получали один идентификатор, а выпущенные для них токены
// оказывались взаимозаменяемыми: токен одного человека подходил другому.
func TestCreateUserReturnsRealID(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	first, err := store.CreateUser(ctx, database.CreateUserParams{
		Login:        uniqueLogin(t, "id-check-1"),
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	second, err := store.CreateUser(ctx, database.CreateUserParams{
		Login:        uniqueLogin(t, "id-check-2"),
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
		Role:         "user",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if first == second {
		t.Fatalf("идентификаторы совпали (%d): каждый пользователь должен получать свой", first)
	}
	if first <= 0 || second <= 0 {
		t.Fatalf("идентификаторы некорректны: %d и %d", first, second)
	}
}

func TestCreateUserRejectsDuplicateLogin(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	login := uniqueLogin(t, "dup")
	params := database.CreateUserParams{
		Login:        login,
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
		Role:         "user",
	}
	if _, err := store.CreateUser(ctx, params); err != nil {
		t.Fatalf("первая регистрация: %v", err)
	}

	if _, err := store.CreateUser(ctx, params); !errors.Is(err, database.ErrLoginTaken) {
		t.Fatalf("ожидался ErrLoginTaken, получено %v", err)
	}
}

func TestLoginIsCaseInsensitive(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	login := uniqueLogin(t, "Case")
	if _, err := store.CreateUser(ctx, database.CreateUserParams{
		Login:        login,
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// В базе стоит CHECK (login = lower(login)) и уникальный индекс по
	// lower(login). Регистрация «User» при отсутствии нормализации падала бы
	// с невнятной ошибкой ограничения.
	upper := strings.ToUpper(login)
	if _, err := store.CreateUser(ctx, database.CreateUserParams{
		Login:        upper,
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
	}); !errors.Is(err, database.ErrLoginTaken) {
		t.Fatalf("логин в другом регистре должен считаться тем же, получено %v", err)
	}

	// Поиск тоже не должен зависеть от регистра.
	found, err := store.UserByLogin(ctx, upper)
	if err != nil {
		t.Fatalf("UserByLogin: %v", err)
	}
	if database.NormalizeLogin(found.Login) != database.NormalizeLogin(login) {
		t.Errorf("найден другой пользователь: %q", found.Login)
	}
}

func TestPasswordIsNotStoredInPlaintext(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	const password = "very-secret-password"
	hash := "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha"

	login := uniqueLogin(t, "hashcheck")
	if _, err := store.CreateUser(ctx, database.CreateUserParams{
		Login:        login,
		PasswordHash: hash,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	user, err := store.UserByLogin(ctx, login)
	if err != nil {
		t.Fatalf("UserByLogin: %v", err)
	}
	if user.PasswordHash == password {
		t.Fatal("пароль сохранён в открытом виде")
	}
	if user.PasswordHash != hash {
		t.Errorf("хеш не совпадает с сохранённым: %q", user.PasswordHash)
	}
}

func TestValidateLogin(t *testing.T) {
	tests := []struct {
		name    string
		login   string
		wantErr bool
	}{
		{"нормальный логин", "nikaydo", false},
		{"с пробелами по краям", "  nikaydo  ", false},
		{"в верхнем регистре", "NIKAYDO", false},
		{"слишком короткий", "ab", true},
		{"пустой", "", true},
		{"с пробелом внутри", "nik aydo", true},
		{"слишком длинный", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := database.ValidateLogin(tt.login)
			if tt.wantErr && err == nil {
				t.Errorf("логин %q должен отклоняться", tt.login)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("логин %q отклонён: %v", tt.login, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	if err := database.ValidatePassword("short"); err == nil {
		t.Error("короткий пароль должен отклоняться")
	}
	if err := database.ValidatePassword("adequate-password"); err != nil {
		t.Errorf("достаточный пароль отклонён: %v", err)
	}
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	if err := database.ValidatePassword(string(long)); err == nil {
		t.Error("слишком длинный пароль должен отклоняться")
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	login := uniqueLogin(t, "rotate")
	userID, err := store.CreateUser(ctx, database.CreateUserParams{
		Login:        login,
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const (
		family = "family-rotate"
		hash1  = "hash-of-first-token"
		hash2  = "hash-of-second-token"
	)
	expiry := time.Now().Add(time.Hour)

	if err := store.SaveRefreshToken(ctx, userID, family, hash1, expiry); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	if _, err := store.UserByRefreshHash(ctx, hash1); err != nil {
		t.Fatalf("активный токен не найден: %v", err)
	}

	// Ротация: первый токен отзывается, выдаётся второй.
	if err := store.RotateRefreshToken(ctx, userID, family, hash1, hash2, expiry); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}

	if _, err := store.UserByRefreshHash(ctx, hash1); !errors.Is(err, database.ErrNotFound) {
		t.Errorf("прежний токен должен перестать работать, получено %v", err)
	}
	if _, err := store.UserByRefreshHash(ctx, hash2); err != nil {
		t.Errorf("новый токен должен работать: %v", err)
	}

	// Повторное предъявление прежнего токена — признак утечки.
	var reused *database.ErrRefreshReused
	err = store.RotateRefreshToken(ctx, userID, family, hash1, "hash-of-third-token", expiry)
	if !errors.As(err, &reused) {
		t.Fatalf("ожидалась ErrRefreshReused, получено %v", err)
	}
}

func TestRotateUnknownToken(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	userID, err := store.CreateUser(ctx, database.CreateUserParams{
		Login:        uniqueLogin(t, "unknown"),
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Токена, которого никогда не было, — это не повторное использование,
	// а неизвестный токен: семейство отзывать не нужно.
	err = store.RotateRefreshToken(ctx, userID, "family", "never-existed", "new-hash", time.Now().Add(time.Hour))
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("ожидался ErrNotFound, получено %v", err)
	}
}

func TestRevokedTokenNotFound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	userID, _ := store.CreateUser(ctx, database.CreateUserParams{
		Login:        uniqueLogin(t, "revoke"),
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
	})

	const hash = "hash-to-revoke"
	if err := store.SaveRefreshToken(ctx, userID, "family-revoke", hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if err := store.RevokeTokenFamily(ctx, "family-revoke"); err != nil {
		t.Fatalf("RevokeTokenFamily: %v", err)
	}

	if _, err := store.UserByRefreshHash(ctx, hash); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("отозванный токен всё ещё находится: %v", err)
	}
}

func TestExpiredTokenNotFound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	userID, _ := store.CreateUser(ctx, database.CreateUserParams{
		Login:        uniqueLogin(t, "expired"),
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
	})

	const hash = "already-expired"
	if err := store.SaveRefreshToken(ctx, userID, "family-expired", hash, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	if _, err := store.UserByRefreshHash(ctx, hash); !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("истёкший токен всё ещё находится: %v", err)
	}
}

func TestRevokeAllUserTokens(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	userID, _ := store.CreateUser(ctx, database.CreateUserParams{
		Login:        uniqueLogin(t, "logout"),
		PasswordHash: "$2a$10$hashhashhashhashhashhashhashhashhashhashhashha",
	})

	for _, hash := range []string{"session-a", "session-b"} {
		if err := store.SaveRefreshToken(ctx, userID, "family-"+hash, hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("SaveRefreshToken %s: %v", hash, err)
		}
	}

	if err := store.RevokeAllUserTokens(ctx, userID); err != nil {
		t.Fatalf("RevokeAllUserTokens: %v", err)
	}

	for _, hash := range []string{"session-a", "session-b"} {
		if _, err := store.UserByRefreshHash(ctx, hash); !errors.Is(err, database.ErrNotFound) {
			t.Errorf("токен %s не отозван: %v", hash, err)
		}
	}
}
