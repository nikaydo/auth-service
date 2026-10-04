// Package database отвечает за работу с PostgreSQL.
//
// Имена таблиц заданы в коде, а не приходят из конфигурации: так запросы
// не зависят от настроек и могут использовать подготовленные выражения.
// Все методы принимают context.Context, чтобы отмена запроса прерывала
// и обращение к базе.
package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ошибки уровня домена.
var (
	ErrNotFound     = errors.New("запись не найдена")
	ErrLoginTaken   = errors.New("логин уже занят")
	ErrWeakPassword = errors.New("пароль слишком простой")
)

// Ограничения на логин и пароль.
const (
	MinLoginLength    = 3
	MaxLoginLength    = 32
	MinPasswordLength = 8
	MaxPasswordLength = 128
)

// Store — обёртка над пулом соединений.
type Store struct {
	pool *pgxpool.Pool
}

// New открывает пул соединений и проверяет доступность базы.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать строку подключения: %w", err)
	}
	// Ограничиваем время жизни соединений: иначе после перезапуска базы
	// пул держит мёртвые соединения и запросы падают по таймауту.
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать пул соединений: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("база данных недоступна: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close закрывает пул соединений.
func (s *Store) Close() {
	s.pool.Close()
}

// Pool возвращает пул для мест, где нужен прямой доступ.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// User — пользователь системы.
type User struct {
	ID    int64
	Login string
	// PasswordHash — bcrypt-хеш пароля. Открытым текстом пароль в базе
	// больше не хранится.
	PasswordHash string
	Role         string
}

// NormalizeLogin приводит логин к каноническому виду: без пробелов по краям
// и в нижнем регистре. В базе стоит ограничение login = lower(login) и
// уникальный индекс по lower(login), поэтому без нормализации регистрация
// «User» падала бы, а «user» и «User» считались бы разными записями.
func NormalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

// ValidateLogin проверяет логин.
func ValidateLogin(login string) error {
	normalized := NormalizeLogin(login)
	if len([]rune(normalized)) < MinLoginLength {
		return fmt.Errorf("логин должен содержать минимум %d символа", MinLoginLength)
	}
	if len([]rune(normalized)) > MaxLoginLength {
		return fmt.Errorf("логин не должен превышать %d символов", MaxLoginLength)
	}
	if strings.ContainsAny(normalized, " \t\n\r") {
		return errors.New("логин не должен содержать пробелов")
	}
	return nil
}

// ValidatePassword проверяет пароль.
func ValidatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("пароль должен содержать минимум %d символов", MinPasswordLength)
	}
	if len(password) > MaxPasswordLength {
		// bcrypt учитывает только первые 72 байта, поэтому ограничение
		// защищает от молчаливого обрезания.
		return fmt.Errorf("пароль не должен превышать %d символов", MaxPasswordLength)
	}
	return nil
}

// CreateUserParams — данные для регистрации.
type CreateUserParams struct {
	Login        string
	PasswordHash string
	Role         string
}

// CreateUser регистрирует пользователя и возвращает его идентификатор.
//
// Идентификатор берётся из RETURNING. Раньше выполнение запроса
// отбрасывалось, а метод возвращал константу 1 — из-за этого все
// пользователи получали один и тот же идентификатор, а токены разных
// людей оказывались взаимозаменяемыми.
func (s *Store) CreateUser(ctx context.Context, p CreateUserParams) (int64, error) {
	if err := ValidateLogin(p.Login); err != nil {
		return 0, err
	}
	if strings.TrimSpace(p.PasswordHash) == "" {
		return 0, errors.New("хеш пароля не может быть пустым")
	}

	role := p.Role
	if role == "" {
		role = "user"
	}

	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (login, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id
	`, NormalizeLogin(p.Login), p.PasswordHash, role).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrLoginTaken
		}
		return 0, fmt.Errorf("не удалось создать пользователя: %w", err)
	}
	return id, nil
}

// UserByLogin возвращает пользователя по логину вместе с хешем пароля.
func (s *Store) UserByLogin(ctx context.Context, login string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, login, password_hash, role
		FROM users
		WHERE login = $1
	`, NormalizeLogin(login)).Scan(&u.ID, &u.Login, &u.PasswordHash, &u.Role)
	if err != nil {
		if isNoRows(err) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("не удалось получить пользователя: %w", err)
	}
	return u, nil
}

// UserByID возвращает пользователя по идентификатору.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, login, password_hash, role
		FROM users
		WHERE id = $1
	`, id).Scan(&u.ID, &u.Login, &u.PasswordHash, &u.Role)
	if err != nil {
		if isNoRows(err) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("не удалось получить пользователя: %w", err)
	}
	return u, nil
}

// SetPasswordHash заменяет хеш пароля.
func (s *Store) SetPasswordHash(ctx context.Context, id int64, passwordHash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, passwordHash, id)
	if err != nil {
		return fmt.Errorf("не удалось обновить пароль: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveRefreshToken сохраняет хеш выданного refresh-токена.
func (s *Store) SaveRefreshToken(ctx context.Context, userID int64, familyID, tokenHash string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, familyID, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("не удалось сохранить refresh-токен: %w", err)
	}
	return nil
}

// ErrRefreshReused возвращается, когда предъявлен уже отозванный токен.
type ErrRefreshReused struct {
	UserID   int64
	FamilyID string
}

func (e *ErrRefreshReused) Error() string {
	return "refresh-токен уже использован, семейство отозвано"
}

// RotateRefreshToken заменяет токен в семействе на новый.
//
// Прежний токен помечается отозванным, новый добавляется отдельной записью.
// Хеш не перезаписывается — иначе он перестал бы существовать и повторное
// предъявление старого токена стало бы неотличимым от предъявления
// несуществующего. Условие revoked_at IS NULL делает операцию идемпотентной.
func (s *Store) RotateRefreshToken(ctx context.Context, userID int64, familyID, oldHash, newHash string, expiresAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("не удалось начать транзакцию: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var rotatedID int64
	err = tx.QueryRow(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = now(), rotated_at = now()
		WHERE token_hash = $1 AND user_id = $2 AND family_id = $3 AND revoked_at IS NULL
		RETURNING id
	`, oldHash, userID, familyID).Scan(&rotatedID)
	if err != nil {
		if !isNoRows(err) {
			return fmt.Errorf("не удалось отозвать предыдущий токен: %w", err)
		}
		var exists bool
		qErr := tx.QueryRow(ctx,
			`SELECT TRUE FROM refresh_tokens WHERE token_hash = $1 AND user_id = $2`,
			oldHash, userID).Scan(&exists)
		switch {
		case qErr != nil && !isNoRows(qErr):
			return fmt.Errorf("не удалось проверить состояние токена: %w", qErr)
		case exists:
			return &ErrRefreshReused{UserID: userID, FamilyID: familyID}
		default:
			return ErrNotFound
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, familyID, newHash, expiresAt); err != nil {
		return fmt.Errorf("не удалось сохранить новый токен: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
	}
	return nil
}

// UserByRefreshHash возвращает пользователя по хешу действующего refresh-токена.
//
// Ищется именно неотозванный и не истёкший токен: подпись у refresh-токена
// нет, поэтому единственный способ его принять — наличие записи в таблице.
func (s *Store) UserByRefreshHash(ctx context.Context, tokenHash string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.login, u.password_hash, u.role
		FROM refresh_tokens rt
		JOIN users u ON u.id = rt.user_id
		WHERE rt.token_hash = $1
		  AND rt.revoked_at IS NULL
		  AND rt.expires_at > now()
	`, tokenHash).Scan(&u.ID, &u.Login, &u.PasswordHash, &u.Role)
	if err != nil {
		if isNoRows(err) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("не удалось найти пользователя по токену: %w", err)
	}
	return u, nil
}

// RevokeTokenFamily отзывает все токены семейства.
func (s *Store) RevokeTokenFamily(ctx context.Context, familyID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now()
		WHERE family_id = $1 AND revoked_at IS NULL
	`, familyID)
	if err != nil {
		return fmt.Errorf("не удалось отозвать семейство токенов: %w", err)
	}
	return nil
}

// RevokeAllUserTokens отзывает все токены пользователя.
func (s *Store) RevokeAllUserTokens(ctx context.Context, userID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	if err != nil {
		return fmt.Errorf("не удалось отозвать токены пользователя: %w", err)
	}
	return nil
}

// isUniqueViolation сообщает, что нарушено ограничение уникальности.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isNoRows сообщает, что запрос не вернул строк.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
