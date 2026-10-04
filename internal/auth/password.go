// Package auth отвечает за проверку паролей и refresh-токенов.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidCredentials — общий ответ на неверный логин или пароль.
//
// Не различаем случаи «пользователя нет» и «пароль не подходит»: различие
// в сообщении позволяет перебирать существующие логины.
var ErrInvalidCredentials = errors.New("неверный логин или пароль")

// PasswordHasher хеширует и проверяет пароли.
type PasswordHasher struct {
	// cost — стоимость bcrypt. Вынесена в структуру, чтобы тесты могли
	// снизить её: при стоимости по умолчанию каждый тест занимает сотни
	// миллисекунд.
	cost int
}

// NewPasswordHasher создаёт хешировщик с указанной стоимостью.
func NewPasswordHasher(cost int) *PasswordHasher {
	if cost < bcrypt.MinCost {
		cost = bcrypt.MinCost
	}
	if cost > bcrypt.MaxCost {
		cost = bcrypt.MaxCost
	}
	return &PasswordHasher{cost: cost}
}

// Hash возвращает bcrypt-хеш пароля.
func (h *PasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("пароль не может быть пустым")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("не удалось захешировать пароль: %w", err)
	}
	return string(hashed), nil
}

// Verify сверяет пароль с хешем из базы.
func (h *PasswordHasher) Verify(hashed, password string) bool {
	if hashed == "" || password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil
}

// dummyHash — настоящий bcrypt-хеш, посчитанный со стоимостью 12.
//
// Нужен для выравнивания времени ответа: при входе с несуществующим логином
// проверка идёт против него, иначе такой запрос возвращался бы заметно быстрее
// и по времени можно было бы перебирать существующие учётные записи.
var dummyHash = []byte("$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

// DummyVerify выполняет фиктивную проверку пароля.
func DummyVerify(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}

// NewRefreshToken возвращает новый refresh-токен, его хеш и идентификатор семейства.
//
// Токен имеет вид "<семейство>.<секрет>": семейство хранится в открытом виде,
// по нему идёт поиск записи, а секрет сверяется по хешу.
func NewRefreshToken() (token, hash, family string, err error) {
	fam := make([]byte, 16)
	if _, err := rand.Read(fam); err != nil {
		return "", "", "", fmt.Errorf("не удалось сгенерировать семейство: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", "", "", fmt.Errorf("не удалось сгенерировать токен: %w", err)
	}
	family = base64.RawURLEncoding.EncodeToString(fam)
	token = family + "." + base64.RawURLEncoding.EncodeToString(secret)

	return token, HashRefreshToken(token), family, nil
}

// HashRefreshToken возвращает SHA-256 хеш токена.
//
// SHA-256 здесь уместен: токен — не пароль, а случайная строка из 256 бит
// энтропии, которую перебором не подобрать, поэтому медленный KDF не нужен.
func HashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MatchesRefreshToken проверяет токен по хешу за постоянное время.
func MatchesRefreshToken(hash, token string) bool {
	if hash == "" || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(HashRefreshToken(token)), []byte(hash)) == 1
}
