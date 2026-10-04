// Package jwt выпускает и проверяет токены доступа.
//
// Используется golang-jwt v5: в отличие от v3 библиотека сама проверяет
// срок действия и алгоритм подписи, а типы ошибок позволяют отличать
// истёкший токен от недействительного без сравнения текстов.
package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/nikaydo/auth-service/internal/auth"
)

// Ошибки проверки токена.
var (
	ErrTokenExpired   = errors.New("срок действия токена истёк")
	ErrTokenInvalid   = errors.New("токен недействителен")
	ErrTokenMalformed = errors.New("токен повреждён")
	ErrUnexpectedAlg  = errors.New("неожиданный алгоритм подписи")
)

// Claims — содержимое токена.
type Claims struct {
	jwtlib.RegisteredClaims
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Manager выпускает и проверяет токены.
type Manager struct {
	secret     []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time
}

// NewManager создаёт менеджер токенов.
func NewManager(secret, issuer string, accessTTL, refreshTTL time.Duration) *Manager {
	return &Manager{
		secret:     []byte(secret),
		issuer:     issuer,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		now:        time.Now,
	}
}

// Pair — выданная пара токенов.
type Pair struct {
	AccessToken  string
	RefreshToken string
	// RefreshHash — хеш, который нужно сохранить вместо самого токена.
	RefreshHash string
	// FamilyID — семейство сессии, к которому относится токен.
	FamilyID string
	// AccessExpiresAt и RefreshExpiresAt нужны клиенту для установки cookie.
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// NewPair выпускает access-токен и описывает параметры refresh-токена.
//
// Refresh-токен непрозрачный: это случайная строка, а не JWT. Она не несёт
// утверждений, поэтому и не подписывается — единственный способ её принять
// это найти запись по хешу в таблице refresh_tokens. Случайность обеспечивает
// 256 бит энтропии, поэтому подбирать перебором токен нельзя и медленный KDF
// не нужен.
func (m *Manager) NewPair(userID int64, username, role, refreshToken, familyID string) (Pair, error) {
	now := m.now()

	accessToken, accessExp, err := m.sign(userID, username, role, m.secret, now.Add(m.accessTTL), now)
	if err != nil {
		return Pair{}, err
	}

	return Pair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshHash:      auth.HashRefreshToken(refreshToken),
		FamilyID:         familyID,
		AccessExpiresAt:  accessExp,
		RefreshExpiresAt: now.Add(m.refreshTTL),
	}, nil
}

// sign выпускает токен доступа.
//
// В claims обязательно входит jti: без него два токена, выпущенные в одну
// секунду для одного пользователя, получаются байт-в-байт одинаковыми,
// потому что подпись HMAC детерминирована. Из-за этого отозванный токен и
// выданный следом «новый» совпали бы, а в логах невозможно было бы связать
// запрос с выдачей.
func (m *Manager) sign(userID int64, username, role string, secret []byte, expiresAt, now time.Time) (string, time.Time, error) {
	tokenID, err := newTokenID()
	if err != nil {
		return "", time.Time{}, err
	}

	claims := Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			ID:        tokenID,
			Subject:   fmt.Sprintf("%d", userID),
			Issuer:    m.issuer,
			Audience:  jwtlib.ClaimStrings{m.issuer},
			IssuedAt:  jwtlib.NewNumericDate(now),
			NotBefore: jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(expiresAt),
		},
		Username: username,
		Role:     role,
	}

	signed, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("не удалось подписать токен: %w", err)
	}
	return signed, expiresAt, nil
}

// ParseAccess проверяет access-токен.
func (m *Manager) ParseAccess(tokenString string) (userID int64, username, role string, err error) {
	claims, err := m.parse(tokenString, m.secret)
	if err != nil {
		return 0, "", "", err
	}
	id, err := parseUserID(claims.Subject)
	if err != nil {
		return 0, "", "", err
	}
	return id, claims.Username, claims.Role, nil
}

// parse проверяет токен общим кодом.
func (m *Manager) parse(tokenString string, secret []byte) (*Claims, error) {
	claims := &Claims{}

	parsed, err := jwtlib.ParseWithClaims(
		tokenString,
		claims,
		func(t *jwtlib.Token) (any, error) {
			// Алгоритм проверяется явно: без этой проверки библиотека
			// приняла бы токен с alg=none или с другим ключом.
			if _, ok := t.Method.(*jwtlib.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedAlg
			}
			return secret, nil
		},
		jwtlib.WithValidMethods([]string{jwtlib.SigningMethodHS256.Alg()}),
		jwtlib.WithIssuer(m.issuer),
		jwtlib.WithAudience(m.issuer),
		jwtlib.WithExpirationRequired(),
		jwtlib.WithIssuedAt(),
		// Проверка срока идёт по времени Manager, а не по системным часам
		// библиотеки: так время контролируется в тестах и в коде.
		jwtlib.WithTimeFunc(m.now),
	)
	if err != nil {
		switch {
		case errors.Is(err, jwtlib.ErrTokenExpired), errors.Is(err, jwtlib.ErrTokenNotValidYet):
			return nil, ErrTokenExpired
		case errors.Is(err, ErrUnexpectedAlg):
			return nil, ErrUnexpectedAlg
		case errors.Is(err, jwtlib.ErrTokenMalformed), errors.Is(err, jwtlib.ErrSignatureInvalid):
			return nil, ErrTokenInvalid
		default:
			return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
		}
	}
	if !parsed.Valid || claims.Subject == "" {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}

// newTokenID возвращает случайный идентификатор токена.
func newTokenID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("не удалось сгенерировать идентификатор токена: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// parseUserID разбирает идентификатор пользователя из claim.
func parseUserID(subject string) (int64, error) {
	id, err := strconv.ParseInt(subject, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: некорректный идентификатор пользователя", ErrTokenInvalid)
	}
	return id, nil
}
