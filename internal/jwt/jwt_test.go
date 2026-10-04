package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/nikaydo/auth-service/internal/auth"
)

const (
	testSecret = "secret-for-tests-0123456789-0123456789"
	testIssuer = "test-issuer"
)

func newTestManager() *Manager {
	return NewManager(testSecret, testIssuer, time.Hour, 30*24*time.Hour)
}

func TestNewPair(t *testing.T) {
	m := newTestManager()

	refreshToken, _, family, err := auth.NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}

	pair, err := m.NewPair(42, "nikaydo", "user", refreshToken, family)
	if err != nil {
		t.Fatalf("NewPair вернул ошибку: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("access-токен пуст")
	}
	if pair.RefreshToken != refreshToken {
		t.Error("refresh-токен не совпадает с переданным")
	}
	if pair.RefreshHash != auth.HashRefreshToken(refreshToken) {
		t.Error("хеш refresh-токена неверный")
	}
	if pair.FamilyID != family {
		t.Errorf("FamilyID = %q, ожидалось %q", pair.FamilyID, family)
	}
	if !pair.AccessExpiresAt.After(time.Now()) {
		t.Errorf("срок access-токена уже истёк: %v", pair.AccessExpiresAt)
	}
	if pair.RefreshExpiresAt.Sub(pair.AccessExpiresAt) < 24*time.Hour {
		t.Errorf("refresh-токен должен жить заметно дольше access: %v", pair.RefreshExpiresAt.Sub(pair.AccessExpiresAt))
	}
}

func TestParseAccess(t *testing.T) {
	m := newTestManager()

	refreshToken, _, family, err := auth.NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	pair, err := m.NewPair(42, "nikaydo", "user", refreshToken, family)
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}

	id, login, role, err := m.ParseAccess(pair.AccessToken)
	if err != nil {
		t.Fatalf("ParseAccess вернул ошибку: %v", err)
	}
	if id != 42 {
		t.Errorf("id = %d, ожидалось 42", id)
	}
	if login != "nikaydo" {
		t.Errorf("login = %q", login)
	}
	if role != "user" {
		t.Errorf("role = %q", role)
	}
}

func TestParseAccessRejectsWrongSecret(t *testing.T) {
	refreshToken, _, family, _ := auth.NewRefreshToken()
	pair, err := newTestManager().NewPair(42, "nikaydo", "user", refreshToken, family)
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}

	other := NewManager("other-secret-0123456789-0123456789", testIssuer, time.Hour, time.Hour)
	if _, _, _, err := other.ParseAccess(pair.AccessToken); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("ожидалась ErrTokenInvalid, получено %v", err)
	}
}

func TestParseAccessRejectsWrongIssuer(t *testing.T) {
	refreshToken, _, family, _ := auth.NewRefreshToken()
	pair, _ := newTestManager().NewPair(42, "nikaydo", "user", refreshToken, family)

	other := NewManager(testSecret, "someone-else", time.Hour, time.Hour)
	if _, _, _, err := other.ParseAccess(pair.AccessToken); err == nil {
		t.Fatal("токен с чужим issuer не должен приниматься")
	}
}

func TestParseAccessDetectsExpired(t *testing.T) {
	m := newTestManager()
	refreshToken, _, family, _ := auth.NewRefreshToken()
	pair, _ := m.NewPair(42, "nikaydo", "user", refreshToken, family)

	// Сдвигаем время вперёд: токен, выпущенный час назад, истёк.
	m.now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	// В исходной версии истечение определялось сравнением текста ошибки
	// ("Token is expired"), что ломалось при смене версии библиотеки.
	if _, _, _, err := m.ParseAccess(pair.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("ожидалась ErrTokenExpired, получено %v", err)
	}
}

func TestParseAccessRejectsNoneAlgorithm(t *testing.T) {
	// Токен с alg=none — классическая атака на подмену алгоритма: без
	// проверки алгоритма подпись не сверяется вовсе.
	const noneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiI0MiIsInVzZXJuYW1lIjoieCJ9."

	if _, _, _, err := newTestManager().ParseAccess(noneToken); err == nil {
		t.Fatal("токен с alg=none не должен приниматься")
	}
}

func TestParseAccessRejectsMalformed(t *testing.T) {
	m := newTestManager()

	for _, token := range []string{
		"",
		"просто-текст",
		"aaa.bbb",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.мусор",
	} {
		if _, _, _, err := m.ParseAccess(token); err == nil {
			t.Errorf("токен %q не должен приниматься", token)
		}
	}
}

func TestAccessTokensAreUnique(t *testing.T) {
	m := newTestManager()

	seen := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		refreshToken, _, family, _ := auth.NewRefreshToken()
		pair, _ := m.NewPair(42, "nikaydo", "user", refreshToken, family)
		if _, dup := seen[pair.AccessToken]; dup {
			t.Fatal("токен повторился")
		}
		seen[pair.AccessToken] = struct{}{}
	}
}
