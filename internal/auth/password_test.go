package auth

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Границы стоимости вынесены в константы, чтобы тесты и сам пакет
// использовали одни и те же значения.
const (
	minCost = bcrypt.MinCost
	maxCost = bcrypt.MaxCost
)

// testHasher возвращает хешировщик с минимальной стоимостью.
//
// При стоимости по умолчанию каждый хеш занимает около 250 мс, и набор тестов
// растягивается на десятки секунд. Проверяемая логика от стоимости не зависит.
func testHasher() *PasswordHasher {
	return NewPasswordHasher(minCost)
}

func TestHashAndVerify(t *testing.T) {
	h := testHasher()

	hash, err := h.Hash("correct-horse-battery")
	if err != nil {
		t.Fatalf("Hash вернул ошибку: %v", err)
	}
	if hash == "correct-horse-battery" {
		t.Fatal("пароль сохранён в открытом виде")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("ожидался bcrypt-хеш, получено %q", hash)
	}
	if !h.Verify(hash, "correct-horse-battery") {
		t.Error("верный пароль не прошёл проверку")
	}
	if h.Verify(hash, "wrong-password") {
		t.Error("неверный пароль прошёл проверку")
	}
}

func TestHashIsSalted(t *testing.T) {
	h := testHasher()
	const password = "correct-horse-battery"

	first, err := h.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := h.Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// Соль в bcrypt встроена, поэтому хеши одного пароля различаются.
	// Одинаковые хеши означали бы, что соль не используется.
	if first == second {
		t.Fatal("два хеша одного пароля совпали: соль не работает")
	}
}

func TestHashRejectsEmpty(t *testing.T) {
	h := testHasher()
	if _, err := h.Hash(""); err == nil {
		t.Fatal("Hash должен отклонять пустой пароль")
	}
}

func TestVerifyRejectsEmptyInputs(t *testing.T) {
	h := testHasher()

	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if h.Verify("", "password123") {
		t.Error("пустой хеш не должен проходить проверку")
	}
	if h.Verify(hash, "") {
		t.Error("пустой пароль не должен проходить проверку")
	}
}

func TestCostIsClamped(t *testing.T) {
	// Слишком низкая стоимость приводится к минимуму, слишком высокая — к
	// максимуму, иначе bcrypt вернул бы ошибку.
	if got := NewPasswordHasher(1).cost; got != minCost {
		t.Errorf("стоимость 1 превратилась в %d, ожидался %d", got, minCost)
	}
	if got := NewPasswordHasher(100).cost; got != maxCost {
		t.Errorf("стоимость 100 превратилась в %d, ожидался %d", got, maxCost)
	}
}

func TestNewRefreshTokenShape(t *testing.T) {
	token, hash, family, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken вернул ошибку: %v", err)
	}

	if !strings.HasPrefix(token, family+".") {
		t.Fatalf("токен %q должен начинаться с семейства %q", token, family)
	}
	if hash == token {
		t.Fatal("хеш совпадает с самим токеном")
	}
	if HashRefreshToken(token) != hash {
		t.Fatal("хеш не воспроизводится")
	}

	secret := strings.TrimPrefix(token, family+".")
	if len(secret) < 40 {
		t.Errorf("секретная часть слишком короткая: %d символов", len(secret))
	}
}

func TestNewRefreshTokenIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 100; i++ {
		token, _, family, err := NewRefreshToken()
		if err != nil {
			t.Fatalf("NewRefreshToken: %v", err)
		}
		if _, dup := seen[token]; dup {
			t.Fatalf("токен повторился на итерации %d", i)
		}
		if _, dup := seen[family]; dup {
			t.Fatalf("семейство повторилось на итерации %d", i)
		}
		seen[token] = struct{}{}
		seen[family] = struct{}{}
	}
}

func TestMatchesRefreshToken(t *testing.T) {
	token, hash, _, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}

	if !MatchesRefreshToken(hash, token) {
		t.Error("верный токен должен совпадать со своим хешем")
	}
	if MatchesRefreshToken(hash, token+"x") {
		t.Error("изменённый токен не должен совпадать")
	}
	if MatchesRefreshToken("", token) {
		t.Error("пустой хеш не должен совпадать ни с чем")
	}
	if MatchesRefreshToken(hash, "") {
		t.Error("пустой токен не должен совпадать")
	}
}

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	DummyVerify("")
	DummyVerify("anything")
}
