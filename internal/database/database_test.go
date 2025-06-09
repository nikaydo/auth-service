package database

import (
	"log"
	"os"
	"testing"

	"main/internal/config"
)

var db UserDB

func TestMain(m *testing.M) {
	env := config.Env{
		EnvMap: map[string]string{
			"POSTGRESS_URL": "postgres://postgres:postgres@localhost:15432/testdb?sslmode=disable",
		},
	}
	var err error
	db, err = DatabaseInit(env)
	if err != nil {
		log.Fatalf("failed to init database: %v", err)
	}
	code := m.Run()
	os.Exit(code)
}

func TestCreateAndCheckUser(t *testing.T) {
	login := "testuser"
	pass := "testpass"

	_, err := db.CreateUser(login, pass)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	user, err := db.CheckUser(login, "", false)
	if err != nil {
		t.Fatalf("failed to get user by login: %v", err)
	}
	if user.Login != login {
		t.Errorf("expected login %s, got %s", login, user.Login)
	}

	user2, err := db.CheckUser(login, pass, true)
	if err != nil {
		t.Fatalf("failed to get user by login/pass: %v", err)
	}
	if user2.Pass != pass {
		t.Errorf("expected pass %s, got %s", pass, user2.Pass)
	}
}

func TestUpdateUser(t *testing.T) {
	login := "testuser"
	newToken := "refreshtoken123"

	err := db.UpdateUser(login, newToken)
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	user, err := db.CheckUser(login, "", false)
	if err != nil {
		t.Fatalf("failed to get user after update: %v", err)
	}
	if user.RefreshToken != newToken {
		t.Errorf("expected token %s, got %s", newToken, user.RefreshToken)
	}
}
