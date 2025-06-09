package database

import (
	"context"
	"database/sql"
	"main/internal/config"
	"main/internal/models"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type UserDB struct {
	UserBD *sql.DB
	ENV    config.Env
}

func DatabaseInit(Env config.Env) (UserDB, error) {
	var err error
	DB, err := sql.Open("pgx", Env.EnvMap["DATABASE_URL"])
	if err != nil {
		return UserDB{}, err
	}
	if err = DB.Ping(); err != nil {
		return UserDB{}, err
	}
	u := UserDB{UserBD: DB, ENV: Env}
	err = u.Tables()
	if err != nil {
		return u, err
	}
	return u, nil
}

func (u *UserDB) Tables() error {
	_, err := u.UserBD.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		login TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		refresh_token TEXT NOT NULL
		);`)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserDB) CreateUser(Login, Pass string) (int64, error) {
	_, err := u.UserBD.ExecContext(context.Background(), `
		INSERT INTO users (login,password,refresh_token)
		VALUES ($1,$2,$3);`, Login, Pass, "")
	if err != nil {
		return 0, err
	}
	return int64(1), nil
}

func (u *UserDB) CheckUser(Login, Pass string, pass bool) (models.User, error) {
	var err error
	var user models.User
	if pass {
		err = u.UserBD.QueryRowContext(context.Background(), `SELECT * FROM users WHERE login = $1 AND password = $2;`, Login, Pass).Scan(&user.Id, &user.Login, &user.Pass, &user.RefreshToken)
	} else {
		err = u.UserBD.QueryRowContext(context.Background(), `SELECT * FROM users WHERE login = $1;`, Login).Scan(&user.Id, &user.Login, &user.Pass, &user.RefreshToken)
	}
	if err != nil {
		return user, err
	}
	return user, nil
}

func (u *UserDB) UpdateUser(login string, t string) error {
	_, err := u.UserBD.ExecContext(context.Background(), `UPDATE users SET refresh_token = $1 WHERE login = $2;`, t, login)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserDB) DeleteUser() {

}
