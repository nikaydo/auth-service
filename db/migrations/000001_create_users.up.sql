-- Пользователи.
--
-- Логины приводятся к нижнему регистру и не должны содержать пробелов.
-- Именно поэтому login = lower(login): иначе "User" и "user" были бы разными
-- учётными записями, а регистрация с заглавной буквы падала бы.
CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    login         TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_login_normalized CHECK (login = lower(login))
);

CREATE UNIQUE INDEX users_login_key ON users (lower(login));
