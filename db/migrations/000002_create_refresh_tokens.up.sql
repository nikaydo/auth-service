-- Refresh-токены.
--
-- Хранится только хеш: утечка базы не даёт войти под пользователем, потому
-- что сам токен ещё нужно предъявить. Токен непрозрачный, поэтому запись в
-- таблице — единственный способ его принять.
--
-- family_id связывает все токены одной сессии. При попытке воспользоваться
-- уже отозванным токеном отзывается всё семейство: это защита от повторного
-- использования токена после его утечки.
--
-- Ротация не перезаписывает token_hash, а добавляет новую запись и помечает
-- прежнюю отозванной. Благодаря этому хеш предъявленного токена остаётся в
-- базе и его повторное предъявление можно распознать.
CREATE TABLE refresh_tokens (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id  TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX refresh_tokens_hash_key ON refresh_tokens (token_hash);

CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id) WHERE revoked_at IS NULL;

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id) WHERE revoked_at IS NULL;

CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);
