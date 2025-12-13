CREATE TABLE users_new
(
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    email         VARCHAR(255) NOT NULL,
    p_word        VARCHAR(255) NOT NULL,
    user_name     VARCHAR(255) NOT NULL UNIQUE,
    created_at    TIMESTAMP    NOT NULL,
    updated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role          VARCHAR(128) NOT NULL DEFAULT 'USER',
    token_version INTEGER      NOT NULL DEFAULT 0
);


INSERT INTO users_new (user_id, email, p_word, user_name, created_at, role)
SELECT user_id,
       email,
       p_word,
       user_name,
       created_at,
       role
FROM users_table;

DROP TABLE users_table;

ALTER TABLE users_new RENAME TO users_table;
