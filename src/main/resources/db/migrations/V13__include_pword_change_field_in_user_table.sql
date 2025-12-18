CREATE TABLE users_modified
(
    user_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    email                   VARCHAR(255) NOT NULL,
    p_word                  VARCHAR(255) NOT NULL,
    user_name               VARCHAR(255) NOT NULL UNIQUE,
    created_at              TIMESTAMP    NOT NULL,
    updated_at              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    role                    VARCHAR(128) NOT NULL DEFAULT 'USER',
    token_version           INTEGER      NOT NULL DEFAULT 0,
    p_word_change_timestamp TIMESTAMP
);


INSERT INTO users_modified (user_id, email, p_word, user_name, created_at, updated_at, role, token_version)
SELECT user_id,
       email,
       p_word,
       user_name,
       created_at,
       updated_at,
       role,
       token_version
FROM users_table;

DROP TABLE users_table;

ALTER TABLE users_modified
    RENAME TO users_table;
