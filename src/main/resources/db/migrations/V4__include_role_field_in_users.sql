CREATE TABLE users_new (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(255) NOT NULL ,
    p_word VARCHAR(255) NOT NULL,
    user_name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL,
    role VARCHAR(128) NOT NULL DEFAULT 'USER'
);


INSERT INTO users_new (user_id,email,p_word,user_name,created_at)
SELECT
    user_id,
    email,
    p_word,
    user_name,
    created_at
FROM users_table;

DROP TABLE users_table;

ALTER TABLE users_new RENAME TO users;
