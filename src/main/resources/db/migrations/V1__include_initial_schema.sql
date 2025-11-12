CREATE TABLE users_table (
    user_id BIGINT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    p_word VARCHAR(255) NOT NULL,
    user_name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE users_profile (
    profile_id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    bio VARCHAR(512),
    full_name VARCHAR(255),
    avatar_url VARCHAR(255),

        FOREIGN KEY (user_id)
        REFERENCES users_table (user_id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_users_email ON users_table (email);