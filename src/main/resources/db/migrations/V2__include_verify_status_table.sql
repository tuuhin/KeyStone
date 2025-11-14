
ALTER TABLE users_table DROP COLUMN is_verified;

CREATE TABLE user_verify_info_table (
    _id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE,
    is_verified BOOLEAN DEFAULT FALSE,
    resend_email_key_hash VARCHAR(255),

    FOREIGN KEY (user_id)
    REFERENCES users_table (user_id)
    ON DELETE CASCADE
);
