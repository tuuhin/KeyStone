CREATE TABLE totp_table
(
    totp_id               INTEGER PRIMARY KEY,
    user_id               INT          NOT NULL,
    is_totp_enabled       BOOLEAN      NOT NULL DEFAULT FALSE,
    totp_secret_encrypted VARCHAR(255) NOT NULL,
    created_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP    NOT NULL,

    CONSTRAINT fk_totp_table_user
        FOREIGN KEY (user_id)
            REFERENCES users_table (user_id)
            ON DELETE CASCADE
);


CREATE TABLE totp_backup_codes_table
(
    totp_backups_id       INTEGER PRIMARY KEY,
    totp_id               INTEGER      NOT NULL,
    is_used               BOOLEAN      NOT NULL DEFAULT FALSE,
    totp_backup_code_hash VARCHAR(255) NOT NULL,
    created_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_totp_backup_codes FOREIGN KEY (totp_id)
        REFERENCES totp_table (totp_id)
        ON DELETE CASCADE
);