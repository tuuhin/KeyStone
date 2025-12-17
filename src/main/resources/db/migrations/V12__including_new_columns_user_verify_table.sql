CREATE TABLE user_verify_info_table_modified
(
    _id                   INTEGER PRIMARY KEY,
    user_id               INTEGER NOT NULL UNIQUE,
    is_verified           BOOLEAN DEFAULT FALSE,
    resend_email_key_hash VARCHAR(255),
    is_key_valid          BOOLEAN DEFAULT FALSE,
    pending_email         VARCHAR(128),
    pending_email_expiry  TIMESTAMP,

    FOREIGN KEY (user_id)
        REFERENCES users_table (user_id)
        ON DELETE CASCADE
);


INSERT INTO user_verify_info_table_modified (_id, user_id, is_verified, resend_email_key_hash, is_key_valid)
SELECT _id,
       user_id,
       is_verified,
       resend_email_key_hash,
       is_key_valid
FROM user_verify_info_table;

DROP TABLE user_verify_info_table;

ALTER TABLE user_verify_info_table_modified RENAME TO user_verify_info_table;
