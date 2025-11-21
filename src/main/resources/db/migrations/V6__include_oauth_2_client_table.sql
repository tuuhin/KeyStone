-- Create OAuth2 clients table

CREATE TABLE oauth_2_client_table (
    _id INTEGER PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255),
    client_name VARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    is_valid BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,

    CONSTRAINT fk_oauth2_client_table_user
        FOREIGN KEY (user_id)
        REFERENCES users_table (user_id)
        ON DELETE CASCADE
);

-- Extra tables for redirect uris ,scopes
CREATE TABLE oauth_2_client_redirect_uris_table (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    redirects VARCHAR(255) NOT NULL,

    CONSTRAINT fk_redirect_uris_client
        FOREIGN KEY (client_id)
        REFERENCES oauth_2_client_table (client_id)
        ON DELETE CASCADE
);


CREATE TABLE oauth_2_client_scopes_table (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    scope VARCHAR(255) NOT NULL,

    CONSTRAINT fk_scopes_client
        FOREIGN KEY (client_id)
         REFERENCES oauth_2_client_table (client_id)
        ON DELETE CASCADE
);

CREATE TABLE oauth_2_client_grant_types_table (
    id BIGSERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    grant_type VARCHAR(255) NOT NULL,

    CONSTRAINT fk_grant_types_client
        FOREIGN KEY (client_id)
         REFERENCES oauth_2_client_table (client_id)
        ON DELETE CASCADE
);
