-- Create extension for UUID if not exists (PostgreSQL)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    login VARCHAR(255) UNIQUE NOT NULL CHECK (LENGTH(login) >= 8 AND login ~ '^[a-zA-Z0-9]+$'),
    password_hash TEXT NOT NULL, -- Store hashed password
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Documents table
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(255),
    is_file BOOLEAN NOT NULL DEFAULT FALSE,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    json_data JSONB, -- For storing JSON metadata
    file_path TEXT, -- Path to the file on disk (or could be binary data in a column)
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster document lookups by owner
CREATE INDEX IF NOT EXISTS idx_documents_owner_id ON documents(owner_id);

-- Grants table (many-to-many relationship between documents and users they are shared with)
CREATE TABLE IF NOT EXISTS document_grants (
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_login VARCHAR(255) NOT NULL REFERENCES users(login) ON DELETE CASCADE,
    PRIMARY KEY (document_id, user_login)
);

-- Index for faster grant lookups
CREATE INDEX IF NOT EXISTS idx_document_grants_user_login ON document_grants(user_login);

-- Sessions/Tokens table (for storing active JWT tokens or refresh tokens if needed)
-- For simplicity, we'll rely on JWT expiration. If logout needs to be immediate,
-- a token blacklist table would be needed.
-- CREATE TABLE IF NOT EXISTS user_sessions (
--     token_hash TEXT PRIMARY KEY, -- Store hash of token to prevent lookup by full token
--     user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--     expires_at TIMESTAMP NOT NULL
-- );
