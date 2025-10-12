CREATE TABLE reports (
    uuid            TEXT NOT NULL PRIMARY KEY,
    user_uuid       TEXT,
    org_uuid        TEXT,
    exposed_count   INTEGER NOT NULL,
    created_at      DATETIME NOT NULL,
    last_updated_at DATETIME NOT NULL,
    
    FOREIGN KEY (user_uuid) REFERENCES users (uuid),
    FOREIGN KEY (org_uuid) REFERENCES organizations (uuid)
);