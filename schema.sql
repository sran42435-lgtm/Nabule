-- schema.sql
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    db_type TEXT,
    vulnerable BOOLEAN DEFAULT 0,
    tables_found TEXT,
    waf_detected TEXT,
    tech_stack TEXT,
    forms_found TEXT,
    inserted_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
