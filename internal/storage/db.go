package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB with application-level helpers.
type DB struct {
	conn *sql.DB
}

// Open opens (or creates) the SQLite database at path.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.configure(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

// OpenMemory opens an in-memory SQLite database (for testing).
func OpenMemory() (*DB, error) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("opening in-memory sqlite: %w", err)
	}
	db := &DB{conn: conn}
	if err := db.configure(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) configure() error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.conn.Exec(p); err != nil {
			return fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	return nil
}

func (db *DB) migrate() error {
	schema := `
-- One row per (iam_role, privilege) pair. The UNIQUE constraint lets the
-- INSERT upsert update the timestamp and call_count on conflict, keeping
-- the table bounded to the set of distinct role-privilege pairs ever seen.
CREATE TABLE IF NOT EXISTS privilege_usage (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  INTEGER NOT NULL,
    iam_role   TEXT    NOT NULL,
    privilege  TEXT    NOT NULL,
    call_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(iam_role, privilege)
);

CREATE INDEX IF NOT EXISTS idx_privilege_usage_role
    ON privilege_usage (iam_role);

CREATE INDEX IF NOT EXISTS idx_privilege_usage_timestamp
    ON privilege_usage (timestamp);

CREATE TABLE IF NOT EXISTS analysis_results (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_date        INTEGER NOT NULL,
    iam_role             TEXT    NOT NULL,
    assigned_privileges  TEXT    NOT NULL,
    used_privileges      TEXT    NOT NULL,
    unused_privileges    TEXT    NOT NULL,
    risk_level           TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analysis_results_role
    ON analysis_results (iam_role);

CREATE INDEX IF NOT EXISTS idx_analysis_results_date
    ON analysis_results (analysis_date);
`
	if _, err := db.conn.Exec(schema); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Conn exposes the raw *sql.DB for queries that need it.
func (db *DB) Conn() *sql.DB {
	return db.conn
}
