package keystore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// MySQLOptions configures TLS and driver safety options for a node's MySQL store.
type MySQLOptions struct {
	TLSMode string // "", "true", "preferred", "skip-verify", "false"
	CAFile  string // optional PEM CA file for custom MySQL server verification
}

// OpenMySQL opens a node-isolated MySQL database using a raw DSN and validates node ownership.
func OpenMySQL(dsn, partyID string) (*Store, error) {
	return OpenMySQLWithOptions(dsn, partyID, MySQLOptions{})
}

// OpenMySQLWithOptions opens a node-isolated MySQL database with explicit TLS options.
func OpenMySQLWithOptions(dsn, partyID string, opts MySQLOptions) (*Store, error) {
	cfg, err := buildMySQLConfig(dsn, partyID, opts)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect mysql: %w", err)
	}
	if err := initMySQL(ctx, db, partyID); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize mysql key database: %w", err)
	}
	return &Store{db: db, partyID: partyID, mysql: true}, nil
}

func buildMySQLConfig(dsn, partyID string, opts MySQLOptions) (*mysql.Config, error) {
	if partyID == "" {
		return nil, errors.New("party ID is required")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse mysql DSN: %w", err)
	}
	if cfg.DBName == "" {
		return nil, errors.New("mysql DSN must select a per-node database name")
	}
	// Harden driver settings regardless of caller DSN parameters.
	cfg.AllowAllFiles = false
	cfg.AllowCleartextPasswords = false
	cfg.MultiStatements = false
	cfg.ParseTime = false
	cfg.InterpolateParams = false
	cfg.ClientFoundRows = false
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.Params == nil {
		cfg.Params = make(map[string]string, 1)
	}
	for k := range cfg.Params {
		if strings.EqualFold(k, "autocommit") {
			delete(cfg.Params, k)
		}
	}
	cfg.Params["autocommit"] = "1"
	if err := applyMySQLTLS(cfg, opts); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyMySQLTLS(cfg *mysql.Config, opts MySQLOptions) error {
	mode := strings.ToLower(strings.TrimSpace(opts.TLSMode))
	if opts.CAFile != "" {
		if mode != "" && mode != "true" {
			return fmt.Errorf("mysql caFile conflicts with tlsMode %q", opts.TLSMode)
		}
		pemBytes, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return fmt.Errorf("read mysql CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return errors.New("mysql CA file contains no PEM certificate")
		}
		sum := sha256.Sum256(pemBytes)
		name := "mpc-mysql-" + hex.EncodeToString(sum[:8])
		if err := mysql.RegisterTLSConfig(name, &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}); err != nil {
			return fmt.Errorf("register mysql TLS config: %w", err)
		}
		cfg.TLSConfig = name
		cfg.AllowFallbackToPlaintext = false
		return nil
	}
	switch mode {
	case "":
		if cfg.TLSConfig == "" {
			cfg.TLSConfig = "true"
		}
	case "true", "false", "skip-verify", "preferred":
		cfg.TLSConfig = mode
	default:
		return fmt.Errorf("unsupported mysql tlsMode %q", opts.TLSMode)
	}
	cfg.AllowFallbackToPlaintext = cfg.TLSConfig == "preferred"
	return nil
}

var mysqlTables = []string{
	"node_owner",
	"key_shares",
	"ecdsa_presign_batches",
	"frost_presign_batches",
	"ecdsa_presignatures",
	"frost_presignatures",
	"reshare_sessions",
	"node_master_key",
	"session_reservations",
	"wallet_backups",
}

func initMySQL(ctx context.Context, db *sql.DB, partyID string) error {
	var autocommit int
	if err := db.QueryRowContext(ctx, "SELECT @@autocommit").Scan(&autocommit); err != nil {
		return err
	}
	if autocommit != 1 {
		return errors.New("mysql connection requires autocommit=1")
	}
	// Reject wrong-node databases before any CREATE/ALTER DDL, since MySQL DDL commits implicitly.
	if err := checkExistingMySQLNodeOwner(ctx, db, partyID); err != nil {
		return err
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS node_owner (
			id TINYINT NOT NULL PRIMARY KEY,
			party_id VARCHAR(32) NOT NULL,
			CHECK (id = 1)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS key_shares (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL DEFAULT 'default',
			algorithm VARCHAR(32) NOT NULL,
			session_id VARCHAR(191) NOT NULL,
			key_id VARCHAR(64) NOT NULL,
			threshold INT NOT NULL,
			share LONGBLOB,
			share_format TINYINT NOT NULL DEFAULT 0,
			created_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP,
			CHECK (share_format IN (0, 1)),
			UNIQUE KEY uq_key_shares_app_alg_key (application_id, algorithm, key_id),
			UNIQUE KEY uq_key_shares_app_alg_session (application_id, algorithm, session_id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS ecdsa_presign_batches (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL DEFAULT 'default',
			session_id VARCHAR(191) NOT NULL,
			key_id VARCHAR(64) NOT NULL,
			binding VARBINARY(64) NOT NULL,
			ids LONGTEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uq_ecdsa_presign_batches_app_session (application_id, session_id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS frost_presign_batches (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL DEFAULT 'default',
			session_id VARCHAR(191) NOT NULL,
			key_id VARCHAR(64) NOT NULL,
			binding VARBINARY(64) NOT NULL,
			ids LONGTEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uq_frost_presign_batches_app_session (application_id, session_id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS ecdsa_presignatures (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL DEFAULT 'default',
			presignature_id VARCHAR(128) NOT NULL,
			key_id VARCHAR(64) NOT NULL,
			share LONGBLOB NOT NULL,
			share_format TINYINT NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			CHECK (share_format IN (0, 1)),
			UNIQUE KEY uq_ecdsa_presignatures_app_presig (application_id, presignature_id),
			KEY idx_ecdsa_presignatures_app_key_id (application_id, key_id, id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS frost_presignatures (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL DEFAULT 'default',
			presignature_id VARCHAR(128) NOT NULL,
			key_id VARCHAR(64) NOT NULL,
			share LONGBLOB NOT NULL,
			share_format TINYINT NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			CHECK (share_format IN (0, 1)),
			UNIQUE KEY uq_frost_presignatures_app_presig (application_id, presignature_id),
			KEY idx_frost_presignatures_app_key_id (application_id, key_id, id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS reshare_sessions (
			application_id VARCHAR(64) NOT NULL DEFAULT 'default',
			algorithm VARCHAR(32) NOT NULL,
			session_id VARCHAR(191) NOT NULL,
			key_id VARCHAR(64) NOT NULL,
			state VARCHAR(32) NOT NULL DEFAULT 'started',
			digest VARBINARY(64),
			share LONGBLOB,
			share_format TINYINT NOT NULL DEFAULT 0,
			CHECK (share_format IN (0, 1)),
			PRIMARY KEY (application_id, algorithm, session_id),
			KEY idx_reshare_app_alg_key_state (application_id, algorithm, key_id, state)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS node_master_key (
			id TINYINT NOT NULL PRIMARY KEY,
			format_version INT NOT NULL,
			salt VARBINARY(64) NOT NULL,
			ciphertext VARBINARY(256) NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			CHECK (id = 1)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS session_reservations (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL,
			session_id VARCHAR(191) NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uq_session_reservations_app_session (application_id, session_id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
		`CREATE TABLE IF NOT EXISTS wallet_backups (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			application_id VARCHAR(64) NOT NULL,
			session_id VARCHAR(191) NOT NULL,
			wallet_id VARCHAR(64) NOT NULL,
			ecdsa_key_id VARCHAR(64),
			frost_key_id VARCHAR(64),
			manifest LONGBLOB,
			format_version INT,
			backup_key_id VARCHAR(128),
			wrapped_key LONGBLOB,
			ciphertext LONGBLOB,
			backup_request_digest VARBINARY(64),
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE KEY uq_wallet_backups_app_session (application_id, session_id),
			UNIQUE KEY uq_wallet_backups_app_wallet (application_id, wallet_id)
		) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin`,
	}
	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if err := upgradeMySQLCollations(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO node_owner (id, party_id) VALUES (1, ?) ON DUPLICATE KEY UPDATE id = id", partyID); err != nil {
		return err
	}
	var owner string
	if err := tx.QueryRowContext(ctx, "SELECT party_id FROM node_owner WHERE id = 1").Scan(&owner); err != nil {
		return err
	}
	if owner != partyID {
		return errors.New("key database belongs to a different MPC node")
	}
	return tx.Commit()
}

func upgradeMySQLCollations(ctx context.Context, db *sql.DB) error {
	for _, table := range mysqlTables {
		var collation sql.NullString
		err := db.QueryRowContext(ctx, `SELECT TABLE_COLLATION FROM information_schema.TABLES
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`, table).Scan(&collation)
		if err != nil {
			return err
		}
		if collation.String == "utf8mb4_0900_bin" {
			continue
		}
		if _, err := db.ExecContext(ctx, "ALTER TABLE `"+table+"` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin"); err != nil {
			return fmt.Errorf("upgrade %s collation: %w", table, err)
		}
	}
	return nil
}

func checkExistingMySQLNodeOwner(ctx context.Context, db *sql.DB, partyID string) error {
	var hasOwnerTable bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'node_owner'
	)`).Scan(&hasOwnerTable); err != nil {
		return err
	}
	if !hasOwnerTable {
		return nil
	}
	var owner string
	err := db.QueryRowContext(ctx, "SELECT party_id FROM node_owner WHERE id = 1").Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if owner != partyID {
		return errors.New("key database belongs to a different MPC node")
	}
	return nil
}
