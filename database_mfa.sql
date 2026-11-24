-- ═══════════════════════════════════════════════════════════════
--  2FA + Fingerprint (WebAuthn) + brute-force protection
--  Run once on your database (MySQL / MariaDB).
-- ═══════════════════════════════════════════════════════════════

ALTER TABLE users
    ADD COLUMN totp_secret        VARCHAR(255) NULL,
    ADD COLUMN totp_enabled       TINYINT(1)   NOT NULL DEFAULT 0,
    ADD COLUMN totp_last_step     BIGINT       NULL,
    ADD COLUMN webauthn_prompted  TINYINT(1)   NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS user_backup_codes (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    code_hash  CHAR(64) NOT NULL,
    used_at    DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backup_lookup (user_id, code_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL,
    credential_id VARCHAR(700) CHARACTER SET ascii NOT NULL,   -- base64 of raw credential id
    public_key    TEXT NOT NULL,                               -- PEM
    sign_count    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    label         VARCHAR(100) NOT NULL DEFAULT 'This device',
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  DATETIME NULL,
    UNIQUE KEY uq_credential (credential_id),
    INDEX idx_wa_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_attempts (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(100) NOT NULL,
    user_id    INT NULL,
    ip         VARCHAR(45) NOT NULL,
    type       ENUM('password','mfa') NOT NULL,
    success    TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_window (username, type, created_at),
    INDEX idx_ip_window (ip, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── ADMIN RESET (user lost phone / device) — replace 123 with the user's id ──
-- UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=NULL, webauthn_prompted=0 WHERE id=123;
-- DELETE FROM webauthn_credentials WHERE user_id=123;
-- DELETE FROM user_backup_codes   WHERE user_id=123;
