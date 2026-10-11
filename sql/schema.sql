-- =====================================================================
-- Medical Image Encryption & Secure Sharing - MySQL 8.0 schema
-- =====================================================================
-- Target engine : MySQL 8.0.x (InnoDB, utf8mb4)
-- This database stores ACCOUNTS, TRANSFER METADATA, PROTECTED (wrapped)
-- key material and AUDIT EVENTS only.
--
-- It NEVER stores:
--   * medical image plaintext (images are encrypted before transfer and
--     the ciphertext is kept in a dedicated storage directory outside
--     the application tree),
--   * plaintext encryption keys,
--   * private keys (those live only in PKCS#12 keystores on the
--     recipient machines / the protected keystore directory).
--
-- Setup (see README.md for details):
--   sudo mysql -e "CREATE DATABASE medical_security CHARACTER SET utf8mb4 \
--         COLLATE utf8mb4_unicode_ci;"
--   sudo mysql -e "CREATE USER 'medsec'@'localhost' IDENTIFIED BY '<password>'; \
--         GRANT ALL ON medical_security.* TO 'medsec'@'localhost';"
--   mysql -u medsec -p medical_security < sql/schema.sql
-- =====================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- ---------------------------------------------------------------------
-- users: one row per account. Passwords are stored as salted hashes
-- (Argon2id when Bouncy Castle is present, otherwise PBKDF2-HMAC-SHA512).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name     VARCHAR(120) NOT NULL,
    role          VARCHAR(24)  NOT NULL COMMENT 'ADMIN | DOCTOR | SPECIALIST',
    active        TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT uk_users_username UNIQUE (username),
    INDEX idx_users_role (role),
    INDEX idx_users_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- user_public_keys: public key metadata for recipients (and any user who
-- may receive transfers). Only PUBLIC key material is stored here; the
-- matching private key is kept in a PKCS#12 keystore and is never
-- exported through the UI, database or network protocol.
-- key_version allows future re-keying of a user.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_public_keys (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    user_id       BIGINT       NOT NULL,
    algorithm     VARCHAR(64)  NOT NULL DEFAULT 'RSA',
    key_size_bits INT          NOT NULL DEFAULT 2048,
    public_key    VARBINARY(2048) NOT NULL COMMENT 'X.509 SubjectPublicKeyInfo (DER)',
    key_version   INT          NOT NULL DEFAULT 1,
    keystore_ref  VARCHAR(255) NULL COMMENT 'keystore file alias/path reference, no secrets',
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT fk_upk_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uk_upk_user_version UNIQUE (user_id, key_version),
    INDEX idx_upk_algorithm (algorithm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- image_transfers: one row per transfer, keyed by an application-level
-- UUID (replay resistant: the UUID is unique and every state change is
-- an explicit, validated transition).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS image_transfers (
    id               BIGINT       NOT NULL AUTO_INCREMENT,
    transfer_id      CHAR(36)     NOT NULL COMMENT 'UUID generated before encryption',
    sender_id        BIGINT       NOT NULL,
    recipient_id     BIGINT       NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    content_type     VARCHAR(64)  NULL,
    plaintext_size   BIGINT       NOT NULL,
    ciphertext_size  BIGINT       NOT NULL,
    plaintext_sha256 CHAR(64)     NOT NULL COMMENT 'hex digest of the original bytes (integrity check)',
    algorithm        VARCHAR(64)  NOT NULL COMMENT 'e.g. AES/GCM/NoPadding',
    key_size_bits    INT          NOT NULL DEFAULT 256,
    nonce            VARBINARY(16) NOT NULL COMMENT 'GCM nonce/IV, unique per encryption',
    tag_bits         INT          NOT NULL DEFAULT 128,
    status           VARCHAR(24)  NOT NULL COMMENT 'PENDING|ENCRYPTING|SENDING|RECEIVED|VERIFIED|DECRYPTED|FAILED|REJECTED',
    storage_ref      VARCHAR(512) NULL COMMENT 'relative path of the encrypted payload in secure storage',
    error_detail     VARCHAR(255) NULL,
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                   ON UPDATE CURRENT_TIMESTAMP(6),
    received_at      DATETIME(6)  NULL,
    completed_at     DATETIME(6)  NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_transfers_uuid UNIQUE (transfer_id),
    CONSTRAINT fk_transfers_sender FOREIGN KEY (sender_id) REFERENCES users (id),
    CONSTRAINT fk_transfers_recipient FOREIGN KEY (recipient_id) REFERENCES users (id),
    INDEX idx_transfers_recipient (recipient_id, status),
    INDEX idx_transfers_sender (sender_id, status),
    INDEX idx_transfers_status (status),
    INDEX idx_transfers_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- protected_key_material: the per-transfer AES data-encryption key,
-- wrapped with the intended recipient's RSA public key (RSA-OAEP
-- SHA-256). Only the wrapped form is ever stored or transmitted.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS protected_key_material (
    id               BIGINT        NOT NULL AUTO_INCREMENT,
    transfer_id      CHAR(36)      NOT NULL,
    wrap_algorithm   VARCHAR(80)   NOT NULL DEFAULT 'RSA/ECB/OAEPWithSHA-256AndMGF1Padding',
    wrapped_key      VARBINARY(1024) NOT NULL COMMENT 'RSA-OAEP wrapped AES key - never plaintext',
    recipient_key_id BIGINT        NULL,
    key_version      INT           NOT NULL DEFAULT 1,
    created_at       DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT uk_pkm_transfer UNIQUE (transfer_id),
    CONSTRAINT fk_pkm_transfer FOREIGN KEY (transfer_id)
        REFERENCES image_transfers (transfer_id) ON DELETE CASCADE,
    CONSTRAINT fk_pkm_recip_key FOREIGN KEY (recipient_key_id)
        REFERENCES user_public_keys (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- audit_logs: append-only trail of authentication, encryption,
-- decryption, key-management and transfer events. Never contains secret
-- material (no keys, no passwords, no image data).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGINT       NOT NULL AUTO_INCREMENT,
    event_type  VARCHAR(48)  NOT NULL COMMENT 'e.g. AUTH_OK, AUTH_FAIL, KEY_RELEASE, TRANSFER_RECV, DECRYPT_OK, DECRYPT_FAIL',
    username    VARCHAR(64)  NULL,
    user_id     BIGINT       NULL,
    transfer_id CHAR(36)     NULL,
    outcome     VARCHAR(16)  NOT NULL COMMENT 'SUCCESS | FAILURE | DENIED',
    detail      VARCHAR(255) NULL,
    source_ip   VARCHAR(45)  NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    INDEX idx_audit_event (event_type),
    INDEX idx_audit_user (username),
    INDEX idx_audit_transfer (transfer_id),
    INDEX idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
