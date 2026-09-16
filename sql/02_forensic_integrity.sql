-- =========================================================================
-- 02_forensic_integrity.sql
-- Phase 2: forensic-integrity features. Run AFTER 01_critical_fixes.sql.
-- =========================================================================
USE forensic_evidence_db;

-- -------------------------------------------------------------------------
-- Fix #6: cryptographic hashing so an uploaded file's integrity can be
-- proven at any later point (FRE 902(14) self-authentication).
-- -------------------------------------------------------------------------
ALTER TABLE evidence_media
    ADD COLUMN file_sha256 CHAR(64) NULL AFTER file_path;

ALTER TABLE analysis_reports
    ADD COLUMN file_sha256 CHAR(64) NULL AFTER report_file_path;

-- Append-only verification log: every "Verify" click (media.php / reports.php)
-- recomputes the file's hash and records the result here, regardless of
-- outcome. Privileges in 03_privileges.sql revoke UPDATE/DELETE on this
-- table from every account, including sysadmin, to keep it append-only.
CREATE TABLE IF NOT EXISTS hash_verification_log (
    log_id          INT AUTO_INCREMENT PRIMARY KEY,
    table_name      ENUM('evidence_media','analysis_reports') NOT NULL,
    record_id       INT NOT NULL,
    evidence_id     INT NULL,
    expected_hash   CHAR(64) NULL,
    computed_hash   CHAR(64) NULL,
    verified_by_id  INT NOT NULL,
    verified_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    result          ENUM('MATCH','MISMATCH','FILE_MISSING','NO_BASELINE') NOT NULL,

    CONSTRAINT fk_hashlog_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT fk_hashlog_verified_by
        FOREIGN KEY (verified_by_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------------------------------------------------------------
-- Fix #9: evidence lineage (e.g. a DNA extract derived from a bloodstain).
-- -------------------------------------------------------------------------
ALTER TABLE evidence
    ADD COLUMN parent_evidence_id INT NULL AFTER evidence_id,
    ADD CONSTRAINT fk_evidence_parent
        FOREIGN KEY (parent_evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL;

-- -------------------------------------------------------------------------
-- Fix #11: disposition needs an independent witness, distinct from the
-- authorizer, required whenever disposition_type = 'DESTROYED'.
-- -------------------------------------------------------------------------
ALTER TABLE disposition
    ADD COLUMN witness_user_id INT NULL AFTER authorized_by_id,
    ADD CONSTRAINT fk_disposition_witness
        FOREIGN KEY (witness_user_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT;

-- FIX (verification pass): a CHECK constraint was originally used here, but
-- MariaDB 10.11 rejects any CHECK clause that references a column carrying
-- a FOREIGN KEY (confirmed by direct testing: ERROR 1901, "Function or
-- expression 'witness_user_id' cannot be used in the CHECK clause" — the
-- same failure occurs for authorized_by_id alone, and for any other FK
-- column on this table). This is a real MariaDB/MySQL divergence: the
-- original CHECK syntax is valid on MySQL 8.0.16+ but not on MariaDB.
-- Since the target environment is MariaDB 10.11, enforcement is moved to
-- BEFORE INSERT / BEFORE UPDATE triggers, which apply the identical rule
-- and cannot be bypassed by direct SQL any more than a CHECK constraint
-- could. The application (pages/disposition.php) still validates this
-- up front too, so the user gets a friendly message before ever reaching
-- the trigger's raw error.
DELIMITER $$

CREATE TRIGGER trg_disposition_witness_insert
BEFORE INSERT ON disposition
FOR EACH ROW
BEGIN
    IF NEW.disposition_type = 'DESTROYED'
       AND (NEW.witness_user_id IS NULL OR NEW.witness_user_id = NEW.authorized_by_id) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'A DESTROYED disposition requires a witness distinct from the authorizing user.';
    END IF;
END$$

CREATE TRIGGER trg_disposition_witness_update
BEFORE UPDATE ON disposition
FOR EACH ROW
BEGIN
    IF NEW.disposition_type = 'DESTROYED'
       AND (NEW.witness_user_id IS NULL OR NEW.witness_user_id = NEW.authorized_by_id) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'A DESTROYED disposition requires a witness distinct from the authorizing user.';
    END IF;
END$$

DELIMITER ;
