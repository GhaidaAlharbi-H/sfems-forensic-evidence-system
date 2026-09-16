-- =========================================================================
-- 01_critical_fixes.sql
-- Phase 1 critical fixes. Run this against the existing forensic_evidence_db
-- database (incremental — does NOT recreate any table).
-- =========================================================================
USE forensic_evidence_db;

-- -------------------------------------------------------------------------
-- Fix #4: trg_evidence_status_location_update inserts NULL into
-- chain_of_custody.to_user_id (NOT NULL), which fails and silently rolls
-- back every Edit Evidence action.
--
-- Fix: a status/location change is a system-observed event, not a
-- person-to-person custody transfer, so it gets its own log table instead
-- of being shoehorned into chain_of_custody. The trigger now writes there.
-- chain_of_custody keeps recording only real transfers, entered explicitly
-- via pages/chain.php (which always supplies both from/to user).
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence_status_log (
    log_id            INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id       INT NOT NULL,
    old_status        ENUM('COLLECTED','SUBMITTED','IN_STORAGE','IN_LAB','IN_COURT','DISPOSED','RETURNED') NULL,
    new_status        ENUM('COLLECTED','SUBMITTED','IN_STORAGE','IN_LAB','IN_COURT','DISPOSED','RETURNED') NULL,
    old_location_id   INT NULL,
    new_location_id   INT NULL,
    changed_at        DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_status_log_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT fk_status_log_old_location
        FOREIGN KEY (old_location_id) REFERENCES storage_locations(location_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL,

    CONSTRAINT fk_status_log_new_location
        FOREIGN KEY (new_location_id) REFERENCES storage_locations(location_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

DROP TRIGGER IF EXISTS trg_evidence_status_location_update;

DELIMITER $$
CREATE TRIGGER trg_evidence_status_location_update
AFTER UPDATE ON evidence
FOR EACH ROW
BEGIN
    IF NEW.current_status <> OLD.current_status
       OR NOT (NEW.current_location_id <=> OLD.current_location_id) THEN

        INSERT INTO evidence_status_log (
            evidence_id, old_status, new_status, old_location_id, new_location_id
        )
        VALUES (
            NEW.evidence_id, OLD.current_status, NEW.current_status,
            OLD.current_location_id, NEW.current_location_id
        );
    END IF;
END$$
DELIMITER ;

-- -------------------------------------------------------------------------
-- Fix #8 (part 1) / #16: soft delete for evidence and evidence_media,
-- instead of hard DELETE, so audit trail rows always have something to
-- point back to.
-- -------------------------------------------------------------------------
ALTER TABLE evidence
    ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 CHECK (is_active IN (0,1));

ALTER TABLE evidence_media
    ADD COLUMN is_active TINYINT(1) NOT NULL DEFAULT 1 CHECK (is_active IN (0,1));

-- -------------------------------------------------------------------------
-- Fix #8 (part 2): audit-trail tables must survive evidence deletion
-- (NISTIR 7928). Change ON DELETE CASCADE -> RESTRICT on the FK from each
-- of these tables to evidence. Combined with the soft-delete above, the
-- app no longer hard-deletes evidence at all, but RESTRICT is kept as a
-- database-level guarantee regardless of how a delete is attempted.
-- -------------------------------------------------------------------------
ALTER TABLE chain_of_custody
    DROP FOREIGN KEY fk_coc_evidence,
    ADD CONSTRAINT fk_coc_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT;

ALTER TABLE evidence_intake
    DROP FOREIGN KEY fk_intake_evidence,
    ADD CONSTRAINT fk_intake_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT;

ALTER TABLE evidence_access_log
    DROP FOREIGN KEY fk_accesslog_evidence,
    ADD CONSTRAINT fk_accesslog_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT;

ALTER TABLE disposition
    DROP FOREIGN KEY fk_disposition_evidence,
    ADD CONSTRAINT fk_disposition_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT;
