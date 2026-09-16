-- =========================================================================
-- 03_privileges.sql
-- Phase 2: fix MySQL account privileges. Run AFTER 01 and 02.
--
-- IMPORTANT: every CREATE USER below uses a CHANGE_ME_<ROLE> placeholder,
-- NOT a real password. This file is meant to be committed to a public repo,
-- so no actual credential can live in it. Before running this script
-- against any real database, replace every CHANGE_ME_* value with your own
-- strong, unique, randomly generated password per account (a password
-- manager's generator is fine) — do not run this file as-is. Update
-- config.php's DB_USER / DB_PASS to match whichever account the app should
-- connect as (typically a new, narrowly-scoped app account — see note at
-- the bottom).
-- =========================================================================

-- -------------------------------------------------------------------------
-- Fix #10: drop the old accounts (password '1234', 'prosecutor' granted on
-- *.*, no 'csi' account at all) and recreate them cleanly, each scoped to
-- forensic_evidence_db.* only — never *.*.
-- -------------------------------------------------------------------------
DROP USER IF EXISTS 'investigator'@'%';
DROP USER IF EXISTS 'analyst'@'%';
DROP USER IF EXISTS 'custodian'@'%';
DROP USER IF EXISTS 'prosecutor'@'%';
DROP USER IF EXISTS 'sysadmin'@'%';
DROP USER IF EXISTS 'csi'@'%';

CREATE USER 'investigator'@'%' IDENTIFIED BY 'CHANGE_ME_INVESTIGATOR';
CREATE USER 'analyst'@'%'      IDENTIFIED BY 'CHANGE_ME_ANALYST';
CREATE USER 'custodian'@'%'    IDENTIFIED BY 'CHANGE_ME_CUSTODIAN';
CREATE USER 'prosecutor'@'%'   IDENTIFIED BY 'CHANGE_ME_PROSECUTOR';
CREATE USER 'sysadmin'@'%'     IDENTIFIED BY 'CHANGE_ME_SYSADMIN';
CREATE USER 'csi'@'%'          IDENTIFIED BY 'CHANGE_ME_CSI';

-- -------------------------------------------------------------------------
-- CSI privileges (was entirely missing). Mirrors what a CSI does in the
-- app: collects evidence, logs the initial chain-of-custody entry, can
-- view (not run) analysis.
-- -------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.evidence TO 'csi'@'%';
GRANT SELECT, INSERT ON forensic_evidence_db.chain_of_custody TO 'csi'@'%';
GRANT SELECT ON forensic_evidence_db.forensic_analysis TO 'csi'@'%';
GRANT SELECT ON forensic_evidence_db.cases TO 'csi'@'%';
GRANT SELECT, INSERT ON forensic_evidence_db.evidence_media TO 'csi'@'%';
GRANT SELECT, INSERT ON forensic_evidence_db.evidence_notes TO 'csi'@'%';
GRANT SELECT, INSERT ON forensic_evidence_db.evidence_access_log TO 'csi'@'%';

-- -------------------------------------------------------------------------
-- Investigator privileges — scoped to forensic_evidence_db.* (was already
-- correctly scoped; recreated here for consistency).
-- -------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.cases TO 'investigator'@'%';
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.evidence TO 'investigator'@'%';
GRANT SELECT ON forensic_evidence_db.forensic_analysis TO 'investigator'@'%';
GRANT SELECT ON forensic_evidence_db.chain_of_custody TO 'investigator'@'%';
GRANT SELECT, INSERT ON forensic_evidence_db.case_assignments TO 'investigator'@'%';

-- -------------------------------------------------------------------------
-- Analyst privileges
-- -------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.forensic_analysis TO 'analyst'@'%';
GRANT SELECT ON forensic_evidence_db.evidence TO 'analyst'@'%';
GRANT SELECT ON forensic_evidence_db.evidence_media TO 'analyst'@'%';
GRANT SELECT ON forensic_evidence_db.evidence_notes TO 'analyst'@'%';
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.analysis_reports TO 'analyst'@'%';

-- -------------------------------------------------------------------------
-- Custodian privileges
-- -------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.evidence_intake TO 'custodian'@'%';
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.chain_of_custody TO 'custodian'@'%';
GRANT SELECT, UPDATE ON forensic_evidence_db.evidence TO 'custodian'@'%';
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.disposition TO 'custodian'@'%';
GRANT SELECT, INSERT, UPDATE ON forensic_evidence_db.storage_locations TO 'custodian'@'%';

-- -------------------------------------------------------------------------
-- Fix #10: Prosecutor was granted SELECT ON *.* — an entire-server read
-- grant. Scope it to this database only, matching their read-only role.
-- -------------------------------------------------------------------------
GRANT SELECT ON forensic_evidence_db.* TO 'prosecutor'@'%';
GRANT INSERT, UPDATE ON forensic_evidence_db.disposition TO 'prosecutor'@'%';

-- -------------------------------------------------------------------------
-- SysAdmin privileges — still broad, but scoped to this database instead
-- of ALL PRIVILEGES ON *.* (which reached every other database on the
-- server, including MySQL's own system schemas).
-- -------------------------------------------------------------------------
GRANT ALL PRIVILEGES ON forensic_evidence_db.* TO 'sysadmin'@'%';

-- -------------------------------------------------------------------------
-- Fix #11 (privilege side): audit-trail and hash-verification tables must
-- stay append-only at the database level too, not just in the app —
-- revoke DELETE/UPDATE even from sysadmin.
-- -------------------------------------------------------------------------
REVOKE DELETE, UPDATE ON forensic_evidence_db.evidence_access_log FROM 'sysadmin'@'%';
REVOKE DELETE, UPDATE ON forensic_evidence_db.hash_verification_log FROM 'sysadmin'@'%';
REVOKE DELETE, UPDATE ON forensic_evidence_db.evidence_status_log FROM 'sysadmin'@'%';
REVOKE DELETE, UPDATE ON forensic_evidence_db.chain_of_custody FROM 'sysadmin'@'%';

FLUSH PRIVILEGES;

-- -------------------------------------------------------------------------
-- Note on the app's own DB connection (db.php / config.php):
-- the app currently connects as 'root'. For defense in depth, consider
-- creating a dedicated 'sfems_app'@'localhost' account scoped to
-- forensic_evidence_db.* with the same table grants as sysadmin above
-- (the app enforces per-role RBAC in PHP, not via separate MySQL logins
-- per user), and pointing config.php at that account instead of root.
-- -------------------------------------------------------------------------
