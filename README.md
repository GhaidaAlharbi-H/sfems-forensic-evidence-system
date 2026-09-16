# FEMS — Forensic Evidence Management System

SFEMS is a PHP + MySQL/MariaDB web app for managing forensic evidence
end-to-end: cases → evidence intake → chain of custody → forensic analysis →
lab reports → disposition. Access is controlled by a six-role RBAC system
(SysAdmin, CSI, Custodian, Analyst, Investigator, Prosecutor) enforced at
both the page level and the per-table CRUD level. Built as a university
database systems course project.

## Setup

1. **Import the base schema:**
   ```
   mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS forensic_evidence_db"
   mysql -u root -p forensic_evidence_db < sql/00_base_schema.sql
   ```

2. **Apply the security/integrity patches, in order:**
   ```
   mysql -u root -p forensic_evidence_db < sql/01_critical_fixes.sql
   mysql -u root -p forensic_evidence_db < sql/02_forensic_integrity.sql
   ```
   Before running `03_privileges.sql`, replace every `CHANGE_ME_*` placeholder
   in that file with a real, unique, strong password for each account —
   it ships with placeholders, not real credentials, so it's safe to commit.
   ```
   mysql -u root -p forensic_evidence_db < sql/03_privileges.sql
   ```

3. **Configure credentials:**
   ```
   cp forensic_evidence_db/config.sample.php forensic_evidence_db/config.php
   ```
   Edit `config.php` with real DB credentials. This file is gitignored —
   never commit it.

4. **Hash any plaintext seed passwords once**, then delete the script:
   ```
   php forensic_evidence_db/migrate_passwords.php
   ```
   This prints a temporary password for any account that only had the seed
   placeholder value — hand those out and have the users change them on
   first login. The script deletes nothing on its own; **delete it yourself**
   immediately after running it (`rm forensic_evidence_db/migrate_passwords.php`).
   It has no auth check by design (it's a CLI-only script), so it must not
   stay reachable in a deployed copy of the app.

5. **Run it:**
   ```
   php -S localhost:8000 -t forensic_evidence_db
   ```
   or point an Apache/nginx vhost's document root at `forensic_evidence_db/`.

## Requirements

- PHP 8.0+ (uses `finfo`, typed properties, `password_hash()`/`password_verify()`)
- **MariaDB 10.2.1+ or MySQL 8.0.16+** — the disposition-witness rule
  (fix #11) is enforced with a `CHECK` constraint, which needs a version
  that actually evaluates it. MariaDB has enforced `CHECK` since 10.2.1.
  MySQL accepted the syntax much earlier but silently ignored it until
  8.0.16 — on an older MySQL server, a DESTROYED record could be saved
  with no witness even though the constraint is present in the schema.

## Security features

- RBAC enforced at both the page level (`$PAGE_ROLES`) and per-table CRUD
  level (`$TABLE_PERMISSIONS`) in `rbac.php`
- Passwords hashed with `password_hash()` / verified with `password_verify()`
- CSRF tokens required on every state-changing (POST) request
- File uploads validated by real MIME type detection (`finfo`), not by
  trusting the extension or client-supplied filename
- SHA-256 integrity hashing of uploaded media/reports at intake, with an
  on-demand "Verify" action and an append-only verification log
- Automatic (server-observed) VIEW/DOWNLOAD audit logging — manual
  self-report is limited to PRINT/EXPORT, which the server genuinely can't
  observe
- Soft deletes for evidence and media records — audit trail rows are never
  orphaned by a hard delete
- Scoped MySQL account privileges: no role account is granted on `*.*`;
  every grant is scoped to `forensic_evidence_db.*`

## Known limitations / deployment notes

- `media/.htaccess` (which blocks script execution in the upload
  directory) only takes effect under **Apache with `mod_php`** and
  `AllowOverride` enabled for that directory. Under **nginx or PHP-FPM**,
  `.htaccess` is not read at all — you must add an equivalent `location`
  block denying `.php` execution under `media/` yourself, e.g.:
  ```nginx
  location ~* ^/media/.*\.php$ {
      deny all;
  }
  ```
- Seed data (`sql/00_base_schema.sql`) references a few evidence photo
  paths (`/media/oj_glove_scene.jpg`, etc.) that are not shipped as actual
  files — only the schema/rows are seeded, not sample media.
