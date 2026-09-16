# SFEMS Security & Forensic-Integrity Changelog

Maps each numbered issue from the brief to what was changed. Nothing was added
outside this list.

## How to apply

1. **Back up your database first.**
2. Run the SQL patches in order against your existing database:
   ```
   mysql -u root -p forensic_evidence_db < sql/01_critical_fixes.sql
   mysql -u root -p forensic_evidence_db < sql/02_forensic_integrity.sql
   mysql -u root -p forensic_evidence_db < sql/03_privileges.sql
   ```
3. Copy `forensic_evidence_db/config.sample.php` to `forensic_evidence_db/config.php`
   and fill in real credentials (a `config.php` with your existing root/dev
   password is already included so the app keeps working locally — replace
   it with your own before deploying anywhere else, and never commit it).
4. Run the one-time password migration from the command line, then delete it:
   ```
   php forensic_evidence_db/migrate_passwords.php
   ```
   It prints a temporary password for any account that only had the seed
   placeholder `'hash'` — hand those out and have the users change them.
   **Delete `migrate_passwords.php` immediately after running it once.**
5. If your web server is Apache, confirm `AllowOverride` is enabled for the
   `media/` directory so `media/.htaccess` (execution lock) takes effect.
   On nginx, add the equivalent `location ~* ^/media/.*\.php$ { deny all; }`
   block yourself — nginx doesn't read `.htaccess`.
6. Test the golden path: login, add evidence, edit evidence, upload media,
   verify a media hash, log a custody transfer, record a DESTROYED
   disposition with a witness.

---

## Phase 1 — Critical fixes

| # | Issue | Fix |
|---|---|---|
| 1 | Plaintext passwords, `===` comparison | `login.php` now uses `password_verify()`; `users.php` hashes with `password_hash()` on add/update (min 8 chars enforced). One-time `migrate_passwords.php` hashes any remaining plaintext rows, then should be deleted. |
| 2 | `intake.php` / `assignments.php` had no auth check | Both now `require bootstrap.php; sfems_require_login();` — same as every other page. `bootstrap.php` is new and is what closes this class of bug: any page that includes it gets a session + RBAC check regardless of whether it's reached via `index.php` or requested directly. Added matching RBAC table entries `INTAKE` and `CASE_ASSIGNMENTS` in `rbac.php`. |
| 3 | `media.php` accepted any upload, kept original filename, RCE risk | `media.php` now validates the **real** MIME type via `finfo` against an allowlist, enforces a 25 MB size cap, generates a random filename (never the client's), and `media/.htaccess` + `media/index.html` disable script execution and directory listing in the upload folder. |
| 4 | `trg_evidence_status_location_update` inserted NULL into `chain_of_custody.to_user_id` (NOT NULL), silently rolling back Edit Evidence | `sql/01_critical_fixes.sql` adds a new `evidence_status_log` table for system-observed status/location changes and rewrites the trigger to write there instead — a status change is not a person-to-person transfer, so it no longer lives in `chain_of_custody`. `chain_of_custody` keeps recording only real transfers entered through `chain.php`. |
| 5 | `db.php` had a live DB password in plaintext | Credentials moved to `config.php` (gitignored) with `config.sample.php` committed as the template. `.gitignore` added. |

## Phase 2 — Forensic integrity

| # | Issue | Fix |
|---|---|---|
| 6 | No cryptographic hashing of uploaded files | `sql/02_forensic_integrity.sql` adds `file_sha256` to `evidence_media` and `analysis_reports`. Computed at upload time in `media.php` / `reports.php`. A "Verify" button on both pages recomputes and compares, logging every check (match, mismatch, missing, or no baseline) to the new append-only `hash_verification_log` table via `log_hash_verification()` in `audit.php`. |
| 7 | Access log was a manual self-report, but the UI claimed it was automatic | `evidence.php` now calls `log_access()` to record a VIEW for every evidence row actually rendered; `download.php` (new file — the gateway every media/report link now goes through) records DOWNLOAD at the point a file is actually served. `access.php`'s manual form is now restricted to PRINT/EXPORT/OTHER — the only actions the server genuinely can't observe — and both the form and the history table label entries as "Self-declared" vs "Automatic". |
| 8 | `ON DELETE CASCADE` on audit-trail FKs let deleting evidence destroy its own audit trail | `sql/01_critical_fixes.sql` changes the FK from `chain_of_custody`, `evidence_intake`, `evidence_access_log`, and `disposition` to `evidence` from CASCADE to RESTRICT. Combined with soft delete (#16), evidence is never hard-deleted by the app at all now, but the RESTRICT is a database-level guarantee independent of that. |
| 9 | No evidence lineage (e.g. DNA extract derived from a bloodstain) | `sql/02_forensic_integrity.sql` adds a self-referencing `parent_evidence_id` FK on `evidence`. `evidence.php`'s Add form has a "Derived From" dropdown, and the list shows each item's parent. |
| 10 | Broken MySQL grants (`prosecutor` had `SELECT ON *.*`; shared password `1234`; no `csi` account) | `sql/03_privileges.sql` drops and recreates every role account, each scoped to `forensic_evidence_db.*` only (never `*.*`), and adds the missing `csi` account with grants matching what a CSI does in the app. Passwords are shipped as `CHANGE_ME_<ROLE>` placeholders — the file is safe to commit as-is, but must have real per-account passwords substituted before it's actually run. |
| 11 | Disposition (especially DESTROYED) had no independent witness requirement | `sql/02_forensic_integrity.sql` adds `witness_user_id` to `disposition` plus two triggers (`trg_disposition_witness_insert` / `trg_disposition_witness_update`) requiring a witness different from the authorizer whenever `disposition_type = 'DESTROYED'`. (A `CHECK` constraint was tried first but MariaDB 10.11 rejects a `CHECK` clause that references an FK-bearing column — confirmed by direct testing, ERROR 1901 — so enforcement moved to `BEFORE INSERT`/`BEFORE UPDATE` triggers instead, which apply the identical rule.) `disposition.php` validates the same rule up front for a friendly error message, and the witness column now appears in the form and the records table. `sql/03_privileges.sql` also revokes DELETE/UPDATE on audit-trail tables (including `hash_verification_log` and `evidence_status_log`) from every account, sysadmin included, so they stay append-only at the database level too. |

## Phase 3 — Security hardening

| # | Issue | Fix |
|---|---|---|
| 12 | No CSRF protection; deletes were plain GET links | New `csrf.php` (`csrf_token()`, `csrf_field()`, `sfems_verify_csrf()`). `bootstrap.php` verifies the token on every POST automatically. Every form across all 15 pages now includes `csrf_field()`. Every GET-based delete/deactivate (`media.php`, `disposition.php`, `users.php`, `locations.php`) was converted to a POST form with confirmation + CSRF. |
| 13 | No session hardening | `bootstrap.php` (and `login.php`) sets `HttpOnly`, `SameSite=Lax`, and `Secure`-when-HTTPS cookie flags; `login.php` calls `session_regenerate_id(true)` on successful login; `bootstrap.php` enforces a 15-minute idle timeout (`sfems_require_login()`), destroying the session and redirecting to login with a timeout notice. `logout.php` clears the session cookie explicitly. |
| 14 | Raw MySQL error messages echoed to the browser | `sfems_generic_db_error()` in `db.php` logs the real error via `error_log()` and returns a generic message. Every `$stmt->error` that used to reach the browser across all pages now goes through it. `mysqli_report(MYSQLI_REPORT_OFF)` in `db.php` so uncaught driver errors don't leak a stack trace either. |
| 15 | Login revealed whether an email exists via different error messages | `login.php` now returns the identical "Incorrect email or password." message whether the account doesn't exist or the password is wrong, and always runs `password_verify()` (against a dummy hash when no user was found) so the two cases take the same time. |
| 16 | Hard deletes used throughout instead of soft deletes | `sql/01_critical_fixes.sql` adds `is_active` to `evidence` and `evidence_media`. `evidence.php` and `media.php` now set `is_active = 0` instead of `DELETE`; all list/dropdown queries filter to `is_active = 1`. (Other tables — cases, disposition, analysis, locations — were left as hard delete since they weren't named in this issue and aren't part of the evidence chain-of-custody trail.) |

## New supporting files

- `bootstrap.php` — session hardening, login/RBAC gate, idle timeout, central CSRF check. Every page in `pages/` now starts with this instead of raw `require "db.php"`.
- `csrf.php` — CSRF token helpers.
- `audit.php` — `log_access()`, `sfems_hash_file()`, `log_hash_verification()`.
- `download.php` — authenticated, RBAC-checked, path-traversal-safe file gateway for media and report downloads; this is what makes DOWNLOAD log entries automatic.
- `config.php` / `config.sample.php` — DB credentials, gitignored / template.
- `migrate_passwords.php` — one-time password migration; **delete after running**.
- `media/.htaccess`, `media/index.html` — lock down the upload directory.
- `sql/01_critical_fixes.sql`, `sql/02_forensic_integrity.sql`, `sql/03_privileges.sql` — incremental patches, run in order.

## Explicitly out of scope (not touched)

- The RBAC matrix pattern in `rbac.php` (`$PAGE_ROLES` / `$TABLE_PERMISSIONS`) — extended with two new table entries (`INTAKE`, `CASE_ASSIGNMENTS`), never restructured.
- Existing queries, views, and the second trigger (`trg_log_access_on_note`) — left as-is.
- File/folder layout — no page was renamed or moved; only `bootstrap.php`, `csrf.php`, `audit.php`, `download.php`, `config.php`/`config.sample.php`, `migrate_passwords.php`, and `sql/` were added.
