CREATE DATABASE forensic_evidence_db;
USE forensic_evidence_db;

-- =========================================================
-- 1. ROLES
-- =========================================================
CREATE TABLE roles (
    role_id        INT AUTO_INCREMENT PRIMARY KEY,
    role_name      VARCHAR(50) NOT NULL UNIQUE,
    description    VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 2. USERS
-- =========================================================
CREATE TABLE users (
    user_id        INT AUTO_INCREMENT PRIMARY KEY,
    role_id        INT NOT NULL,
    full_name      VARCHAR(100) NOT NULL,
    email          VARCHAR(100) NOT NULL UNIQUE,
    username       VARCHAR(50) NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    phone          VARCHAR(20),
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active      TINYINT(1) DEFAULT 1 CHECK (is_active IN (0,1)),

    CONSTRAINT fk_users_role
        FOREIGN KEY (role_id) REFERENCES roles(role_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 3. CASES
-- =========================================================
CREATE TABLE cases (
    case_id               INT AUTO_INCREMENT PRIMARY KEY,
    case_number           VARCHAR(50) NOT NULL UNIQUE,
    title                 VARCHAR(255) NOT NULL,
    description           TEXT,
    status                ENUM('OPEN','UNDER_INVESTIGATION','CLOSED','ARCHIVED') DEFAULT 'OPEN',
    opened_date           DATE NOT NULL,
    closed_date           DATE NULL,
    lead_investigator_id  INT NULL,

    CONSTRAINT fk_cases_lead_investigator
        FOREIGN KEY (lead_investigator_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 4. CASE ASSIGNMENTS (Associative Entity)
-- =========================================================
CREATE TABLE case_assignments (
    case_id        INT NOT NULL,
    user_id        INT NOT NULL,
    assigned_role  VARCHAR(50),
    assigned_at    DATETIME DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (case_id, user_id),

    CONSTRAINT fk_case_assignments_case
        FOREIGN KEY (case_id) REFERENCES cases(case_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_case_assignments_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 5. STORAGE LOCATIONS
-- =========================================================
CREATE TABLE storage_locations (
    location_id     INT AUTO_INCREMENT PRIMARY KEY,
    location_code   VARCHAR(50) NOT NULL UNIQUE,
    description     VARCHAR(255),
    room            VARCHAR(50),
    shelf           VARCHAR(50),
    locker          VARCHAR(50),
    storage_type    ENUM('GENERAL','COLD_STORAGE','WEAPONS_LOCKER','DIGITAL_VAULT','OTHER')
                    DEFAULT 'GENERAL',
    is_active       TINYINT(1) DEFAULT 1 CHECK (is_active IN (0,1))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 6. EVIDENCE
-- =========================================================
CREATE TABLE evidence (
    evidence_id          INT AUTO_INCREMENT PRIMARY KEY,
    case_id              INT NOT NULL,
    evidence_code        VARCHAR(50) NOT NULL,
    description          TEXT NOT NULL,
    evidence_type        ENUM('PHYSICAL','BIOLOGICAL','DIGITAL','DOCUMENT','WEAPON','OTHER') NOT NULL,
    collected_by_id      INT NOT NULL,
    collected_datetime   DATETIME NOT NULL,
    collection_location  VARCHAR(255),
    current_status       ENUM('COLLECTED','SUBMITTED','IN_STORAGE','IN_LAB','IN_COURT','DISPOSED','RETURNED')
                          DEFAULT 'COLLECTED',
    current_location_id  INT NULL,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (case_id, evidence_code),

    CONSTRAINT fk_evidence_case
        FOREIGN KEY (case_id) REFERENCES cases(case_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT fk_evidence_collected_by
        FOREIGN KEY (collected_by_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT fk_evidence_current_location
        FOREIGN KEY (current_location_id) REFERENCES storage_locations(location_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 7. EVIDENCE MEDIA
-- =========================================================
CREATE TABLE evidence_media (
    media_id        INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id     INT NOT NULL,
    media_type      ENUM('PHOTO','VIDEO','AUDIO','DOCUMENT','OTHER') NOT NULL,
    file_path       VARCHAR(255) NOT NULL,
    description     VARCHAR(255),
    uploaded_by_id  INT NOT NULL,
    uploaded_at     DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_evidence_media_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_evidence_media_user
        FOREIGN KEY (uploaded_by_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 8. EVIDENCE INTAKE
-- =========================================================
CREATE TABLE evidence_intake (
    intake_id           INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id         INT NOT NULL,
    received_by_id      INT NOT NULL,
    received_datetime   DATETIME NOT NULL,
    received_condition  VARCHAR(255),
    intake_status       ENUM('PENDING','ACCEPTED','REJECTED') DEFAULT 'ACCEPTED',
    notes               TEXT,

    CONSTRAINT fk_intake_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_intake_received_by
        FOREIGN KEY (received_by_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- =========================================================
-- 9. CHAIN OF CUSTODY
-- =========================================================
CREATE TABLE chain_of_custody (
    transfer_id       INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id       INT NOT NULL,
    from_user_id      INT NULL,
    to_user_id        INT NOT NULL,
    from_location_id  INT NULL,
    to_location_id    INT NULL,
    purpose           VARCHAR(255),
    transfer_datetime DATETIME NOT NULL,
    condition_notes   VARCHAR(255),

    CONSTRAINT fk_coc_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_coc_from_user
        FOREIGN KEY (from_user_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL,

    CONSTRAINT fk_coc_to_user
        FOREIGN KEY (to_user_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT fk_coc_from_location
        FOREIGN KEY (from_location_id) REFERENCES storage_locations(location_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL,

    CONSTRAINT fk_coc_to_location
        FOREIGN KEY (to_location_id) REFERENCES storage_locations(location_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 10. FORENSIC ANALYSIS
-- =========================================================
CREATE TABLE forensic_analysis (
    analysis_id          INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id          INT NOT NULL,
    analyst_id           INT NOT NULL,
    requested_by_id      INT NULL,
    analysis_type        VARCHAR(100) NOT NULL,
    lab_reference        VARCHAR(100),
    analysis_status      ENUM('PENDING','IN_PROGRESS','COMPLETED','CANCELLED') DEFAULT 'PENDING',
    requested_datetime   DATETIME NOT NULL,
    started_datetime     DATETIME NULL,
    completed_datetime   DATETIME NULL,
    summary              TEXT,
    
    CONSTRAINT fk_analysis_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_analysis_analyst
        FOREIGN KEY (analyst_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    CONSTRAINT fk_analysis_requested_by
        FOREIGN KEY (requested_by_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 11. ANALYSIS REPORTS
-- =========================================================
CREATE TABLE analysis_reports (
    report_id        INT AUTO_INCREMENT PRIMARY KEY,
    analysis_id      INT NOT NULL,
    report_title     VARCHAR(255) NOT NULL,
    report_file_path VARCHAR(255) NOT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by_id    INT NOT NULL,

    CONSTRAINT fk_reports_analysis
        FOREIGN KEY (analysis_id) REFERENCES forensic_analysis(analysis_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_reports_created_by
        FOREIGN KEY (created_by_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- =========================================================
-- 12. EVIDENCE NOTES
-- =========================================================
CREATE TABLE evidence_notes (
    note_id      INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id  INT NOT NULL,
    user_id      INT NOT NULL,
    note_text    TEXT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_notes_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_notes_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 13. EVIDENCE ACCESS LOG
-- =========================================================
CREATE TABLE evidence_access_log (
    access_id        INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id      INT NOT NULL,
    user_id          INT NOT NULL,
    access_datetime  DATETIME DEFAULT CURRENT_TIMESTAMP,
    access_type      ENUM('VIEW','DOWNLOAD','PRINT','EXPORT','OTHER') NOT NULL,
    details          VARCHAR(255),

    CONSTRAINT fk_accesslog_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_accesslog_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================================
-- 14. DISPOSITION
-- =========================================================
CREATE TABLE disposition (
    disposition_id       INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id          INT NOT NULL,
    disposition_type     ENUM('DESTROYED','RETURNED_TO_OWNER','PERMANENTLY_STORED','OTHER') NOT NULL,
    disposition_datetime DATETIME NOT NULL,
    authorized_by_id     INT NOT NULL,
    notes                TEXT,

    CONSTRAINT fk_disposition_evidence
        FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,

    CONSTRAINT fk_disposition_authorized_by
        FOREIGN KEY (authorized_by_id) REFERENCES users(user_id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


/* ============================================================
   1. INSERT INTO ROLES
   ============================================================ */
INSERT INTO roles (role_name, description) VALUES
('CSI', 'Crime Scene Investigator'),
('Custodian', 'Evidence Room Custodian'),
('Analyst', 'Forensic DNA & Trace Analyst'),
('Investigator', 'Lead Detective'),
('Prosecutor', 'District Attorney / Legal Officer'),
('SysAdmin', 'System Administrator');

/* ============================================================
   2. INSERT INTO USERS 
   ============================================================ */
INSERT INTO users (role_id, full_name, email, username, password_hash, phone) VALUES
(1, 'Dennis Fung', 'fung.csi@example.com', 'fungcsi', 'hash', '5551000'),
(1, 'Phillip Vannatter', 'vannatter.det@example.com', 'vannatter', 'hash', '5551001'),
(2, 'Andrea Mazzola', 'mazzola.cust@example.com', 'mazzola', 'hash', '5552000'),
(3, 'Dr. Cotton', 'cotton.lab@example.com', 'cottonlab', 'hash', '5553000'),
(4, 'Tom Lange', 'lange.det@example.com', 'lange', 'hash', '5554000'),
(5, 'Marcia Clark', 'clark.pros@example.com', 'mclark', 'hash', '5555000'),
(6, 'Admin User', 'admin@example.com', 'admin', 'hash', '5556000');

/* ============================================================
   3. CASES (O.J. SIMPSON DOUBLE-MURDER)
   ============================================================ */
INSERT INTO cases (case_number, title, description, status, opened_date, lead_investigator_id)
VALUES
('CASE-1994-OJ',
 'Double Murder of Nicole Brown & Ron Goldman',
 'Real 1994 homicide case involving forensic DNA evidence, gloves, blood trails, shoeprints, and Bronco blood.',
 'CLOSED',
 '1994-06-12',
 4);  

/* ============================================================
   4. CASE ASSIGNMENTS
   ============================================================ */
INSERT INTO case_assignments (case_id, user_id, assigned_role)
VALUES
(1, 4, 'Lead Investigator'),
(1, 1, 'Crime Scene Investigator'),
(1, 3, 'Forensic Analyst'),
(1, 5, 'Prosecutor');

/* ============================================================
   5. STORAGE LOCATIONS
   ============================================================ */
INSERT INTO storage_locations (location_code, description, room, shelf, locker, storage_type)
VALUES
('SCN-LOCK-01', 'Temporary scene evidence storage', 'Scene Vault', 'Shelf S1', 'L1', 'GENERAL'),
('MAIN-EVD-01', 'Main evidence room', 'Evidence Room A', 'Shelf 2', 'Locker 5', 'GENERAL'),
('BIO-VLT-01', 'Biological samples cold vault', 'Bio Lab', 'Shelf B1', 'Locker C2', 'COLD_STORAGE'),
('WEAP-LOCK-01', 'Gloves & garments locker', 'Weapons Room', 'Shelf W1', 'Locker 7', 'WEAPONS_LOCKER');


/* ============================================================
   6. EVIDENCE (ALL REAL CASE ITEMS)
   ============================================================ */
INSERT INTO evidence (case_id, evidence_code, description, evidence_type,
 collected_by_id, collected_datetime, collection_location,
 current_status, current_location_id)
VALUES
-- The Bundy glove
(1, 'OJ-GLOVE-1', 'Left leather glove found at Bundy crime scene', 'PHYSICAL',
 1, '1994-06-13 02:15:00', 'Bundy Drive Crime Scene', 'IN_STORAGE', 4),

-- Matching glove at Rockingham
(1, 'OJ-GLOVE-2', 'Right leather glove found at Simpson residence', 'PHYSICAL',
 1, '1994-06-13 10:00:00', 'Rockingham Estate Backyard', 'IN_STORAGE', 4),

-- Blood drop at scene
(1, 'OJ-BLOOD-1', 'Blood drop near the shoeprint at crime scene', 'BIOLOGICAL',
 1, '1994-06-13 03:00:00', 'Bundy walkway', 'IN_STORAGE', 3),

-- Blood-stained socks
(1, 'OJ-SOCKS-1', 'Blood-stained socks found in Simpson bedroom', 'BIOLOGICAL',
 1, '1994-06-13 11:00:00', 'Simpson Bedroom Closet', 'IN_STORAGE', 3),

-- Shoeprint cast (Bruno Magli)
(1, 'OJ-SHOE-CAST', 'Cast of Bruno Magli shoeprint', 'PHYSICAL',
 1, '1994-06-13 04:00:00', 'Bundy driveway path', 'IN_STORAGE', 1),

-- Bronco blood
(1, 'OJ-BRONCO-BLOOD', 'Blood stains collected from inside Bronco', 'BIOLOGICAL',
 1, '1994-06-13 09:00:00', 'Ford Bronco interior', 'IN_STORAGE', 3);


/* ============================================================
   7. EVIDENCE MEDIA (1 PER CATEGORY TO SHOW TABLE USAGE)
   ============================================================ */
INSERT INTO evidence_media (evidence_id, media_type, file_path, description, uploaded_by_id)
VALUES
(1, 'PHOTO', '/media/oj_glove_scene.jpg', 'Photo of Bundy glove', 1),
(3, 'PHOTO', '/media/oj_blood_drop.jpg', 'Photo of blood drop at walkway', 1),
(5, 'PHOTO', '/media/oj_shoeprint_cast.jpg', 'Cast of Bruno Magli shoeprint', 1);


/* ============================================================
   8. EVIDENCE INTAKE
   ============================================================ */
INSERT INTO evidence_intake (evidence_id, received_by_id, received_datetime,
 received_condition, intake_status, notes)
VALUES
(1, 2, '1994-06-13 05:00:00', 'Sealed bag', 'ACCEPTED', 'Stored in weapons locker'),
(2, 2, '1994-06-13 12:00:00', 'Sealed bag', 'ACCEPTED', 'Matching glove stored'),
(3, 2, '1994-06-13 05:30:00', 'Sealed', 'ACCEPTED', 'Blood sample placed in bio vault'),
(4, 2, '1994-06-13 12:30:00', 'Sealed', 'ACCEPTED', 'Socks placed in bio vault'),
(5, 2, '1994-06-13 05:45:00', 'Dry cast', 'ACCEPTED', 'Stored temporarily at SCN locker'),
(6, 2, '1994-06-13 10:00:00', 'Sealed', 'ACCEPTED', 'Bronco sample stored');


/* ============================================================
   9. CHAIN OF CUSTODY (EVERY EVIDENCE USED)
   ============================================================ */
INSERT INTO chain_of_custody 
(evidence_id, from_user_id, to_user_id, from_location_id, to_location_id, purpose, transfer_datetime, condition_notes)
VALUES
(1, 1, 2, 1, 4, 'Scene → Evidence Room', '1994-06-13 05:00:00', 'Sealed'),
(2, 1, 2, 1, 4, 'Scene → Evidence Room', '1994-06-13 12:00:00', 'Sealed'),
(3, 1, 2, 1, 3, 'Scene → Bio Vault',     '1994-06-13 05:30:00', 'Sealed'),
(4, 1, 2, 1, 3, 'Scene → Bio Vault',     '1994-06-13 12:30:00', 'Sealed'),
(5, 1, 2, 1, 1, 'Scene → Temporary Locker','1994-06-13 05:45:00','Dry'),
(6, 1, 2, 1, 3, 'Scene → Bio Vault',     '1994-06-13 10:00:00', 'Sealed');


/* ============================================================
   10. FORENSIC ANALYSIS (ALL CATEGORIES USED)
   ============================================================ */
INSERT INTO forensic_analysis (evidence_id, analyst_id, requested_by_id,
 analysis_type, lab_reference, analysis_status,
 requested_datetime, started_datetime, completed_datetime, summary)
VALUES
(1, 3, 4, 'DNA Testing on Glove Blood', 'DNA-OJ-001', 'COMPLETED',
 '1994-06-13 14:00:00','1994-06-13 15:00:00','1994-06-14 12:00:00',
 'Glove blood consistent with victims'),

(3, 3, 4, 'DNA Test on Crime Scene Blood Drop', 'DNA-OJ-002', 'COMPLETED',
 '1994-06-13 16:00:00','1994-06-13 17:00:00','1994-06-14 13:00:00',
 'Blood drop consistent with Simpson'),

(4, 3, 4, 'DNA Test on Blood-Stained Socks', 'DNA-OJ-003', 'COMPLETED',
 '1994-06-14 09:00:00','1994-06-14 09:30:00','1994-06-14 14:00:00',
 'Blood linked to Nicole Brown'),

(5, 3, 4, 'Shoeprint Comparison', 'SHOE-OJ-001', 'COMPLETED',
 '1994-06-13 18:00:00','1994-06-13 18:30:00','1994-06-14 10:00:00',
 'Cast matches Bruno Magli shoe worn by suspect'),

(6, 3, 4, 'DNA Test on Bronco Blood', 'DNA-OJ-004', 'COMPLETED',
 '1994-06-14 11:00:00','1994-06-14 11:15:00','1994-06-14 16:00:00',
 'DNA mixture includes Simpson & victims');


/* ============================================================
   11. ANALYSIS REPORTS
   ============================================================ */
INSERT INTO analysis_reports (analysis_id, report_title, report_file_path, created_by_id)
VALUES
(1, 'DNA Report – Glove Blood', '/reports/oj_glove_dna.pdf', 3),
(2, 'DNA Report – Crime Scene Blood Drop', '/reports/oj_blood_drop.pdf', 3),
(3, 'DNA Report – Socks Blood', '/reports/oj_socks_dna.pdf', 3),
(4, 'Shoeprint Analysis Report', '/reports/oj_shoeprint.pdf', 3),
(5, 'DNA Report – Bronco Blood', '/reports/oj_bronco_blood.pdf', 3);


/* ============================================================
   12. EVIDENCE NOTES (MEANINGFUL CASE INSIGHTS)
   ============================================================ */
INSERT INTO evidence_notes (evidence_id, user_id, note_text)
VALUES
(1, 4, 'Bundy glove became central forensic evidence.'),
(2, 4, 'Matching glove at Rockingham links suspect to scene.'),
(3, 3, 'Blood drop profile consistent with O.J. Simpson.'),
(4, 3, 'Sock blood DNA consistent with Nicole Brown.'),
(5, 4, 'Shoeprint suggests expensive Bruno Magli shoes worn by suspect.'),
(6, 3, 'Bronco blood showed DNA mixture: suspect + victims.');


/* ============================================================
   13. EVIDENCE ACCESS LOG
   ============================================================ */
INSERT INTO evidence_access_log (evidence_id, user_id, access_type, details)
VALUES
(1, 3, 'VIEW', 'Analyst inspected glove prior to DNA extraction'),
(3, 3, 'VIEW', 'Analyst prepared blood sample for PCR'),
(5, 4, 'VIEW', 'Detective reviewed shoeprint cast'),
(6, 3, 'VIEW', 'DNA analyst reviewed Bronco stains');


/* ============================================================
   14. DISPOSITION (REALISTIC OUTCOME)
   ============================================================ */
INSERT INTO disposition (evidence_id, disposition_type, disposition_datetime, authorized_by_id, notes)
VALUES
(1, 'PERMANENTLY_STORED', '1995-10-03 12:00:00', 5, 'Retained as historical evidence'),
(2, 'PERMANENTLY_STORED', '1995-10-03 12:00:00', 5, 'Retained with matching glove'),
(3, 'PERMANENTLY_STORED', '1995-10-03 12:00:00', 5, 'Biological evidence kept'),
(4, 'PERMANENTLY_STORED', '1995-10-03 12:00:00', 5, 'Socks retained'),
(5, 'PERMANENTLY_STORED', '1995-10-03 12:00:00', 5, 'Shoeprint cast archived'),
(6, 'PERMANENTLY_STORED', '1995-10-03 12:00:00', 5, 'Bronco blood kept');



/*******************************************************************************************
    SECTION 3.3 — QUERY DEVELOPMENT & DATA MANIPULATION
    This section includes:
    - SELECT ALL for each table
    - Five queries per table
    - Aggregate functions
    - Joins (Inner, Left, Right)
    - Views
    - GROUP BY + HAVING
    - Triggers
*******************************************************************************************/

---------------------------------------------
-- 3.3.1 SELECT ALL FROM EACH TABLE
---------------------------------------------
SELECT * FROM roles;
SELECT * FROM users;
SELECT * FROM cases;
SELECT * FROM case_assignments;
SELECT * FROM storage_locations;
SELECT * FROM evidence;
SELECT * FROM evidence_media;
SELECT * FROM evidence_intake;
SELECT * FROM chain_of_custody;
SELECT * FROM forensic_analysis;
SELECT * FROM analysis_reports;
SELECT * FROM evidence_notes;
SELECT * FROM evidence_access_log;
SELECT * FROM disposition;

---------------------------------------------
-- 3.3.2 Queries Per Table (At Least Five Per Table)
---------------------------------------------

/*************** ROLES ***************/
SELECT * 
FROM roles
ORDER BY role_name ASC;

SELECT role_id, role_name AS role_label
FROM roles
WHERE role_name IN ('CSI', 'Analyst');

SELECT DISTINCT description
FROM roles;

SELECT *
FROM roles
WHERE role_name NOT LIKE '%Admin%';

SELECT role_name
FROM roles
WHERE role_name LIKE 'C%'
UNION
SELECT role_name
FROM roles
WHERE role_name LIKE 'P%';


/*************** USERS ***************/
SELECT *
FROM users
ORDER BY full_name ASC;

SELECT full_name, email
FROM users
WHERE email LIKE '%@example.com';

SELECT username AS login_name, role_id
FROM users
WHERE is_active = 1
  AND phone LIKE '555%';

SELECT full_name
FROM users
WHERE role_id IN (1, 3, 4);

SELECT full_name
FROM users
WHERE role_id = 1
UNION
SELECT full_name
FROM users
WHERE role_id = 4;


/*************** CASES ***************/
SELECT *
FROM cases
WHERE status = 'CLOSED';

SELECT case_number, title
FROM cases
WHERE opened_date BETWEEN '1994-01-01' AND '1994-12-31';

SELECT case_number, closed_date
FROM cases
WHERE closed_date IS NULL;

SELECT c.case_number, c.title, u.full_name AS lead_investigator
FROM cases c
JOIN users u ON c.lead_investigator_id = u.user_id;

SELECT case_number
FROM cases
WHERE case_id IN (SELECT DISTINCT case_id FROM evidence);


/*************** CASE_ASSIGNMENTS ***************/
SELECT *
FROM case_assignments
WHERE case_id = 1;

SELECT DISTINCT assigned_role
FROM case_assignments
ORDER BY assigned_role;

SELECT case_id, COUNT(*) AS assigned_team_size
FROM case_assignments
GROUP BY case_id;

SELECT u.full_name, ca.assigned_role
FROM case_assignments ca
JOIN users u ON ca.user_id = u.user_id
ORDER BY ca.assigned_role;

SELECT *
FROM case_assignments
WHERE assigned_role NOT LIKE '%Analyst%';


/*************** STORAGE_LOCATIONS ***************/
SELECT *
FROM storage_locations
ORDER BY location_code ASC;

SELECT location_code, storage_type
FROM storage_locations
WHERE storage_type IN ('GENERAL', 'COLD_STORAGE');

SELECT DISTINCT room
FROM storage_locations;

SELECT *
FROM storage_locations
WHERE description LIKE '%evidence%' 
   OR description LIKE '%vault%';

SELECT location_id, location_code, is_active
FROM storage_locations
WHERE is_active = 1;


/*************** EVIDENCE ***************/
SELECT *
FROM evidence
WHERE evidence_type = 'BIOLOGICAL';

SELECT evidence_code, description
FROM evidence
WHERE description LIKE '%glove%' 
   OR description LIKE '%socks%';

SELECT evidence_code, collected_datetime
FROM evidence
ORDER BY collected_datetime ASC;

SELECT e.evidence_code, u.full_name AS collected_by, s.location_code AS current_location
FROM evidence e
JOIN users u ON e.collected_by_id = u.user_id
LEFT JOIN storage_locations s ON e.current_location_id = s.location_id;

SELECT evidence_type, COUNT(*) AS count_per_type
FROM evidence
GROUP BY evidence_type
HAVING COUNT(*) > 1;



/*************** EVIDENCE_MEDIA ***************/
SELECT *
FROM evidence_media
WHERE media_type = 'PHOTO';

SELECT file_path
FROM evidence_media
ORDER BY uploaded_at DESC;

SELECT DISTINCT media_type
FROM evidence_media;

SELECT em.evidence_id, em.file_path, e.evidence_code
FROM evidence_media em
JOIN evidence e ON em.evidence_id = e.evidence_id
WHERE e.description LIKE '%shoeprint%';

SELECT evidence_id, COUNT(*) AS media_count
FROM evidence_media
GROUP BY evidence_id;


/*************** EVIDENCE_INTAKE ***************/
SELECT *
FROM evidence_intake
WHERE intake_status = 'ACCEPTED';

SELECT evidence_id, received_datetime
FROM evidence_intake
ORDER BY received_datetime ASC;

SELECT received_by_id, COUNT(*) AS total_received
FROM evidence_intake
GROUP BY received_by_id;

SELECT e.evidence_code, u.full_name AS received_by, ei.received_condition
FROM evidence_intake ei
JOIN evidence e ON ei.evidence_id = e.evidence_id
JOIN users u ON ei.received_by_id = u.user_id;

SELECT *
FROM evidence_intake
WHERE received_datetime BETWEEN '1994-06-13 05:00:00' AND '1994-06-13 12:30:00';


/*************** CHAIN_OF_CUSTODY ***************/
SELECT *
FROM chain_of_custody
WHERE evidence_id = 1
ORDER BY transfer_datetime ASC;

SELECT evidence_id, COUNT(*) AS transfer_count
FROM chain_of_custody
GROUP BY evidence_id;

SELECT e.evidence_code, u.full_name AS to_user, c.transfer_datetime
FROM chain_of_custody c
JOIN evidence e ON c.evidence_id = e.evidence_id
JOIN users u ON c.to_user_id = u.user_id;

SELECT *
FROM chain_of_custody
WHERE from_location_id = 1
  AND to_location_id IN (3, 4);

SELECT *
FROM chain_of_custody
WHERE condition_notes LIKE '%Sealed%';


/*************** FORENSIC_ANALYSIS ***************/
SELECT *
FROM forensic_analysis
WHERE analysis_status = 'COMPLETED';

SELECT evidence_id, analysis_type, requested_datetime
FROM forensic_analysis
ORDER BY requested_datetime ASC;

SELECT analysis_type, COUNT(*) AS total_analyses
FROM forensic_analysis
GROUP BY analysis_type;

SELECT fa.analysis_id, e.evidence_code, u.full_name AS analyst
FROM forensic_analysis fa
JOIN evidence e ON fa.evidence_id = e.evidence_id
JOIN users u ON fa.analyst_id = u.user_id;

SELECT *
FROM forensic_analysis
WHERE analysis_type LIKE '%DNA%'
   OR analysis_type LIKE '%Shoeprint%';


/*************** ANALYSIS_REPORTS ***************/
SELECT *
FROM analysis_reports
ORDER BY created_at DESC;

SELECT report_title, report_file_path
FROM analysis_reports
WHERE report_title LIKE '%DNA%';

SELECT created_by_id, COUNT(*) AS reports_written
FROM analysis_reports
GROUP BY created_by_id;

SELECT ar.report_title, fa.analysis_type
FROM analysis_reports ar
JOIN forensic_analysis fa ON ar.analysis_id = fa.analysis_id;

SELECT DISTINCT analysis_id
FROM analysis_reports;


/*************** EVIDENCE_NOTES ***************/
SELECT *
FROM evidence_notes
WHERE note_text LIKE '%blood%';

SELECT evidence_id, COUNT(*) AS note_count
FROM evidence_notes
GROUP BY evidence_id;

SELECT *
FROM evidence_notes
ORDER BY created_at DESC;

SELECT e.evidence_code, en.note_text, u.full_name AS author
FROM evidence_notes en
JOIN evidence e ON en.evidence_id = e.evidence_id
JOIN users u ON en.user_id = u.user_id;

SELECT DISTINCT user_id
FROM evidence_notes;


/*************** EVIDENCE_ACCESS_LOG ***************/
SELECT *
FROM evidence_access_log
WHERE access_type = 'VIEW';

SELECT evidence_id, COUNT(*) AS access_count
FROM evidence_access_log
GROUP BY evidence_id;

SELECT *
FROM evidence_access_log
ORDER BY access_datetime DESC;

SELECT e.evidence_code, u.full_name, a.access_type, a.access_datetime
FROM evidence_access_log a
JOIN evidence e ON a.evidence_id = e.evidence_id
JOIN users u ON a.user_id = u.user_id;

SELECT DISTINCT access_type
FROM evidence_access_log;


/*************** DISPOSITION ***************/
SELECT *
FROM disposition
WHERE disposition_type = 'PERMANENTLY_STORED';

SELECT evidence_id, disposition_datetime
FROM disposition
ORDER BY disposition_datetime ASC;

SELECT disposition_type, COUNT(*) AS total_per_type
FROM disposition
GROUP BY disposition_type;

SELECT d.disposition_id, e.evidence_code, u.full_name AS authorized_by
FROM disposition d
JOIN evidence e ON d.evidence_id = e.evidence_id
JOIN users u ON d.authorized_by_id = u.user_id;

SELECT *
FROM disposition
WHERE disposition_datetime BETWEEN '1995-10-03 00:00:00'
                              AND '1995-10-03 23:59:59';


---------------------------------------------
-- 3.3.3 Aggregate Functions (At Least Two Per Table)
---------------------------------------------

-- ROLES
SELECT COUNT(*) AS total_roles,
       MIN(role_id) AS smallest_role_id,
       MAX(role_id) AS largest_role_id
FROM roles;

-- USERS
SELECT COUNT(*) AS total_users,
       MAX(user_id) AS max_user_id,
       MIN(user_id) AS min_user_id
FROM users;

-- CASES
SELECT COUNT(*) AS total_cases,
       MIN(opened_date) AS earliest_case_opened,
       MAX(opened_date) AS latest_case_opened
FROM cases;

-- CASE_ASSIGNMENTS
SELECT case_id,
       COUNT(user_id) AS total_assigned,
       MIN(assigned_at) AS first_assignment_time,
       MAX(assigned_at) AS last_assignment_time
FROM case_assignments
GROUP BY case_id;

-- STORAGE_LOCATIONS
SELECT COUNT(*) AS total_locations,
       COUNT(DISTINCT storage_type) AS distinct_storage_types
FROM storage_locations;

-- EVIDENCE
SELECT COUNT(*) AS total_evidence,
       COUNT(DISTINCT evidence_type) AS distinct_evidence_types
FROM evidence;

-- EVIDENCE_MEDIA
SELECT COUNT(*) AS total_media,
       MIN(uploaded_at) AS earliest_media,
       MAX(uploaded_at) AS latest_media
FROM evidence_media;

-- EVIDENCE_INTAKE
SELECT COUNT(*) AS total_intake_records,
       MIN(received_datetime) AS first_received,
       MAX(received_datetime) AS last_received
FROM evidence_intake;

-- CHAIN_OF_CUSTODY
SELECT COUNT(*) AS total_transfers,
       COUNT(DISTINCT evidence_id) AS evidences_moved
FROM chain_of_custody;

-- FORENSIC_ANALYSIS
SELECT COUNT(*) AS total_analyses,
       COUNT(DISTINCT analysis_type) AS distinct_analysis_types
FROM forensic_analysis;

-- ANALYSIS_REPORTS
SELECT COUNT(*) AS total_reports,
       MIN(created_at) AS first_report_time,
       MAX(created_at) AS last_report_time
FROM analysis_reports;

-- EVIDENCE_NOTES
SELECT COUNT(*) AS total_notes,
       COUNT(DISTINCT user_id) AS distinct_note_authors
FROM evidence_notes;

-- EVIDENCE_ACCESS_LOG
SELECT COUNT(*) AS total_access_events,
       COUNT(DISTINCT access_type) AS distinct_access_types
FROM evidence_access_log;

-- DISPOSITION
SELECT COUNT(*) AS total_disposition_records,
       COUNT(DISTINCT disposition_type) AS distinct_disposition_types
FROM disposition;


---------------------------------------------
-- 3.3.4 Join Queries (Inner / Outer Joins)
---------------------------------------------

-- Evidence with collector and current storage (INNER + LEFT)
SELECT e.evidence_code,
       e.evidence_type,
       u.full_name AS collected_by,
       s.location_code AS current_location
FROM evidence e
JOIN users u ON e.collected_by_id = u.user_id
LEFT JOIN storage_locations s ON e.current_location_id = s.location_id;

-- Chain of custody with evidence and destination user
SELECT e.evidence_code,
       c.transfer_datetime,
       u.full_name AS transferred_to,
       c.purpose
FROM chain_of_custody c
JOIN evidence e ON c.evidence_id = e.evidence_id
JOIN users u ON c.to_user_id = u.user_id
ORDER BY c.transfer_datetime;

-- Forensic analysis with evidence and analyst
SELECT fa.analysis_id,
       e.evidence_code,
       fa.analysis_type,
       u.full_name AS analyst
FROM forensic_analysis fa
JOIN evidence e ON fa.evidence_id = e.evidence_id
JOIN users u ON fa.analyst_id = u.user_id;

-- Analysis reports with analysis and analyst
SELECT ar.report_title,
       fa.analysis_type,
       u.full_name AS analyst
FROM analysis_reports ar
JOIN forensic_analysis fa ON ar.analysis_id = fa.analysis_id
JOIN users u ON fa.analyst_id = u.user_id;

-- Evidence intake with evidence, custodian (receiver), and initial location
SELECT e.evidence_code,
       u.full_name AS received_by,
       ei.received_datetime,
       ei.received_condition
FROM evidence_intake ei
JOIN evidence e ON ei.evidence_id = e.evidence_id
JOIN users u ON ei.received_by_id = u.user_id;


---------------------------------------------
-- 3.3.6 Views
---------------------------------------------
-- View 1: Case evidence summary (case + evidence basic info)
CREATE VIEW vw_case_evidence_summary AS
SELECT c.case_number,
       c.title,
       e.evidence_id,
       e.evidence_code,
       e.evidence_type,
       e.current_status
FROM cases c
JOIN evidence e ON c.case_id = e.case_id;


-- View 2: Evidence full chain history
CREATE VIEW vw_evidence_chain_history AS
SELECT e.evidence_code,
       c.transfer_datetime,
       u_from.full_name AS from_user,
       u_to.full_name   AS to_user,
       c.purpose,
       c.condition_notes
FROM chain_of_custody c
JOIN evidence e      ON c.evidence_id = e.evidence_id
LEFT JOIN users u_from ON c.from_user_id = u_from.user_id
JOIN users u_to       ON c.to_user_id   = u_to.user_id;


-- View 3: Analysis overview (evidence + analysis + report)
CREATE VIEW vw_analysis_overview AS
SELECT e.evidence_code,
       fa.analysis_type,
       fa.analysis_status,
       fa.requested_datetime,
       ar.report_title,
       ar.report_file_path
FROM forensic_analysis fa
JOIN evidence e       ON fa.evidence_id = e.evidence_id
LEFT JOIN analysis_reports ar ON fa.analysis_id = ar.analysis_id;

-- use examples of this three views
SELECT * FROM vw_case_evidence_summary;
SELECT * FROM vw_evidence_chain_history WHERE evidence_code = 'OJ-GLOVE-1';
SELECT * FROM vw_analysis_overview WHERE analysis_type LIKE '%DNA%';


---------------------------------------------
-- 3.3.7 Triggers
---------------------------------------------
-- Trigger 1: Log chain-of-custody automatically when evidence location or status changes
DELIMITER $$
CREATE TRIGGER trg_evidence_status_location_update
AFTER UPDATE ON evidence
FOR EACH ROW
BEGIN
    IF NEW.current_status <> OLD.current_status
       OR NEW.current_location_id <> OLD.current_location_id THEN

        INSERT INTO chain_of_custody (
            evidence_id,
            from_user_id,
            to_user_id,
            from_location_id,
            to_location_id,
            purpose,
            transfer_datetime,
            condition_notes
        )
        VALUES (
            NEW.evidence_id,
            NULL,
            NULL,
            OLD.current_location_id,
            NEW.current_location_id,
            CONCAT('Status/location changed from ', OLD.current_status, ' to ', NEW.current_status),
            NOW(),
            'Auto-logged by trigger'
        );
    END IF;
END$$
DELIMITER ;


-- Trigger 2: Automatically log access whenever a note is added for evidence
DELIMITER $$
CREATE TRIGGER trg_log_access_on_note
AFTER INSERT ON evidence_notes
FOR EACH ROW
BEGIN
    INSERT INTO evidence_access_log (
        evidence_id,
        user_id,
        access_datetime,
        access_type,
        details
    )
    VALUES (
        NEW.evidence_id,
        NEW.user_id,
        NOW(),
        'VIEW',
        'Note created for this evidence'
    );
END$$
DELIMITER ;


/*******************************************************************************************
    SECTION 3.5 — SECURITY & USER PERMISSIONS
     SECURITY SUMMARY:
   - Users are restricted to only the data they need.
   - Investigators: handle case/evidence.
   - Analysts: handle forensic results.
   - Custodians: manage storage & transfers.
   - Prosecutors: read-only for legal review.
   - SysAdmin: full administrative power.
*******************************************************************************************/

-- 3.5.1 — CREATE DATABASE USERS (for system roles)
CREATE USER 'investigator'@'%' IDENTIFIED BY '1234';
CREATE USER 'analyst'@'%' IDENTIFIED BY '1234';
CREATE USER 'custodian'@'%' IDENTIFIED BY '1234';
CREATE USER 'prosecutor'@'%' IDENTIFIED BY '1234';
CREATE USER 'sysadmin'@'%' IDENTIFIED BY '1234';

-- 3.5.2 — INVESTIGATOR PRIVILEGES 
-- Investigators should read case information and update evidence status.
GRANT SELECT, INSERT, UPDATE ON cases TO 'investigator'@'%';
GRANT SELECT, INSERT, UPDATE ON evidence TO 'investigator'@'%';
GRANT SELECT ON forensic_analysis TO 'investigator'@'%';
GRANT SELECT ON chain_of_custody TO 'investigator'@'%';

-- 3.5.3 — ANALYST PRIVILEGES
-- Laboratory analysts can run forensic analysis and upload reports.
GRANT SELECT, INSERT, UPDATE ON forensic_analysis TO 'analyst'@'%';
GRANT SELECT ON evidence TO 'analyst'@'%';
GRANT SELECT ON evidence_media TO 'analyst'@'%';
GRANT SELECT ON evidence_notes TO 'analyst'@'%';

-- 3.5.4 — CUSTODIAN PRIVILEGES
-- Custodian manages intake, storage, and evidence transfers.
GRANT SELECT, INSERT, UPDATE ON evidence_intake TO 'custodian'@'%';
GRANT SELECT, INSERT, UPDATE ON chain_of_custody TO 'custodian'@'%';
GRANT SELECT, UPDATE ON evidence TO 'custodian'@'%';

-- 3.5.5 — PROSECUTOR PRIVILEGES (READ-ONLY)
-- Prosecutors must NOT modify data. They only view evidence.
GRANT SELECT ON *.* TO 'prosecutor'@'%';

-- 3.5.6 — SYSADMIN PRIVILEGES
GRANT ALL PRIVILEGES ON *.* TO 'sysadmin'@'%' WITH GRANT OPTION;

-- 3.5.7 — APPLY PRIVILEGES
FLUSH PRIVILEGES;





