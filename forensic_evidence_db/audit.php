<?php
// Forensic-integrity helpers: automatic access logging and file hashing.
// Requires $conn (mysqli) from db.php.

/**
 * Record a server-observed access event. Call this at the point access
 * actually happens (a view or a download), never as a manual self-report.
 */
function log_access(mysqli $conn, int $evidenceId, int $userId, string $accessType, string $details = ""): void
{
    $stmt = $conn->prepare(
        "INSERT INTO evidence_access_log (evidence_id, user_id, access_type, details) VALUES (?,?,?,?)"
    );
    if (!$stmt) {
        error_log("[SFEMS] log_access prepare failed: " . $conn->error);
        return;
    }
    $stmt->bind_param("iiss", $evidenceId, $userId, $accessType, $details);
    $stmt->execute();
    $stmt->close();
}

/** SHA-256 of a file on disk, or null if it can't be read. */
function sfems_hash_file(string $path): ?string
{
    if (!is_file($path) || !is_readable($path)) {
        return null;
    }
    $hash = hash_file("sha256", $path);
    return $hash !== false ? $hash : null;
}

/**
 * Record a hash verification check to the append-only hash_verification_log table.
 * $tableName is 'evidence_media' or 'analysis_reports'.
 */
function log_hash_verification(
    mysqli $conn,
    string $tableName,
    int $recordId,
    ?int $evidenceId,
    ?string $expectedHash,
    ?string $computedHash,
    int $verifiedById,
    string $result
): void {
    $stmt = $conn->prepare(
        "INSERT INTO hash_verification_log
            (table_name, record_id, evidence_id, expected_hash, computed_hash, verified_by_id, result)
         VALUES (?,?,?,?,?,?,?)"
    );
    if (!$stmt) {
        error_log("[SFEMS] log_hash_verification prepare failed: " . $conn->error);
        return;
    }
    $stmt->bind_param("siissis", $tableName, $recordId, $evidenceId, $expectedHash, $computedHash, $verifiedById, $result);
    $stmt->execute();
    $stmt->close();
}
?>
