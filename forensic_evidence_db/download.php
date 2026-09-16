<?php
// Gateway for serving media files and lab report files. Every file access
// goes through here so it can be authenticated, RBAC-checked, and logged
// automatically — this is what makes evidence_access_log DOWNLOAD entries
// server-observed instead of a self-report (see pages/access.php).
require "bootstrap.php";
sfems_require_login();

$current_user_id = (int)$_SESSION["user_id"];
$current_role     = $_SESSION["role"];

$type = $_GET["type"] ?? "";
$id   = (int)($_GET["id"] ?? 0);

if (!in_array($type, ["media", "report"], true) || $id <= 0) {
    http_response_code(400);
    die("Invalid request.");
}

if ($type === "media") {
    if (!can_retrieve($current_role, "MEDIA")) {
        http_response_code(403);
        die("You do not have permission to view media.");
    }
    $stmt = $conn->prepare("
        SELECT em.media_id, em.evidence_id, em.file_path, em.uploaded_by_id
        FROM evidence_media em
        WHERE em.media_id = ? AND em.is_active = 1
    ");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$row) {
        http_response_code(404);
        die("Not found.");
    }
    // Row-level scoping: Prosecutor may only pull media they uploaded (matches pages/media.php)
    if ($current_role === "Prosecutor" && (int)$row["uploaded_by_id"] !== $current_user_id) {
        http_response_code(403);
        die("You may only download media you uploaded.");
    }

    $relativePath = $row["file_path"];
    $evidenceId   = (int)$row["evidence_id"];
    $label        = "media #" . $row["media_id"];
} else {
    if (!can_retrieve($current_role, "LAB_REPORTS")) {
        http_response_code(403);
        die("You do not have permission to view lab reports.");
    }
    $stmt = $conn->prepare("
        SELECT r.report_id, fa.evidence_id, r.report_file_path
        FROM analysis_reports r
        JOIN forensic_analysis fa ON r.analysis_id = fa.analysis_id
        WHERE r.report_id = ?
    ");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$row) {
        http_response_code(404);
        die("Not found.");
    }
    $relativePath = $row["report_file_path"];
    $evidenceId   = (int)$row["evidence_id"];
    $label        = "report #" . $row["report_id"];
}

// Only allow serving files that live under this app's own directories —
// report file paths were historically free-text, so this guards against
// path traversal / arbitrary file disclosure.
$base = realpath(__DIR__);
$full = realpath(__DIR__ . "/" . ltrim($relativePath, "/"));
if ($full === false || strpos($full, $base) !== 0 || !is_file($full)) {
    http_response_code(404);
    die("File not found on disk.");
}

log_access($conn, $evidenceId, $current_user_id, "DOWNLOAD", "Downloaded $label");

$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime  = finfo_file($finfo, $full) ?: "application/octet-stream";
finfo_close($finfo);

header("Content-Type: " . $mime);
header("Content-Length: " . filesize($full));
header("Content-Disposition: inline; filename=\"" . basename($full) . "\"");
header("X-Content-Type-Options: nosniff");
readfile($full);
exit();
?>
