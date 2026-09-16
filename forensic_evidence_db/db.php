<?php
// Database connection. Credentials live in config.php (gitignored) —
// see config.sample.php for the template.
require_once __DIR__ . "/config.php";

mysqli_report(MYSQLI_REPORT_OFF); // we handle errors ourselves; never let raw driver errors reach the browser

$conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME, $DB_PORT);
if ($conn->connect_error) {
    error_log("[SFEMS] DB connection failed: " . $conn->connect_error);
    http_response_code(500);
    die("A system error occurred. Please try again later.");
}
$conn->set_charset("utf8mb4");

/**
 * Log the real error server-side and return a generic message safe to show users.
 * Use this instead of echoing $stmt->error / $conn->error directly.
 */
function sfems_generic_db_error(string $realError, string $context = ""): string
{
    error_log("[SFEMS] " . ($context !== "" ? "$context: " : "") . $realError);
    return "A database error occurred. Please try again, or contact your administrator if the problem continues.";
}
?>
