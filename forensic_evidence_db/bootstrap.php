<?php
// Shared bootstrap for every protected page. Include this (not db.php/rbac.php
// directly) at the top of every file in pages/ so that:
//   - direct requests to pages/*.php (bypassing index.php) still get a session
//     + auth check (fixes unauthenticated pages like intake.php/assignments.php)
//   - every POST request is checked for a valid CSRF token
//   - the session is hardened (secure cookie flags, idle timeout, id rotation)

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        "lifetime" => 0,
        "path"     => "/",
        "httponly" => true,
        "samesite" => "Lax",
        "secure"   => (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off"),
    ]);
    session_start();
}

require_once __DIR__ . "/db.php";
require_once __DIR__ . "/rbac.php";
require_once __DIR__ . "/csrf.php";
require_once __DIR__ . "/audit.php";

const SFEMS_IDLE_TIMEOUT_SECONDS = 900; // 15 minutes of inactivity

/** True when the currently running script lives in pages/ and was requested directly. */
function sfems_login_redirect_path(): string
{
    $script = str_replace("\\", "/", $_SERVER["SCRIPT_NAME"] ?? "");
    return (basename(dirname($script)) === "pages") ? "../login.php" : "login.php";
}

/**
 * Call at the top of every protected page. Enforces login, idle timeout,
 * and (for POST requests) a valid CSRF token.
 */
function sfems_require_login(): void
{
    if (!isset($_SESSION["user_id"], $_SESSION["role"])) {
        header("Location: " . sfems_login_redirect_path());
        exit();
    }

    if (isset($_SESSION["last_activity"]) && (time() - $_SESSION["last_activity"]) > SFEMS_IDLE_TIMEOUT_SECONDS) {
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), "", time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        session_destroy();
        header("Location: " . sfems_login_redirect_path() . "?timeout=1");
        exit();
    }
    $_SESSION["last_activity"] = time();

    if (($_SERVER["REQUEST_METHOD"] ?? "GET") === "POST") {
        sfems_verify_csrf();
    }
}
?>
