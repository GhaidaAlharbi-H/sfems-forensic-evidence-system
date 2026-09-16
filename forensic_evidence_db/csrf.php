<?php
// CSRF token helpers. Requires an active session.

function csrf_token(): string
{
    if (empty($_SESSION["csrf_token"])) {
        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
    }
    return $_SESSION["csrf_token"];
}

/** Echo a hidden CSRF input for a <form method="post"> block. */
function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES) . '">';
}

/** Verify the token on the current POST request; halts the request if invalid. */
function sfems_verify_csrf(): void
{
    $token = $_POST["csrf_token"] ?? "";
    if (empty($_SESSION["csrf_token"]) || !hash_equals($_SESSION["csrf_token"], $token)) {
        http_response_code(403);
        die("Your session has expired or this request could not be verified. Please go back, refresh the page, and try again.");
    }
}
?>
