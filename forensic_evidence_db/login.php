<?php
session_set_cookie_params([
    "lifetime" => 0,
    "path"     => "/",
    "httponly" => true,
    "samesite" => "Lax",
    "secure"   => (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off"),
]);
session_start();
require "db.php";
require "csrf.php";

// Already logged in? Don't re-show the login form.
if (isset($_SESSION["user_id"])) {
    header("Location: index.php");
    exit();
}

$error = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    sfems_verify_csrf();

    $email    = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($email === "" || $password === "") {
        $error = "Please enter email and password.";
    } else {
        $sql = "SELECT u.user_id, u.full_name, u.password_hash, r.role_name
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                WHERE u.email = ? AND u.is_active = 1
                LIMIT 1";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $res = $stmt->get_result();
        $user = ($res && $res->num_rows === 1) ? $res->fetch_assoc() : null;
        $stmt->close();

        // Always run password_verify (even against a dummy hash) so login takes
        // the same time whether or not the email exists — avoids leaking which
        // emails are registered via response timing, on top of the identical
        // error message below.
        $hashToCheck = $user["password_hash"] ?? '$2y$10$invalidinvalidinvaliduinvalidinvalidinvalidinvalidin';
        $ok = password_verify($password, $hashToCheck);

        if ($user && $ok) {
            session_regenerate_id(true);
            $_SESSION["user_id"]       = $user["user_id"];
            $_SESSION["full_name"]     = $user["full_name"];
            $_SESSION["role"]          = $user["role_name"];
            $_SESSION["email"]         = $email;
            $_SESSION["last_activity"] = time();
            unset($_SESSION["csrf_token"]); // force a fresh token post-login

            header("Location: index.php");
            exit();
        } else {
            // Same message whether the email doesn't exist or the password is wrong.
            $error = "Incorrect email or password.";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SFEMS Login</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body class="login-bg">
<div class="login-card">
    <h2>SFEMS Login</h2>
    <p class="muted">Forensic Evidence Management System</p>

    <?php if (isset($_GET["timeout"])): ?>
        <div class="alert-error">You were signed out due to inactivity. Please log in again.</div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="POST">
        <?= csrf_field() ?>
        <label>Email</label>
        <input type="text" name="email" required>

        <label>Password</label>
        <input type="password" name="password" required>

        <button class="btn-primary" type="submit">Login</button>
    </form>
</div>
</body>
</html>
