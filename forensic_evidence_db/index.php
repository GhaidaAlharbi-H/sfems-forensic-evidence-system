<?php
require "bootstrap.php";
sfems_require_login();

$current_user = $_SESSION["full_name"] ?? "User";
$current_role = $_SESSION["role"]      ?? "Role";
$initial      = strtoupper(mb_substr($current_user, 0, 1));
$page = $_GET["page"] ?? "dashboard";
$access_denied = false;
// Validate page & role
if (!isset($PAGE_ROLES[$page]) || !can_access_page($page, $current_role, $PAGE_ROLES)) {
   if ($page !== "dashboard") {
       $access_denied = true;
   }
   $page = "dashboard";
}
// Only allow routing to files that actually exist in pages/ (avoid path tricks)
$page = preg_replace('/[^a-z_]/', '', $page);
if (!is_file(__DIR__ . "/pages/$page.php")) {
    $page = "dashboard";
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SFEMS - <?= htmlspecialchars(ucfirst($page)) ?></title>
<link rel="stylesheet" href="assets/style.css">
<script src="assets/app.js" defer></script>
</head>
<body>
<header class="top-header">
<div class="logo">SFEMS</div>
<nav class="main-nav">
<?php if (can_access_page("dashboard", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=dashboard">Dashboard</a>
<?php endif; ?>
<?php if (can_access_page("cases", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=cases">Cases</a>
<?php endif; ?>
<?php if (can_access_page("evidence", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=evidence">Evidence</a>
<?php endif; ?>
<?php if (can_access_page("intake", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=intake">Intake</a>
<?php endif; ?>
<?php if (can_access_page("assignments", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=assignments">Assignments</a>
<?php endif; ?>
<?php if (can_access_page("chain", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=chain">Chain</a>
<?php endif; ?>
<?php if (can_access_page("analysis", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=analysis">Analysis</a>
<?php endif; ?>
<?php if (can_access_page("disposition", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=disposition">Disposition</a>
<?php endif; ?>
<?php if (can_access_page("media", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=media">Media</a>
<?php endif; ?>
<?php if (can_access_page("notes", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=notes">Notes</a>
<?php endif; ?>
<?php if (can_access_page("access", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=access">Access Log</a>
<?php endif; ?>
<?php if (can_access_page("users", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=users">Users</a>
<?php endif; ?>
<?php if (can_access_page("locations", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=locations">Locations</a>
<?php endif; ?>
<?php if (can_access_page("reports", $current_role, $PAGE_ROLES)): ?>
<a href="index.php?page=reports">Reports</a>
<?php endif; ?>
</nav>
<div class="user-chip">
<div class="avatar"><?= htmlspecialchars($initial) ?></div>
<div>
<div class="user-name"><?= htmlspecialchars($current_user) ?></div>
<div class="user-role"><?= htmlspecialchars($current_role) ?></div>
</div>
<a href="logout.php" class="logout">Logout</a>
</div>
</header>
<main class="content">
<?php if ($access_denied): ?>
<div class="alert-error">Access Denied. You were redirected to the dashboard.</div>
<?php endif; ?>
<?php include "pages/$page.php"; ?>
</main>
</body>
</html>
