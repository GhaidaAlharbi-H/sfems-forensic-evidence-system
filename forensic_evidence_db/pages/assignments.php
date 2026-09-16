<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_role = $_SESSION["role"];

// ---- RBAC flags for CASE_ASSIGNMENTS ----
// case_assignments controls who can see what evidence in evidence.php, so
// an unauthenticated write here was effectively an unauthenticated evidence
// read — this is the auth + RBAC check that was completely missing (fix #2).
$canAdd      = can_add($current_role, "CASE_ASSIGNMENTS");
$canRetrieve = can_retrieve($current_role, "CASE_ASSIGNMENTS");

if (!can_access_page("assignments", $current_role, $PAGE_ROLES) || !$canRetrieve) {
    http_response_code(403);
    die("<h2>You do NOT have permission to view case assignments.</h2>");
}

$msg = "";

$cases = $conn->query("SELECT case_id, case_number FROM cases ORDER BY case_number");
$users = $conn->query("SELECT user_id, full_name FROM users WHERE is_active = 1 ORDER BY full_name");

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!$canAdd) {
        $msg = "You do not have permission to create case assignments.";
    } else {
        $case = (int)($_POST["case_id"] ?? 0);
        $user = (int)($_POST["user_id"] ?? 0);
        $role = trim($_POST["assigned_role"] ?? "");
        if ($case && $user) {
            $stmt = $conn->prepare("INSERT INTO case_assignments (case_id, user_id, assigned_role) VALUES (?,?,?)");
            $stmt->bind_param("iis", $case, $user, $role);
            if ($stmt->execute()) {
                $msg = "Assignment saved.";
            } else {
                $msg = sfems_generic_db_error($stmt->error, "case_assignments insert");
            }
            $stmt->close();
        } else {
            $msg = "Select case & user.";
        }
    }
}

$list = $conn->query("
SELECT ca.*, c.case_number, u.full_name
FROM case_assignments ca
JOIN cases c ON ca.case_id = c.case_id
JOIN users u ON ca.user_id = u.user_id
ORDER BY ca.case_id, ca.user_id
");
?>
<h2>Case Assignments</h2>
<?php if ($msg): ?><div class="alert-success"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

<?php if ($canAdd): ?>
<form method="post" action="index.php?page=assignments" class="form-inline">
    <?= csrf_field() ?>
    <div>
        <label>Case *</label>
        <select name="case_id" required>
            <option value="">--Case--</option>
            <?php while($c = $cases->fetch_assoc()): ?>
                <option value="<?= $c["case_id"] ?>"><?= htmlspecialchars($c["case_number"]) ?></option>
            <?php endwhile; ?>
        </select>
    </div>
    <div>
        <label>User *</label>
        <select name="user_id" required>
            <option value="">--User--</option>
            <?php while($u = $users->fetch_assoc()): ?>
                <option value="<?= $u["user_id"] ?>"><?= htmlspecialchars($u["full_name"]) ?></option>
            <?php endwhile; ?>
        </select>
    </div>
    <div>
        <label>Assigned Role</label>
        <input name="assigned_role">
    </div>
    <button class="btn-primary">Assign</button>
</form>
<?php else: ?>
<p class="muted">Only <strong>Investigator</strong> and <strong>SysAdmin</strong> can create case assignments.</p>
<?php endif; ?>

<table class="table">
<tr><th>Case</th><th>User</th><th>Assigned Role</th><th>Assigned At</th></tr>
<?php while($a = $list->fetch_assoc()): ?>
<tr>
    <td><?= htmlspecialchars($a["case_number"]) ?></td>
    <td><?= htmlspecialchars($a["full_name"]) ?></td>
    <td><?= htmlspecialchars($a["assigned_role"]) ?></td>
    <td><?= htmlspecialchars($a["assigned_at"]) ?></td>
</tr>
<?php endwhile; ?>
</table>
