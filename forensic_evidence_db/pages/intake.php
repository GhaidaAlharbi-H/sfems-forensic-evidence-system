<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_user_id   = (int)$_SESSION["user_id"];
$current_role      = $_SESSION["role"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";

// ---- RBAC flags for INTAKE (evidence_intake) ----
$canAdd      = can_add($current_role, "INTAKE");
$canRetrieve = can_retrieve($current_role, "INTAKE");

if (!can_access_page("intake", $current_role, $PAGE_ROLES) || !$canRetrieve) {
    http_response_code(403);
    die("<h2>You do NOT have permission to view evidence intake.</h2>");
}

$msg = "";

$evidence = $conn->query("SELECT evidence_id, evidence_code FROM evidence WHERE is_active = 1 ORDER BY evidence_code");
$users    = $conn->query("SELECT user_id, full_name FROM users WHERE is_active = 1 ORDER BY full_name");

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!$canAdd) {
        $msg = "You do not have permission to record evidence intake.";
    } else {
        $eid   = (int)($_POST["evidence_id"] ?? 0);
        $recBy = (int)($_POST["received_by_id"] ?? 0);
        $dt    = $_POST["received_datetime"] ?? "";
        if (!empty($dt)) {
            $dt = str_replace("T", " ", $dt);
            if (strlen($dt) === 16) {
                $dt .= ":00";
            }
        }
        $cond  = trim($_POST["received_condition"] ?? "");
        $stat  = $_POST["intake_status"] ?? "ACCEPTED";
        $notes = trim($_POST["notes"] ?? "");
        if ($eid && $recBy && $dt) {
            $stmt = $conn->prepare("
                INSERT INTO evidence_intake (evidence_id, received_by_id, received_datetime, received_condition, intake_status, notes)
                VALUES (?,?,?,?,?,?)
            ");
            $stmt->bind_param("iissss", $eid, $recBy, $dt, $cond, $stat, $notes);
            if ($stmt->execute()) {
                $msg = "Intake recorded.";
            } else {
                $msg = sfems_generic_db_error($stmt->error, "intake insert");
            }
            $stmt->close();
        } else {
            $msg = "Evidence, receiver, datetime required.";
        }
    }
}

$list = $conn->query("
SELECT ei.*, e.evidence_code, u.full_name
FROM evidence_intake ei
JOIN evidence e ON ei.evidence_id = e.evidence_id
JOIN users u ON ei.received_by_id = u.user_id
ORDER BY ei.intake_id DESC
");
?>
<h2>Evidence Intake</h2>
<?php if ($msg): ?><div class="alert-success"><?= htmlspecialchars($msg) ?></div><?php endif; ?>

<?php if ($canAdd): ?>
<form method="post" action="index.php?page=intake" class="form-inline">
    <?= csrf_field() ?>
    <div>
        <label>Evidence *</label>
        <select name="evidence_id" required>
            <option value="">--Evidence--</option>
            <?php while($e = $evidence->fetch_assoc()): ?>
                <option value="<?= $e["evidence_id"] ?>"><?= htmlspecialchars($e["evidence_code"]) ?></option>
            <?php endwhile; ?>
        </select>
    </div>
    <div>
        <label>Received By *</label>
        <select name="received_by_id" required>
            <option value="">--User--</option>
            <?php while($u = $users->fetch_assoc()): ?>
                <option value="<?= $u["user_id"] ?>"><?= htmlspecialchars($u["full_name"]) ?></option>
            <?php endwhile; ?>
        </select>
    </div>
    <div><label>Received Datetime *</label><input type="datetime-local" name="received_datetime" required></div>
    <div><label>Condition</label><input name="received_condition"></div>
    <div>
        <label>Status</label>
        <select name="intake_status">
            <option>ACCEPTED</option>
            <option>PENDING</option>
            <option>REJECTED</option>
        </select>
    </div>
    <div style="flex:1 1 100%">
        <label>Notes</label><input name="notes"></div>
    <button class="btn-primary">Record Intake</button>
</form>
<?php else: ?>
<p class="muted">Only <strong>Custodian</strong> and <strong>SysAdmin</strong> can record evidence intake.</p>
<?php endif; ?>

<table class="table">
<tr><th>ID</th><th>Evidence</th><th>Received By</th><th>Datetime</th><th>Status</th><th>Condition</th></tr>
<?php while($i = $list->fetch_assoc()): ?>
<tr>
    <td><?= $i["intake_id"] ?></td>
    <td><?= htmlspecialchars($i["evidence_code"]) ?></td>
    <td><?= htmlspecialchars($i["full_name"]) ?></td>
    <td><?= htmlspecialchars($i["received_datetime"]) ?></td>
    <td><?= htmlspecialchars($i["intake_status"]) ?></td>
    <td><?= htmlspecialchars($i["received_condition"]) ?></td>
</tr>
<?php endwhile; ?>
</table>
