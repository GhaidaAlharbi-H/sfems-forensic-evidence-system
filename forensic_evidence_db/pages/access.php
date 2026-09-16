<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_user_id   = (int)$_SESSION["user_id"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$current_role      = $_SESSION["role"];
$msg = "";
// ---- RBAC flags for AUDIT_LOGS (evidence_access_log) ----
$canAdd      = can_add($current_role, "AUDIT_LOGS");
$canRetrieve = can_retrieve($current_role, "AUDIT_LOGS");
if (!$canRetrieve) {
   http_response_code(403);
   die("<h2>You do NOT have permission to view the access log.</h2>");
}
// Evidence dropdown
$evidence_list = $conn->query("
   SELECT evidence_id, evidence_code
   FROM evidence
   WHERE is_active = 1
   ORDER BY evidence_code
");
// -------------------------------------------------------
// Handle ADD access log entry — self-declared only. VIEW and DOWNLOAD are
// now recorded automatically at the point they actually happen (see
// log_access() calls in pages/evidence.php and download.php), so this
// manual form is restricted to actions the server genuinely cannot
// observe: printing or exporting something after it left the app.
// -------------------------------------------------------
$selfDeclaredTypes = ["PRINT", "EXPORT", "OTHER"];
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {
   if (!$canAdd) {
       $msg = "You do NOT have permission to add access log entries.";
   } else {
       $evidence_id = (int)($_POST["evidence_id"] ?? 0);
       $access_type = $_POST["access_type"] ?? "";
       $details     = trim($_POST["details"] ?? "");
       $user_id     = $current_user_id;
       if ($evidence_id && in_array($access_type, $selfDeclaredTypes, true)) {
           $details = "[Self-declared] " . $details;
           $stmt = $conn->prepare("
               INSERT INTO evidence_access_log (evidence_id, user_id, access_type, details)
               VALUES (?,?,?,?)
           ");
           $stmt->bind_param("iiss", $evidence_id, $user_id, $access_type, $details);
           if ($stmt->execute()) {
               $msg = "Access entry recorded.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "access log insert");
           }
           $stmt->close();
       } else {
           $msg = "Evidence and a valid access type (PRINT/EXPORT/OTHER) are required.";
       }
   }
}
// -------------------------------------------------------
// List log entries
// -------------------------------------------------------
$list = $conn->query("
   SELECT l.*, e.evidence_code, u.full_name
   FROM evidence_access_log l
   JOIN evidence e ON l.evidence_id = e.evidence_id
   JOIN users   u ON l.user_id      = u.user_id
   ORDER BY l.access_id DESC
");
?>
<h2>Access Log</h2>
<p class="muted">
   VIEW and DOWNLOAD entries are recorded automatically by the server when they happen.
   PRINT and EXPORT entries below are self-declared by the user, since the server
   cannot observe what happens after a file leaves the application.
</p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAdd): ?>
<h3>Declare a Print / Export</h3>
<form method="post" action="index.php?page=access" class="form-inline">
<?= csrf_field() ?>
<input type="hidden" name="action" value="add">
<div>
<label>Evidence *</label>
<select name="evidence_id" required>
<option value="">--Evidence--</option>
<?php while($e = $evidence_list->fetch_assoc()): ?>
<option value="<?= $e['evidence_id'] ?>">
<?= htmlspecialchars($e['evidence_code']) ?>
</option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Access Type *</label>
<select name="access_type" required>
<option value="">--Select--</option>
<option>PRINT</option>
<option>EXPORT</option>
<option>OTHER</option>
</select>
</div>
<div style="flex:1 1 100%;">
<label>Details</label>
<input name="details">
</div>
<button class="btn-primary">Add Entry</button>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">Access History</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Evidence</th>
<th>User</th>
<th>Type</th>
<th>Source</th>
<th>Details</th>
<th>When</th>
</tr>
<?php if ($list && $list->num_rows): ?>
<?php while($a = $list->fetch_assoc()): ?>
<?php $isSelfDeclared = in_array($a["access_type"], $selfDeclaredTypes, true); ?>
<tr>
<td><?= $a["access_id"] ?></td>
<td><?= htmlspecialchars($a["evidence_code"]) ?></td>
<td><?= htmlspecialchars($a["full_name"]) ?></td>
<td><?= htmlspecialchars($a["access_type"]) ?></td>
<td><?= $isSelfDeclared ? "Self-declared" : "Automatic" ?></td>
<td><?= htmlspecialchars($a["details"]) ?></td>
<td><?= htmlspecialchars($a["access_datetime"]) ?></td>
</tr>
<?php endwhile; ?>
<?php else: ?>
<tr><td colspan="7">No access log entries.</td></tr>
<?php endif; ?>
</table>
