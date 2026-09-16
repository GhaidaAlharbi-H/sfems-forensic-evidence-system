<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_user_id   = (int)$_SESSION["user_id"];
$current_role      = $_SESSION["role"];
$current_user_name = $_SESSION["full_name"] ?? "User";
$canAddEvidence    = can_add($current_role, "EVIDENCE");
$canUpdateEvidence = can_update($current_role, "EVIDENCE");
$canViewEvidence   = can_retrieve($current_role, "EVIDENCE");
$canDeleteEvidence = can_delete($current_role, "EVIDENCE");
$redirect = "index.php?page=evidence";
$msg      = "";
$editing  = null;
// ======================================================
// HANDLE DELETE (soft delete — keeps the audit trail intact, see fix #8/#16)
// ======================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete") {
   if ($canDeleteEvidence) {
       $id = (int)($_POST["evidence_id"] ?? 0);
       if ($id > 0) {
           $stmt = $conn->prepare("UPDATE evidence SET is_active = 0 WHERE evidence_id = ?");
           $stmt->bind_param("i", $id);
           if ($stmt->execute()) {
               $_SESSION["msg"] = "Evidence deactivated successfully.";
           } else {
               $_SESSION["msg"] = sfems_generic_db_error($stmt->error, "evidence soft-delete");
           }
           $stmt->close();
       }
   } else {
       $_SESSION["msg"] = "You do not have permission to delete evidence.";
   }
   header("Location: $redirect");
   exit();
}
// ======================================================
// HANDLE UPDATE
// ======================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "update") {
   if ($canUpdateEvidence) {
       $id      = (int)($_POST["evidence_id"] ?? 0);
       $desc    = trim($_POST["description"] ?? "");
       $loc     = trim($_POST["collection_location"] ?? "");
       $status  = $_POST["current_status"] ?? "";
       if ($id > 0 && $desc !== "" && $status !== "") {
           $stmt = $conn->prepare("
               UPDATE evidence
                  SET description = ?,
                      collection_location = ?,
                      current_status = ?
                WHERE evidence_id = ?
           ");
           $stmt->bind_param("sssi", $desc, $loc, $status, $id);
           if ($stmt->execute()) {
               $_SESSION["msg"] = "Evidence updated successfully.";
           } else {
               $_SESSION["msg"] = sfems_generic_db_error($stmt->error, "evidence update");
           }
           $stmt->close();
       } else {
           $_SESSION["msg"] = "Description and status are required.";
       }
   } else {
       $_SESSION["msg"] = "You do not have permission to update evidence.";
   }
   header("Location: $redirect");
   exit();
}
// ======================================================
// HANDLE ADD
// ======================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {
   if ($canAddEvidence) {
       $case   = (int)($_POST["case_id"] ?? 0);
       $code   = trim($_POST["evidence_code"] ?? "");
       $desc   = trim($_POST["description"] ?? "");
       $type   = $_POST["evidence_type"] ?? "";
       $dt     = $_POST["collected_datetime"] ?? "";
       $loc    = trim($_POST["collection_location"] ?? "");
       $status = "COLLECTED";
       $parent = ($_POST["parent_evidence_id"] ?? "") !== "" ? (int)$_POST["parent_evidence_id"] : null;
       // Convert HTML datetime-local ➜ MySQL DATETIME
       if (!empty($dt)) {
           $dt = str_replace("T", " ", $dt);
           if (strlen($dt) === 16) {
               $dt .= ":00"; // add seconds if missing
           }
       }
       if ($case && $code && $desc && $type && $dt) {
           $stmt = $conn->prepare("
               INSERT INTO evidence
                   (case_id, evidence_code, description, evidence_type,
                    collected_by_id, collected_datetime, collection_location, current_status, parent_evidence_id)
               VALUES (?,?,?,?,?,?,?,?,?)
           ");
           if ($stmt) {
               $stmt->bind_param(
                   "isssisssi",
                   $case,
                   $code,
                   $desc,
                   $type,
                   $current_user_id,
                   $dt,
                   $loc,
                   $status,
                   $parent
               );
               if ($stmt->execute()) {
                   $_SESSION["msg"] = "Evidence added successfully.";
               } else {
                   $_SESSION["msg"] = sfems_generic_db_error($stmt->error, "evidence insert");
               }
               $stmt->close();
           } else {
               $_SESSION["msg"] = sfems_generic_db_error($conn->error, "evidence insert prepare");
           }
       } else {
           $_SESSION["msg"] = "Please fill all required fields.";
       }
   } else {
       $_SESSION["msg"] = "You do not have permission to add evidence.";
   }
   header("Location: $redirect");
   exit();
}
// ======================================================
// GET EVIDENCE LIST (based on role) — active records only
// ======================================================
if (!$canViewEvidence) {
   die("Access denied.");
}
switch ($current_role) {
   case "CSI":
       // Only evidence collected by this CSI
       $sql = "
           SELECT e.*, c.case_number, p.evidence_code AS parent_code
             FROM evidence e
             JOIN cases c ON e.case_id = c.case_id
             LEFT JOIN evidence p ON e.parent_evidence_id = p.evidence_id
            WHERE e.collected_by_id = {$current_user_id} AND e.is_active = 1
            ORDER BY e.evidence_id DESC
       ";
       break;
   case "Investigator":
       // Evidence from cases this investigator is assigned to
       $sql = "
           SELECT e.*, c.case_number, p.evidence_code AS parent_code
             FROM evidence e
             JOIN cases c ON e.case_id = c.case_id
             JOIN case_assignments ca ON ca.case_id = c.case_id
             LEFT JOIN evidence p ON e.parent_evidence_id = p.evidence_id
            WHERE ca.user_id = {$current_user_id} AND e.is_active = 1
            ORDER BY e.evidence_id DESC
       ";
       break;
   case "Analyst":
       // Let Analyst see all active evidence they may need to work on
       $sql = "
           SELECT e.*, c.case_number, p.evidence_code AS parent_code
             FROM evidence e
             JOIN cases c ON e.case_id = c.case_id
             LEFT JOIN evidence p ON e.parent_evidence_id = p.evidence_id
            WHERE e.is_active = 1
            ORDER BY e.evidence_id DESC
       ";
       break;
   default:
       // SysAdmin + others with retrieve see all active
       $sql = "
           SELECT e.*, c.case_number, p.evidence_code AS parent_code
             FROM evidence e
             JOIN cases c ON e.case_id = c.case_id
             LEFT JOIN evidence p ON e.parent_evidence_id = p.evidence_id
            WHERE e.is_active = 1
            ORDER BY e.evidence_id DESC
       ";
}
$list  = $conn->query($sql);
$cases = $conn->query("SELECT case_id, case_number FROM cases ORDER BY case_number");
$parentOptions = $conn->query("SELECT evidence_id, evidence_code FROM evidence WHERE is_active = 1 ORDER BY evidence_code");

// Automatic access logging (fix #7): every evidence row actually rendered to
// this user counts as a server-observed VIEW, recorded once per row per page
// load — not a self-report form.
$viewedRows = [];
if ($list && $list->num_rows > 0) {
    while ($row = $list->fetch_assoc()) {
        $viewedRows[] = $row;
    }
    foreach ($viewedRows as $row) {
        log_access($conn, (int)$row["evidence_id"], $current_user_id, "VIEW", "Viewed in evidence list");
    }
}

// Editing row
$edit_id = isset($_GET["edit_id"]) ? (int)$_GET["edit_id"] : 0;
if ($edit_id > 0 && $canUpdateEvidence) {
   $stmt = $conn->prepare("SELECT * FROM evidence WHERE evidence_id = ?");
   $stmt->bind_param("i", $edit_id);
   $stmt->execute();
   $editing = $stmt->get_result()->fetch_assoc();
   $stmt->close();
}
// flash message
if (isset($_SESSION["msg"])) {
   $msg = $_SESSION["msg"];
   unset($_SESSION["msg"]);
}
?>
<h2>Evidence</h2>
<p class="muted">Logged in as: <strong><?= htmlspecialchars($current_user_name) ?></strong></p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAddEvidence): ?>
<h3>Add Evidence</h3>
<form method="post" action="index.php?page=evidence" class="form-inline">
<?= csrf_field() ?>
<input type="hidden" name="action" value="add">
<div>
<label>Case *</label>
<select name="case_id" required>
<option value="">-- Select Case --</option>
<?php while ($c = $cases->fetch_assoc()): ?>
<option value="<?= $c['case_id'] ?>"><?= htmlspecialchars($c['case_number']) ?></option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Evidence Code *</label>
<input type="text" name="evidence_code" required>
</div>
<div>
<label>Type *</label>
<select name="evidence_type" required>
<option>PHYSICAL</option>
<option>BIOLOGICAL</option>
<option>DIGITAL</option>
<option>DOCUMENT</option>
<option>WEAPON</option>
<option>OTHER</option>
</select>
</div>
<div>
<label>Datetime *</label>
<input type="datetime-local" name="collected_datetime" required>
</div>
<div>
<label>Location</label>
<input type="text" name="collection_location">
</div>
<div>
<label>Derived From (parent evidence)</label>
<select name="parent_evidence_id">
<option value="">-- None --</option>
<?php while ($p = $parentOptions->fetch_assoc()): ?>
<option value="<?= $p['evidence_id'] ?>"><?= htmlspecialchars($p['evidence_code']) ?></option>
<?php endwhile; ?>
</select>
</div>
<div style="flex:1 1 100%;">
<label>Description *</label>
<input type="text" name="description" required>
</div>
<button class="btn-primary">Add</button>
</form>
<?php endif; ?>
<h3>Existing Evidence</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Case</th>
<th>Code</th>
<th>Type</th>
<th>Status</th>
<th>Derived From</th>
<th>Collected</th>
<?php if ($canUpdateEvidence || $canDeleteEvidence): ?>
<th>Actions</th>
<?php endif; ?>
</tr>
<?php if (!empty($viewedRows)): ?>
<?php foreach ($viewedRows as $e): ?>
<tr>
<?php if ($editing && $editing['evidence_id'] == $e['evidence_id']): ?>
<!-- Edit row -->
<form method="post" action="index.php?page=evidence">
<?= csrf_field() ?>
<input type="hidden" name="action" value="update">
<input type="hidden" name="evidence_id" value="<?= (int)$e['evidence_id'] ?>">
<td><?= (int)$e['evidence_id'] ?></td>
<td><?= htmlspecialchars($e['case_number']) ?></td>
<td><?= htmlspecialchars($e['evidence_code']) ?></td>
<td><?= htmlspecialchars($e['evidence_type']) ?></td>
<td>
<select name="current_status">
<?php
                           $statuses = [
                               'COLLECTED',
                               'SUBMITTED',
                               'IN_STORAGE',
                               'IN_LAB',
                               'IN_COURT',
                               'DISPOSED',
                               'RETURNED'
                           ];
                           foreach ($statuses as $st):
                               $sel = ($st === $e['current_status']) ? "selected" : "";
                           ?>
<option value="<?= $st ?>" <?= $sel ?>><?= $st ?></option>
<?php endforeach; ?>
</select>
</td>
<td><?= htmlspecialchars($e['parent_code'] ?? '') ?></td>
<td><?= htmlspecialchars($e['collected_datetime']) ?></td>
<td>
<input type="text" name="description"
                              value="<?= htmlspecialchars($e['description']) ?>">
<input type="text" name="collection_location"
                              value="<?= htmlspecialchars($e['collection_location']) ?>">
<button class="btn-primary">Save</button>
<a href="index.php?page=evidence" class="btn-secondary">Cancel</a>
</td>
</form>
<?php else: ?>
<!-- Normal row -->
<td><?= (int)$e['evidence_id'] ?></td>
<td><?= htmlspecialchars($e['case_number']) ?></td>
<td><?= htmlspecialchars($e['evidence_code']) ?></td>
<td><?= htmlspecialchars($e['evidence_type']) ?></td>
<td><?= htmlspecialchars($e['current_status']) ?></td>
<td><?= htmlspecialchars($e['parent_code'] ?? '—') ?></td>
<td><?= htmlspecialchars($e['collected_datetime']) ?></td>
<?php if ($canUpdateEvidence || $canDeleteEvidence): ?>
<td>
<?php if ($canUpdateEvidence): ?>
<a href="index.php?page=evidence&edit_id=<?= (int)$e['evidence_id'] ?>"
                              class="btn-secondary">Edit</a>
<?php endif; ?>
<?php if ($canDeleteEvidence): ?>
<form method="post" action="index.php?page=evidence" style="display:inline;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="evidence_id" value="<?= (int)$e['evidence_id'] ?>">
<button class="btn-danger"
                                       onclick="return confirm('Deactivate this evidence record? It will be hidden but its audit trail is preserved.')">Delete</button>
</form>
<?php endif; ?>
</td>
<?php endif; ?>
<?php endif; ?>
</tr>
<?php endforeach; ?>
<?php else: ?>
<tr><td colspan="8">No evidence records.</td></tr>
<?php endif; ?>
</table>
