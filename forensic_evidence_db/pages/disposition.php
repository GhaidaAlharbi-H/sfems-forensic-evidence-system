<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_user_id   = (int)$_SESSION["user_id"];
$current_role      = $_SESSION["role"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
// RBAC for DISPOSITION table
$canAddDisposition    = can_add($current_role, "DISPOSITION");
$canViewDisposition   = can_retrieve($current_role, "DISPOSITION");
$canUpdateDisposition = can_update($current_role, "DISPOSITION");
$canDeleteDisposition = can_delete($current_role, "DISPOSITION");
$msg      = "";
$editMode = false;
$editRow  = null;
/**
* Convert HTML datetime-local (YYYY-MM-DDTHH:MM) to MySQL DATETIME (YYYY-MM-DD HH:MM:SS)
*/
function normalize_datetime_from_input(?string $raw): ?string {
   if (!$raw) return null;
   $raw = trim($raw);
   $dt = str_replace('T', ' ', $raw);
   if (strlen($dt) === 16) {
       $dt .= ':00';
   }
   return $dt;
}
// ======================================================
// 1) HANDLE DELETE (POST + CSRF — was a plain GET link, fix #12)
// ======================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete") {
   $delete_id = (int)($_POST["disposition_id"] ?? 0);
   if (!$canDeleteDisposition) {
       $msg = "You do NOT have permission to delete disposition records.";
   } elseif ($delete_id > 0) {
       $stmt = $conn->prepare("DELETE FROM disposition WHERE disposition_id = ?");
       $stmt->bind_param("i", $delete_id);
       if ($stmt->execute()) {
           $msg = "Disposition record deleted.";
       } else {
           $msg = sfems_generic_db_error($stmt->error, "disposition delete");
       }
       $stmt->close();
   }
}
// ======================================================
// 2) HANDLE ADD / UPDATE (POST)
// ======================================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && in_array($_POST["action"] ?? "", ["add", "update"], true)) {
   $action = $_POST["action"];
   $evidence_id      = (int)($_POST["evidence_id"] ?? 0);
   $disposition_type = $_POST["disposition_type"] ?? "PERMANENTLY_STORED";
   $raw_dt           = $_POST["disposition_datetime"] ?? "";
   $notes            = trim($_POST["notes"] ?? "");
   $witness_id       = ($_POST["witness_user_id"] ?? "") !== "" ? (int)$_POST["witness_user_id"] : null;
   $disposition_datetime = normalize_datetime_from_input($raw_dt);

   if ($action === "add") {
       if (!$canAddDisposition) {
           $msg = "You do NOT have permission to add disposition records.";
       } else {
           $authorized_by_id = $current_user_id;
           // Fix #11: DESTROYED requires an independent witness, distinct
           // from the authorizer. Checked here (friendly message) and again
           // by the DB triggers trg_disposition_witness_insert /
           // trg_disposition_witness_update (belt & braces).
           if ($disposition_type === "DESTROYED" && (!$witness_id || $witness_id === $authorized_by_id)) {
               $msg = "Destroying evidence requires a witness who is a different person from the authorizer.";
           } elseif ($evidence_id && $disposition_type && $disposition_datetime) {
               $sql = "
                   INSERT INTO disposition
                       (evidence_id, disposition_type, disposition_datetime, authorized_by_id, witness_user_id, notes)
                   VALUES (?,?,?,?,?,?)
               ";
               $stmt = $conn->prepare($sql);
               $stmt->bind_param(
                   "issiis",
                   $evidence_id,
                   $disposition_type,
                   $disposition_datetime,
                   $authorized_by_id,
                   $witness_id,
                   $notes
               );
               if ($stmt->execute()) {
                   $msg = "Disposition recorded.";
               } else {
                   $msg = sfems_generic_db_error($stmt->error, "disposition insert");
               }
               $stmt->close();
           } else {
               $msg = "All fields marked * are required.";
           }
       }
   } elseif ($action === "update") {
       if (!$canUpdateDisposition) {
           $msg = "You do NOT have permission to update disposition records.";
       } else {
           $disposition_id = (int)($_POST["disposition_id"] ?? 0);
           // Need the authorizer on file to re-validate the witness rule
           $existingAuthorizer = null;
           if ($disposition_id) {
               $chk = $conn->prepare("SELECT authorized_by_id FROM disposition WHERE disposition_id = ?");
               $chk->bind_param("i", $disposition_id);
               $chk->execute();
               $existingAuthorizer = (int)($chk->get_result()->fetch_assoc()["authorized_by_id"] ?? 0);
               $chk->close();
           }
           if ($disposition_type === "DESTROYED" && (!$witness_id || $witness_id === $existingAuthorizer)) {
               $msg = "Destroying evidence requires a witness who is a different person from the authorizer.";
           } elseif ($disposition_id && $evidence_id && $disposition_type && $disposition_datetime) {
               $sql = "
                   UPDATE disposition
                   SET evidence_id = ?,
                       disposition_type = ?,
                       disposition_datetime = ?,
                       witness_user_id = ?,
                       notes = ?
                   WHERE disposition_id = ?
               ";
               $stmt = $conn->prepare($sql);
               $stmt->bind_param(
                   "issisi",
                   $evidence_id,
                   $disposition_type,
                   $disposition_datetime,
                   $witness_id,
                   $notes,
                   $disposition_id
               );
               if ($stmt->execute()) {
                   $msg      = "Disposition updated.";
                   $editMode = false;
                   $editRow  = null;
               } else {
                   $msg = sfems_generic_db_error($stmt->error, "disposition update");
               }
               $stmt->close();
           } else {
               $msg = "All fields marked * are required for update.";
           }
       }
   }
}
// ======================================================
// 3) LOAD RECORD FOR EDIT (?edit_id=...) AFTER POST
// ======================================================
if ($canUpdateDisposition && isset($_GET["edit_id"]) && $_SERVER["REQUEST_METHOD"] === "GET") {
   $edit_id = (int)$_GET["edit_id"];
   if ($edit_id > 0) {
       $stmt = $conn->prepare("
           SELECT d.*, e.evidence_code, u.full_name
           FROM disposition d
           JOIN evidence e ON d.evidence_id = e.evidence_id
           JOIN users   u ON d.authorized_by_id = u.user_id
           WHERE d.disposition_id = ?
       ");
       $stmt->bind_param("i", $edit_id);
       $stmt->execute();
       $result = $stmt->get_result();
       if ($row = $result->fetch_assoc()) {
           $editMode = true;
           $editRow  = $row;
       }
       $stmt->close();
   }
}
// ======================================================
// 4) DROPDOWNS & LIST
// ======================================================
if (!$canViewDisposition) {
   echo "<h2>You do NOT have permission to view disposition records.</h2>";
   return;
}
// Evidence dropdown
$evidence_list = $conn->query("
   SELECT evidence_id, evidence_code
   FROM evidence
   WHERE is_active = 1
   ORDER BY evidence_code
");
// Witness candidates (anyone but current user for add; UI still enforces != authorizer)
$witness_list = $conn->query("
   SELECT user_id, full_name
   FROM users
   WHERE is_active = 1
   ORDER BY full_name
");
// Records list
$list = $conn->query("
   SELECT d.*, e.evidence_code, u.full_name AS authorized_name, w.full_name AS witness_name
   FROM disposition d
   JOIN evidence e ON d.evidence_id = e.evidence_id
   JOIN users   u ON d.authorized_by_id = u.user_id
   LEFT JOIN users w ON d.witness_user_id = w.user_id
   ORDER BY d.disposition_id DESC
");
// ----------------------------------------------------
// 5) FORM PREFILL (ADD vs EDIT)
// ----------------------------------------------------
$form_action     = $editMode ? "update" : "add";
$form_title      = $editMode ? "Edit Disposition" : "Add Disposition";
$form_button_txt = $editMode ? "Update Disposition" : "Add Disposition";
$form_disposition_id = $editMode ? (int)$editRow["disposition_id"] : 0;
$form_evidence_id    = $editMode ? (int)$editRow["evidence_id"] : 0;
$form_type           = $editMode ? $editRow["disposition_type"] : "PERMANENTLY_STORED";
$form_notes          = $editMode ? $editRow["notes"] : "";
$form_witness_id     = $editMode ? (int)($editRow["witness_user_id"] ?? 0) : 0;
if ($editMode && !empty($editRow["disposition_datetime"])) {
   $form_datetime = date("Y-m-d\\TH:i", strtotime($editRow["disposition_datetime"]));
} else {
   $form_datetime = date("Y-m-d\\TH:i");
}
?>
<h2>Disposition</h2>
<p class="muted">
   Authorized By is automatically
<strong><?= htmlspecialchars($current_user_name) ?></strong>
   for new records. <strong>DESTROYED</strong> dispositions require an independent witness.
</p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAddDisposition || ($editMode && $canUpdateDisposition)): ?>
<h3><?= htmlspecialchars($form_title) ?></h3>
<form method="post" action="index.php?page=disposition" class="form-inline">
<?= csrf_field() ?>
<input type="hidden" name="action" value="<?= htmlspecialchars($form_action) ?>">
<?php if ($editMode): ?>
<input type="hidden" name="disposition_id" value="<?= $form_disposition_id ?>">
<?php endif; ?>
<div>
<label>Evidence *</label>
<select name="evidence_id" required>
<option value="">--Evidence--</option>
<?php
               $evidence_list->data_seek(0);
               while ($e = $evidence_list->fetch_assoc()):
                   $selected = ($form_evidence_id == (int)$e['evidence_id']) ? 'selected' : '';
               ?>
<option value="<?= $e['evidence_id'] ?>" <?= $selected ?>>
<?= htmlspecialchars($e['evidence_code']) ?>
</option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Disposition Type *</label>
<select name="disposition_type" id="disposition_type">
<option value="DESTROYED"          <?= $form_type === "DESTROYED" ? "selected" : "" ?>>DESTROYED</option>
<option value="RETURNED_TO_OWNER"  <?= $form_type === "RETURNED_TO_OWNER" ? "selected" : "" ?>>RETURNED_TO_OWNER</option>
<option value="PERMANENTLY_STORED" <?= $form_type === "PERMANENTLY_STORED" ? "selected" : "" ?>>PERMANENTLY_STORED</option>
<option value="OTHER"              <?= $form_type === "OTHER" ? "selected" : "" ?>>OTHER</option>
</select>
</div>
<div>
<label>Witness (required if DESTROYED)</label>
<select name="witness_user_id">
<option value="">--None--</option>
<?php
               $witness_list->data_seek(0);
               while ($w = $witness_list->fetch_assoc()):
                   $selected = ($form_witness_id === (int)$w['user_id']) ? 'selected' : '';
               ?>
<option value="<?= $w['user_id'] ?>" <?= $selected ?>>
<?= htmlspecialchars($w['full_name']) ?>
</option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Date &amp; Time *</label>
<input type="datetime-local"
                  name="disposition_datetime"
                  value="<?= htmlspecialchars($form_datetime) ?>"
                  required>
</div>
<div style="flex:1 1 100%;">
<label>Notes</label>
<input name="notes" value="<?= htmlspecialchars($form_notes) ?>">
</div>
<button class="btn-primary" type="submit"><?= htmlspecialchars($form_button_txt) ?></button>
<?php if ($editMode): ?>
<a href="index.php?page=disposition" class="btn-secondary">Cancel</a>
<?php endif; ?>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">Disposition Records</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Evidence</th>
<th>Type</th>
<th>Authorized By</th>
<th>Witness</th>
<th>When</th>
<th>Notes</th>
<?php if ($canUpdateDisposition): ?>
<th>Edit</th>
<?php endif; ?>
<?php if ($canDeleteDisposition): ?>
<th>Delete</th>
<?php endif; ?>
</tr>
<?php if ($list && $list->num_rows > 0): ?>
<?php while ($d = $list->fetch_assoc()): ?>
<tr>
<td><?= $d["disposition_id"] ?></td>
<td><?= htmlspecialchars($d["evidence_code"]) ?></td>
<td><?= htmlspecialchars($d["disposition_type"]) ?></td>
<td><?= htmlspecialchars($d["authorized_name"]) ?></td>
<td><?= htmlspecialchars($d["witness_name"] ?? "—") ?></td>
<td><?= htmlspecialchars($d["disposition_datetime"]) ?></td>
<td><?= htmlspecialchars($d["notes"]) ?></td>
<?php if ($canUpdateDisposition): ?>
<td>
<a href="index.php?page=disposition&edit_id=<?= $d['disposition_id'] ?>"
                          class="btn-secondary">
                           Edit
</a>
</td>
<?php endif; ?>
<?php if ($canDeleteDisposition): ?>
<td>
<form method="post" action="index.php?page=disposition" style="display:inline;"
      onsubmit="return confirm('Delete this disposition record?');">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="disposition_id" value="<?= $d['disposition_id'] ?>">
<button class="btn-danger" type="submit">Delete</button>
</form>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php else: ?>
<tr>
<td colspan="<?=
               7 + ($canUpdateDisposition ? 1 : 0) + ($canDeleteDisposition ? 1 : 0);
           ?>">
               No disposition records.
</td>
</tr>
<?php endif; ?>
</table>
