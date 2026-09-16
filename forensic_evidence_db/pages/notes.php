<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();
$current_user_id   = (int)$_SESSION["user_id"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$current_role      = $_SESSION["role"] ?? "";
$msg = "";
// ---- RBAC flags for NOTES table ----
$canAdd      = can_add($current_role, "NOTES");
$canRetrieve = can_retrieve($current_role, "NOTES");
$canUpdate   = can_update($current_role, "NOTES");
$canDelete   = can_delete($current_role, "NOTES");
// If they are not allowed to even see notes, stop here
if (!$canRetrieve) {
   die("<h2>You do NOT have permission to view evidence notes.</h2>");
}
// Evidence dropdown
$evidence_list = $conn->query("
   SELECT evidence_id, evidence_code
   FROM evidence
   WHERE is_active = 1
   ORDER BY evidence_code
");
// -------------------------------------------------------
// Handle POST actions: add / update / delete
// -------------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST") {
   $action = $_POST["action"] ?? "";
   // ADD NOTE
   if ($action === "add") {
       if (!$canAdd) {
           $msg = "You do not have permission to add notes.";
       } else {
           $evidence_id = (int)($_POST["evidence_id"] ?? 0);
           $note_text   = trim($_POST["note_text"] ?? "");
           $user_id     = $current_user_id;
           if ($evidence_id && $note_text !== "") {
               $stmt = $conn->prepare("
                   INSERT INTO evidence_notes (evidence_id, user_id, note_text)
                   VALUES (?,?,?)
               ");
               $stmt->bind_param("iis", $evidence_id, $user_id, $note_text);
               if ($stmt->execute()) {
                   $msg = "Note added.";
               } else {
                   $msg = sfems_generic_db_error($stmt->error, "note insert");
               }
           } else {
               $msg = "Evidence and note text are required.";
           }
       }
   // UPDATE NOTE
   } elseif ($action === "update") {
       if (!$canUpdate) {
           $msg = "You do not have permission to update notes.";
       } else {
           $note_id   = (int)($_POST["note_id"] ?? 0);
           $note_text = trim($_POST["note_text"] ?? "");
           if ($note_id && $note_text !== "") {
               // SysAdmin can update any note
               if ($current_role === "SysAdmin") {
                   $stmt = $conn->prepare("
                       UPDATE evidence_notes
                       SET note_text = ?
                       WHERE note_id = ?
                   ");
                   $stmt->bind_param("si", $note_text, $note_id);
               // Other roles: only their own notes
               } else {
                   $stmt = $conn->prepare("
                       UPDATE evidence_notes
                       SET note_text = ?
                       WHERE note_id = ? AND user_id = ?
                   ");
                   $stmt->bind_param("sii", $note_text, $note_id, $current_user_id);
               }
               if ($stmt->execute() && $stmt->affected_rows > 0) {
                   $msg = "Note updated.";
               } else {
                   $msg = "Could not update note (maybe not your note?).";
               }
           } else {
               $msg = "Note text is required.";
           }
       }
   // DELETE NOTE (SysAdmin only per RBAC)
   } elseif ($action === "delete") {
       if (!$canDelete) {
           $msg = "You do not have permission to delete notes.";
       } else {
           $note_id = (int)($_POST["note_id"] ?? 0);
           if ($note_id) {
               $stmt = $conn->prepare("
                   DELETE FROM evidence_notes
                   WHERE note_id = ?
               ");
               $stmt->bind_param("i", $note_id);
               if ($stmt->execute() && $stmt->affected_rows > 0) {
                   $msg = "Note deleted.";
               } else {
                   $msg = "Could not delete note.";
               }
           }
       }
   }
}
// -------------------------------------------------------
// List notes (all, since role-based filtering is not needed here)
// -------------------------------------------------------
$list = $conn->query("
SELECT n.*, e.evidence_code, u.full_name
FROM evidence_notes n
JOIN evidence e ON n.evidence_id = e.evidence_id
JOIN users   u ON n.user_id = u.user_id
ORDER BY n.note_id DESC
");
?>
<h2>Evidence Notes</h2>
<p class="muted">
   Notes are automatically attributed to <?= htmlspecialchars($current_user_name) ?>.
</p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAdd): ?>
<h3>Add Note</h3>
<form method="post" action="index.php?page=notes" class="form-inline">
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
<div style="flex:1 1 100%;">
<label>Note Text *</label>
<input name="note_text" required>
</div>
<button class="btn-primary">Add Note</button>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">Existing Notes</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Evidence</th>
<th>User</th>
<th>Note</th>
<th>When</th>
<?php if ($canUpdate || $canDelete): ?>
<th>Actions</th>
<?php endif; ?>
</tr>
<?php if ($list && $list->num_rows): ?>
<?php while($n = $list->fetch_assoc()): ?>
<tr>
<td><?= $n["note_id"] ?></td>
<td><?= htmlspecialchars($n["evidence_code"]) ?></td>
<td><?= htmlspecialchars($n["full_name"]) ?></td>
<td><?= htmlspecialchars($n["note_text"]) ?></td>
<td><?= htmlspecialchars($n["created_at"]) ?></td>
<?php if ($canUpdate || $canDelete): ?>
<td>
<?php if ($canUpdate && ($current_role === "SysAdmin" || $n["user_id"] == $current_user_id)): ?>
<!-- Inline edit form -->
<form method="post" action="index.php?page=notes" style="display:inline-block; margin-right:5px;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="update">
<input type="hidden" name="note_id" value="<?= $n["note_id"] ?>">
<input type="text" name="note_text"
                                      value="<?= htmlspecialchars($n["note_text"]) ?>">
<button type="submit" class="btn-secondary">Update</button>
</form>
<?php endif; ?>
<?php if ($canDelete): ?>
<!-- Delete form (SysAdmin only in RBAC) -->
<form method="post" action="index.php?page=notes" style="display:inline-block;"
                                 onsubmit="return confirm('Delete this note?');">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="note_id" value="<?= $n["note_id"] ?>">
<button type="submit" class="btn-danger">Delete</button>
</form>
<?php endif; ?>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php else: ?>
<tr><td colspan="<?= ($canUpdate || $canDelete) ? 6 : 5; ?>">No notes.</td></tr>
<?php endif; ?>
</table>