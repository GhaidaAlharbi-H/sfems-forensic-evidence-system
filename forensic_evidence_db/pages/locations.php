<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();
$current_role = $_SESSION["role"] ?? "";
// RBAC for STORAGE_LOCATIONS
$canAdd      = can_add($current_role, "STORAGE_LOCATIONS");
$canRetrieve = can_retrieve($current_role, "STORAGE_LOCATIONS");
$canUpdate   = can_update($current_role, "STORAGE_LOCATIONS");
$canDelete   = can_delete($current_role, "STORAGE_LOCATIONS");
if (!$canRetrieve) {
   http_response_code(403);
   echo "<h2>Access denied</h2><p>You do NOT have permission to view storage locations.</p>";
   exit();
}
$msg = "";
/* -----------------------------
  DELETE  (SysAdmin only per RBAC) — POST + CSRF (fix #12; was a GET link)
  ----------------------------- */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete") {
   if (!$canDelete) {
       $msg = "You do NOT have permission to delete storage locations.";
   } else {
       $id = (int)($_POST["location_id"] ?? 0);
       if ($id > 0) {
           $stmt = $conn->prepare("DELETE FROM storage_locations WHERE location_id = ?");
           $stmt->bind_param("i", $id);
           if ($stmt->execute()) {
               $msg = $stmt->affected_rows > 0 ? "Location deleted." : "Location not found or already deleted.";
           } else {
               // Likely foreign-key in use (evidence.current_location_id, chain_of_custody, etc.)
               $msg = "Delete failed: this location is still referenced by evidence or chain-of-custody records.";
           }
       }
   }
}
/* -----------------------------
  ADD
  ----------------------------- */
if (
   $canAdd &&
   $_SERVER["REQUEST_METHOD"] === "POST" &&
   ($_POST["action"] ?? "") === "add"
) {
   $code   = trim($_POST["location_code"] ?? "");
   $desc   = trim($_POST["description"] ?? "");
   $room   = trim($_POST["room"] ?? "");
   $shelf  = trim($_POST["shelf"] ?? "");
   $locker = trim($_POST["locker"] ?? "");
   $type   = $_POST["storage_type"] ?? "GENERAL";
   if ($code !== "") {
       $stmt = $conn->prepare("
           INSERT INTO storage_locations
               (location_code, description, room, shelf, locker, storage_type)
           VALUES (?,?,?,?,?,?)
       ");
       $stmt->bind_param("ssssss", $code, $desc, $room, $shelf, $locker, $type);
       if ($stmt->execute()) {
           $msg = "Location added.";
       } else {
           $msg = sfems_generic_db_error($stmt->error, "storage location insert");
       }
   } else {
       $msg = "Code is required.";
   }
}
/* -----------------------------
  UPDATE
  ----------------------------- */
if (
   $canUpdate &&
   $_SERVER["REQUEST_METHOD"] === "POST" &&
   ($_POST["action"] ?? "") === "update"
) {
   $id     = (int)($_POST["location_id"] ?? 0);
   $desc   = trim($_POST["description"] ?? "");
   $room   = trim($_POST["room"] ?? "");
   $shelf  = trim($_POST["shelf"] ?? "");
   $locker = trim($_POST["locker"] ?? "");
   $type   = $_POST["storage_type"] ?? "GENERAL";
   if ($id > 0) {
       $stmt = $conn->prepare("
           UPDATE storage_locations
              SET description = ?, room = ?, shelf = ?, locker = ?, storage_type = ?
            WHERE location_id = ?
       ");
       $stmt->bind_param("sssssi", $desc, $room, $shelf, $locker, $type, $id);
       if ($stmt->execute()) {
           $msg = "Location updated.";
       } else {
           $msg = sfems_generic_db_error($stmt->error, "storage location update");
       }
   }
}
/* -----------------------------
  READ
  ----------------------------- */
$res = $conn->query("SELECT * FROM storage_locations ORDER BY location_id");
?>
<h2>Storage Locations</h2>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAdd): ?>
<form method="post" action="index.php?page=locations" class="form-inline" style="margin-bottom:16px;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="add">
<div>
<label>Code *</label>
<input name="location_code" required>
</div>
<div>
<label>Description</label>
<input name="description">
</div>
<div>
<label>Room</label>
<input name="room">
</div>
<div>
<label>Shelf</label>
<input name="shelf">
</div>
<div>
<label>Locker</label>
<input name="locker">
</div>
<div>
<label>Type</label>
<select name="storage_type">
<option>GENERAL</option>
<option>COLD_STORAGE</option>
<option>WEAPONS_LOCKER</option>
<option>DIGITAL_VAULT</option>
<option>OTHER</option>
</select>
</div>
<button class="btn-primary">Add</button>
</form>
<?php else: ?>
<p class="muted">
       Only <strong>Custodian</strong> and <strong>SysAdmin</strong> can add locations.
</p>
<?php endif; ?>
<table class="table">
<tr>
<th>ID</th>
<th>Code</th>
<th>Description</th>
<th>Room</th>
<th>Shelf</th>
<th>Locker</th>
<th>Type</th>
<?php if ($canUpdate || $canDelete): ?>
<th>Action</th>
<?php endif; ?>
</tr>
<?php while ($r = $res->fetch_assoc()): ?>
<tr>
<td><?= (int)$r["location_id"] ?></td>
<td><?= htmlspecialchars($r["location_code"]) ?></td>
<?php if ($canUpdate): ?>
<!-- Editable fields; whole row is one form -->
<form method="post" action="index.php?page=locations" class="form-inline"
      onsubmit="if(event.submitter &amp;&amp; event.submitter.value==='delete'){return confirm('Delete this location?');}">
<?= csrf_field() ?>
<input type="hidden" name="location_id" value="<?= (int)$r["location_id"] ?>">
<td><input name="description" value="<?= htmlspecialchars($r["description"]) ?>"></td>
<td><input name="room"        value="<?= htmlspecialchars($r["room"]) ?>"></td>
<td><input name="shelf"       value="<?= htmlspecialchars($r["shelf"]) ?>"></td>
<td><input name="locker"      value="<?= htmlspecialchars($r["locker"]) ?>"></td>
<td>
<select name="storage_type">
<?php
                           $types = ["GENERAL","COLD_STORAGE","WEAPONS_LOCKER","DIGITAL_VAULT","OTHER"];
                           foreach ($types as $t):
                           ?>
<option <?= ($r["storage_type"] === $t ? "selected" : "") ?>><?= $t ?></option>
<?php endforeach; ?>
</select>
</td>
<td>
<?php if ($canUpdate): ?>
<button class="btn-secondary" type="submit" name="action" value="update">Save</button>
<?php endif; ?>
<?php if ($canDelete): ?>
<button class="btn-danger" type="submit" name="action" value="delete">Delete</button>
<?php endif; ?>
</td>
</form>
<?php else: ?>
<!-- Read-only display -->
<td><?= htmlspecialchars($r["description"]) ?></td>
<td><?= htmlspecialchars($r["room"]) ?></td>
<td><?= htmlspecialchars($r["shelf"]) ?></td>
<td><?= htmlspecialchars($r["locker"]) ?></td>
<td><?= htmlspecialchars($r["storage_type"]) ?></td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
</table>