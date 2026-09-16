<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();
$current_user_id   = (int)$_SESSION["user_id"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$current_role      = $_SESSION["role"] ?? "";
$msg = "";
// ---- RBAC flags for USERS table ----
$canAdd      = can_add($current_role, "USERS");
$canRetrieve = can_retrieve($current_role, "USERS");
$canUpdate   = can_update($current_role, "USERS");
$canDelete   = can_delete($current_role, "USERS");
// If they are not allowed to see users at all, stop
if (!$canRetrieve) {
   die("<h2>You do NOT have permission to view users.</h2>");
}
// --------------------------------------------------
// Handle soft delete (SysAdmin only per RBAC) — POST + CSRF (fix #12; was a
// plain GET link that deactivated a user with no confirmation and no token)
// --------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "deactivate") {
   if (!$canDelete) {
       $msg = "You do NOT have permission to deactivate users.";
   } else {
       $delete_id = (int)($_POST["user_id"] ?? 0);
       if ($delete_id > 0) {
           $stmt = $conn->prepare("UPDATE users SET is_active = 0 WHERE user_id = ?");
           $stmt->bind_param("i", $delete_id);
           if ($stmt->execute()) {
               $msg = "User deactivated.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "user deactivate");
           }
       }
   }
}
// --------------------------------------------------
// Handle UPDATE user
// POST action=update
// --------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "update") {
   if (!$canUpdate) {
       $msg = "You do NOT have permission to update users.";
   } else {
       $user_id = (int)($_POST["user_id"] ?? 0);
       $role_id = (int)($_POST["role_id"] ?? 0);
       $full    = trim($_POST["full_name"] ?? "");
       $email   = trim($_POST["email"] ?? "");
       $user    = trim($_POST["username"] ?? "");
       $pass    = trim($_POST["password"] ?? "");   // optional on update
       $phone   = trim($_POST["phone"] ?? "");
       $active  = isset($_POST["is_active"]) ? 1 : 0;
       if ($pass !== "" && strlen($pass) < 8) {
           $msg = "New password must be at least 8 characters.";
       } elseif ($user_id && $role_id && $full && $email && $user) {
           if ($pass !== "") {
               $passHash = password_hash($pass, PASSWORD_DEFAULT);
               $stmt = $conn->prepare("
                   UPDATE users
                   SET role_id = ?, full_name = ?, email = ?, username = ?, password_hash = ?, phone = ?, is_active = ?
                   WHERE user_id = ?
               ");
               $stmt->bind_param("isssssii", $role_id, $full, $email, $user, $passHash, $phone, $active, $user_id);
           } else {
               // do not change password
               $stmt = $conn->prepare("
                   UPDATE users
                   SET role_id = ?, full_name = ?, email = ?, username = ?, phone = ?, is_active = ?
                   WHERE user_id = ?
               ");
               $stmt->bind_param("issssii", $role_id, $full, $email, $user, $phone, $active, $user_id);
           }
           if ($stmt->execute()) {
               $msg = "User updated.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "user update");
           }
       } else {
           $msg = "Role, name, email and username are required.";
       }
   }
}
// --------------------------------------------------
// Handle ADD user
// POST action=add
// --------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {
   if (!$canAdd) {
       $msg = "You do NOT have permission to add users.";
   } else {
       $role_id = (int)($_POST["role_id"] ?? 0);
       $full    = trim($_POST["full_name"] ?? "");
       $email   = trim($_POST["email"] ?? "");
       $user    = trim($_POST["username"] ?? "");
       $pass    = trim($_POST["password"] ?? "");
       $phone   = trim($_POST["phone"] ?? "");
       if (!($role_id && $full && $email && $user && $pass)) {
           $msg = "Fill all required fields.";
       } elseif (strlen($pass) < 8) {
           $msg = "Password must be at least 8 characters.";
       } else {
           $passHash = password_hash($pass, PASSWORD_DEFAULT);
           $stmt = $conn->prepare("
               INSERT INTO users (role_id, full_name, email, username, password_hash, phone)
               VALUES (?,?,?,?,?,?)
           ");
           $stmt->bind_param("isssss", $role_id, $full, $email, $user, $passHash, $phone);
           if ($stmt->execute()) {
               $msg = "User added.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "user insert");
           }
       }
   }
}
// --------------------------------------------------
// Data for dropdown + list
// --------------------------------------------------
$rolesAdd = $conn->query("SELECT role_id, role_name FROM roles ORDER BY role_name");
// If editing, load that user
$editUser = null;
$rolesEdit = null;
if ($canUpdate && isset($_GET["action"]) && $_GET["action"] === "edit") {
   $edit_id = (int)($_GET["id"] ?? 0);
   if ($edit_id > 0) {
       $res = $conn->query("
           SELECT user_id, role_id, full_name, email, username, phone, is_active
           FROM users
           WHERE user_id = {$edit_id}
           LIMIT 1
       ");
       if ($res && $res->num_rows === 1) {
           $editUser = $res->fetch_assoc();
           // separate roles result set for edit form
           $rolesEdit = $conn->query("SELECT role_id, role_name FROM roles ORDER BY role_name");
       }
   }
}
// List of users for table
$list = $conn->query("
   SELECT u.user_id, u.full_name, u.email, u.username, u.is_active, r.role_name
   FROM users u
   JOIN roles r ON u.role_id = r.role_id
   ORDER BY u.user_id
");
?>
<h2>Users</h2>
<p class="muted">User & role management.</p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAdd): ?>
<h3>Add User</h3>
<form method="post" action="index.php?page=users" class="form-inline">
<?= csrf_field() ?>
<input type="hidden" name="action" value="add">
<div>
<label>Role *</label>
<select name="role_id" required>
<option value="">--Role--</option>
<?php while($r = $rolesAdd->fetch_assoc()): ?>
<option value="<?= $r["role_id"] ?>"><?= htmlspecialchars($r["role_name"]) ?></option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Full Name *</label>
<input type="text" name="full_name" required>
</div>
<div>
<label>Email *</label>
<input type="text" name="email" required>
</div>
<div>
<label>Username *</label>
<input type="text" name="username" required>
</div>
<div>
<label>Password * (min 8 characters)</label>
<input type="password" name="password" minlength="8" required>
</div>
<div>
<label>Phone</label>
<input type="text" name="phone">
</div>
<button class="btn-primary">Add User</button>
</form>
<?php endif; ?>
<?php if ($canUpdate && $editUser): ?>
<hr>
<h3>Edit User #<?= $editUser["user_id"] ?></h3>
<form method="post" action="index.php?page=users" class="form-inline">
<?= csrf_field() ?>
<input type="hidden" name="action" value="update">
<input type="hidden" name="user_id" value="<?= $editUser['user_id'] ?>">
<div>
<label>Role *</label>
<select name="role_id" required>
<option value="">--Role--</option>
<?php while($r = $rolesEdit->fetch_assoc()): ?>
<option value="<?= $r["role_id"] ?>"
<?= ($r["role_id"] == $editUser["role_id"]) ? "selected" : "" ?>>
<?= htmlspecialchars($r["role_name"]) ?>
</option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Full Name *</label>
<input type="text" name="full_name"
              value="<?= htmlspecialchars($editUser['full_name']) ?>" required>
</div>
<div>
<label>Email *</label>
<input type="text" name="email"
              value="<?= htmlspecialchars($editUser['email']) ?>" required>
</div>
<div>
<label>Username *</label>
<input type="text" name="username"
              value="<?= htmlspecialchars($editUser['username']) ?>" required>
</div>
<div>
<label>New Password (optional, min 8 characters)</label>
<input type="password" name="password" minlength="8" placeholder="Leave blank to keep current">
</div>
<div>
<label>Phone</label>
<input type="text" name="phone"
              value="<?= htmlspecialchars($editUser['phone']) ?>">
</div>
<div>
<label>Active</label>
<input type="checkbox" name="is_active" value="1"
<?= $editUser["is_active"] ? "checked" : "" ?>>
</div>
<button class="btn-primary" type="submit">Save Changes</button>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">All Users</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Name</th>
<th>Email</th>
<th>Username</th>
<th>Role</th>
<th>Active</th>
<?php if ($canUpdate || $canDelete): ?>
<th>Actions</th>
<?php endif; ?>
</tr>
<?php if ($list && $list->num_rows > 0): ?>
<?php while($u = $list->fetch_assoc()): ?>
<tr>
<td><?= $u["user_id"] ?></td>
<td><?= htmlspecialchars($u["full_name"]) ?></td>
<td><?= htmlspecialchars($u["email"]) ?></td>
<td><?= htmlspecialchars($u["username"]) ?></td>
<td><?= htmlspecialchars($u["role_name"]) ?></td>
<td><?= $u["is_active"] ? "Yes" : "No" ?></td>
<?php if ($canUpdate || $canDelete): ?>
<td>
<?php if ($canUpdate): ?>
<a href="?page=users&action=edit&id=<?= $u['user_id'] ?>">Edit</a>
<?php endif; ?>
<?php if ($canDelete && $u["is_active"]): ?>
&nbsp;
<form method="post" action="index.php?page=users" style="display:inline;"
      onsubmit="return confirm('Deactivate this user?');">
<?= csrf_field() ?>
<input type="hidden" name="action" value="deactivate">
<input type="hidden" name="user_id" value="<?= (int)$u['user_id'] ?>">
<button type="submit" class="btn-danger" style="padding:2px 8px;">Deactivate</button>
</form>
<?php endif; ?>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php endif; ?>
</table>