<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_role = $_SESSION["role"] ?? "";
$msg = "";

// 🔒 DENY ALL ACCESS if the role CANNOT view the ROLES table
if (!can_retrieve($current_role, "ROLES")) {
    echo "<div class='alert-error'>Access Denied: You do not have permission to view roles.</div>";
    exit;
}

// ✅ ADD ROLE (SysAdmin only)
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!can_add($current_role, "ROLES")) {
        echo "<div class='alert-error'>Access Denied: You do not have permission to add roles.</div>";
        exit;
    }

    $name = trim($_POST["role_name"] ?? "");
    $desc = trim($_POST["description"] ?? "");

    if ($name !== "") {
        $stmt = $conn->prepare("INSERT INTO roles (role_name, description) VALUES (?, ?)");
        $stmt->bind_param("ss", $name, $desc);
        if ($stmt->execute()) {
            $msg = "Role added.";
        } else {
            $msg = sfems_generic_db_error($stmt->error, "role insert");
        }
    }
}

// ✅ RETRIEVE ROLE LIST (SysAdmin only)
$roles = [];
if (can_retrieve($current_role, "ROLES")) {
    $res = $conn->query("SELECT * FROM roles ORDER BY role_id");
    while ($row = $res->fetch_assoc()) {
        $roles[] = $row;
    }
}
?>

<h2>Roles</h2>

<?php if ($msg): ?>
    <div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>

<!-- 🔒 ADD ROLE FORM - visible to SysAdmin only -->
<?php if (can_add($current_role, "ROLES")): ?>
<form method="post" action="index.php?page=roles" class="form-inline">
    <?= csrf_field() ?>
    <div>
        <label>Role Name</label>
        <input type="text" name="role_name" required>
    </div>
    <div>
        <label>Description</label>
        <input type="text" name="description">
    </div>
    <button class="btn-primary">Add Role</button>
</form>
<?php endif; ?>

<!-- 🔒 ROLES TABLE - visible to SysAdmin only -->
<?php if (can_retrieve($current_role, "ROLES")): ?>
    <table class="table">
    <tr><th>ID</th><th>Name</th><th>Description</th></tr>
    <?php foreach ($roles as $r): ?>
    <tr>
        <td><?= $r["role_id"] ?></td>
        <td><?= htmlspecialchars($r["role_name"]) ?></td>
        <td><?= htmlspecialchars($r["description"]) ?></td>
    </tr>
    <?php endforeach; ?>
    </table>
<?php endif; ?>
