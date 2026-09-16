<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();
$current_user_id   = (int)$_SESSION["user_id"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$current_role      = $_SESSION["role"] ?? "";
// ------------------------------
// RBAC permissions for CASES
// ------------------------------
$canAddCase    = can_add($current_role, "CASES");        // SysAdmin + Investigator
$canViewCases  = can_retrieve($current_role, "CASES");
$canUpdateCase = can_update($current_role, "CASES");     // SysAdmin + Investigator
$canDeleteCase = can_delete($current_role, "CASES");     // SysAdmin only (from RBAC)
$isSysAdmin = ($current_role === "SysAdmin");
$msg = "";
// ========================================
// ENFORCE VIEW PERMISSION
// ========================================
if (!$canViewCases) {
   die("<h2>You are not allowed to view cases.</h2>");
}
// ========================================
// DELETE case (only if role is allowed)
// ========================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete") {
   if (!$canDeleteCase) {
       $msg = "You are not allowed to delete cases.";
   } else {
       $case_id = (int)($_POST["case_id"] ?? 0);
       if ($case_id > 0) {
           $sql  = "DELETE FROM cases WHERE case_id = ?";
           $stmt = $conn->prepare($sql);
           $stmt->bind_param("i", $case_id);
           if ($stmt->execute()) {
               $msg = "Case deleted.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "case delete");
           }
           $stmt->close();
       }
   }
   // Redirect back to routed page (fixes 404)
   header("Location: index.php?page=cases");
   exit;
}
// ========================================
// ADD case (only if role is allowed)
// ========================================
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {
   if (!$canAddCase) {
       // Someone tried to POST directly without permission
       $msg = "You are not allowed to add cases.";
   } else {
       $case_number  = trim($_POST["case_number"] ?? "");
       $title        = trim($_POST["title"] ?? "");
       $description  = trim($_POST["description"] ?? "");
       $status       = $_POST["status"] ?? "OPEN";
       $opened_date  = $_POST["opened_date"] ?? "";
       $closed_date  = $_POST["closed_date"] ?? null;
       // Lead investigator = current user
       $lead_id = $current_user_id;
       if ($case_number && $title && $opened_date) {
           $sql = "INSERT INTO cases
                   (case_number, title, description, status, opened_date, closed_date, lead_investigator_id)
                   VALUES (?,?,?,?,?,?,?)";
           $stmt = $conn->prepare($sql);
           $stmt->bind_param(
               "ssssssi",
               $case_number,
               $title,
               $description,
               $status,
               $opened_date,
               $closed_date,
               $lead_id
           );
           if ($stmt->execute()) {
               $msg = "Case created.";
               // also add the lead investigator into case_assignments
               $new_case_id = $stmt->insert_id;
               if ($new_case_id && $lead_id) {
                   $assignSql = "INSERT INTO case_assignments (case_id, user_id, assigned_role)
                                 VALUES (?,?,?)";
                   $assignStmt = $conn->prepare($assignSql);
                   $leadLabel  = "Lead Investigator";
                   $assignStmt->bind_param("iis", $new_case_id, $lead_id, $leadLabel);
                   $assignStmt->execute();
                   $assignStmt->close();
               }
           } else {
               $msg = sfems_generic_db_error($stmt->error, "case insert");
           }
           $stmt->close();
       } else {
           $msg = "Case number, title, and opened date are required.";
       }
   }
}
// ========================================
// LOAD CASES
// ========================================
if ($isSysAdmin) {
   // SysAdmin sees each assignment on its own row
   $sql = "
       SELECT
           c.case_id,
           c.case_number,
           c.title,
           c.status,
           c.opened_date,
           u_team.full_name,
           ca.assigned_role
       FROM cases c
       LEFT JOIN case_assignments ca
           ON ca.case_id = c.case_id
       LEFT JOIN users u_team
           ON ca.user_id = u_team.user_id
       ORDER BY c.case_id, u_team.full_name
   ";
} else {
   // Regular users see basic case list + lead investigator
   $sql = "
       SELECT
           c.case_id,
           c.case_number,
           c.title,
           c.status,
           c.opened_date,
           u.full_name AS lead_name
       FROM cases c
       LEFT JOIN users u
           ON c.lead_investigator_id = u.user_id
       ORDER BY c.case_id
   ";
}
$list = $conn->query($sql);
// Do we have any row-level actions?
$hasActions = $canUpdateCase || $canDeleteCase;
?>
<h2>Cases</h2>
<p class="muted">
<?php if ($canAddCase): ?>
       Lead Investigator for new cases is the current user:
<strong><?= htmlspecialchars($current_user_name) ?></strong>
<?php else: ?>
       You can view cases. Only <strong>Investigator</strong> and <strong>SysAdmin</strong> can create new cases.
<?php endif; ?>
</p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAddCase): ?>
<h3>Add Case</h3>
<form method="post" action="index.php?page=cases" class="form-inline">
<?= csrf_field() ?>
<input type="hidden" name="action" value="add">
<div>
<label>Case Number *</label>
<input type="text" name="case_number" required>
</div>
<div>
<label>Title *</label>
<input type="text" name="title" required>
</div>
<div style="flex:1 1 100%;">
<label>Description</label>
<input type="text" name="description">
</div>
<div>
<label>Status</label>
<select name="status">
<option value="OPEN">OPEN</option>
<option value="UNDER_INVESTIGATION">UNDER_INVESTIGATION</option>
<option value="CLOSED">CLOSED</option>
<option value="ARCHIVED">ARCHIVED</option>
</select>
</div>
<div>
<label>Opened Date *</label>
<input type="date" name="opened_date" required>
</div>
<div>
<label>Closed Date</label>
<input type="date" name="closed_date">
</div>
<button class="btn-primary" type="submit">Add Case</button>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">Existing Cases</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Number</th>
<th>Title</th>
<th>Status</th>
<th>Opened</th>
<?php if ($isSysAdmin): ?>
<th>Name</th>
<th>Case Role</th>
<?php else: ?>
<th>Lead Investigator</th>
<?php endif; ?>
<?php if ($hasActions): ?>
<th>Actions</th>
<?php endif; ?>
</tr>
<?php if ($isSysAdmin): ?>
<?php
   $haveRows = false;
   while ($row = $list->fetch_assoc()):
       $haveRows = true;
       $caseId   = (int)$row["case_id"];
       $number   = htmlspecialchars($row["case_number"]);
       $title    = htmlspecialchars($row["title"]);
       $status   = htmlspecialchars($row["status"]);
       $opened   = htmlspecialchars($row["opened_date"]);
       $name     = $row["full_name"]     ? htmlspecialchars($row["full_name"])     : "—";
       $caseRole = $row["assigned_role"] ? htmlspecialchars($row["assigned_role"]) : "No assignments";
   ?>
<tr>
<td><?= $caseId ?></td>
<td><?= $number ?></td>
<td><?= $title ?></td>
<td><?= $status ?></td>
<td><?= $opened ?></td>
<td><?= $name ?></td>
<td><?= $caseRole ?></td>
<?php if ($hasActions): ?>
<td>
<?php if ($canUpdateCase): ?>
<!-- Add your own edit page if you want -->
<a href="index.php?page=edit_case&id=<?= $caseId ?>" class="btn-secondary">Edit</a>
<?php endif; ?>
<?php if ($canDeleteCase): ?>
<form method="post" action="index.php?page=cases" style="display:inline;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="case_id" value="<?= $caseId ?>">
<button type="submit"
                                   class="btn-danger"
                                   onclick="return confirm('Are you sure you want to delete this case?');">
                               Delete
</button>
</form>
<?php endif; ?>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php if (!$haveRows): ?>
<tr><td colspan="<?= $hasActions ? 8 : 7; ?>">No cases found.</td></tr>
<?php endif; ?>
<?php else: ?>
<?php if ($list->num_rows === 0): ?>
<tr><td colspan="<?= $hasActions ? 7 : 6; ?>">No cases found.</td></tr>
<?php else: ?>
<?php while ($row = $list->fetch_assoc()): ?>
<?php $caseId = (int)$row["case_id"]; ?>
<tr>
<td><?= $caseId ?></td>
<td><?= htmlspecialchars($row["case_number"]) ?></td>
<td><?= htmlspecialchars($row["title"]) ?></td>
<td><?= htmlspecialchars($row["status"]) ?></td>
<td><?= htmlspecialchars($row["opened_date"]) ?></td>
<td><?= htmlspecialchars($row["lead_name"] ?? "—") ?></td>
<?php if ($hasActions): ?>
<td>
<?php if ($canUpdateCase): ?>
<a href="index.php?page=edit_case&id=<?= $caseId ?>" class="btn-secondary">Edit</a>
<?php endif; ?>
<?php if ($canDeleteCase): ?>
<form method="post" action="index.php?page=cases" style="display:inline;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="case_id" value="<?= $caseId ?>">
<button type="submit"
                                       class="btn-danger"
                                       onclick="return confirm('Are you sure you want to delete this case?');">
                                   Delete
</button>
</form>
<?php endif; ?>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php endif; ?>
<?php endif; ?>
</table>