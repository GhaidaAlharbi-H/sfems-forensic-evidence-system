<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();
$current_user_id   = (int)$_SESSION["user_id"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$current_role      = $_SESSION["role"] ?? "";
$msg = "";
// --------------------------------------------------
// RBAC for forensic_analysis table
// --------------------------------------------------
$RBAC_TABLE_KEY    = "ANALYSIS"; // must exist in $TABLE_PERMISSIONS in rbac.php
$canAddAnalysis    = can_add($current_role,      $RBAC_TABLE_KEY);
$canViewAnalysis   = can_retrieve($current_role, $RBAC_TABLE_KEY);
$canUpdateAnalysis = can_update($current_role,   $RBAC_TABLE_KEY);
$canDeleteAnalysis = can_delete($current_role,   $RBAC_TABLE_KEY);
if (!$canViewAnalysis) {
   die("<h2>You do NOT have permission to view forensic analyses.</h2>");
}
/* =========================================================
  ADD ANALYSIS
  ========================================================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {
   if (!$canAddAnalysis) {
       $msg = "You do not have permission to add forensic analysis records.";
   } else {
       $evidence_id      = (int)($_POST["evidence_id"] ?? 0);
       $analysis_type    = trim($_POST["analysis_type"] ?? "");
       $lab_reference    = trim($_POST["lab_reference"] ?? "");
       $analysis_status  = $_POST["analysis_status"] ?? "PENDING";
       $requested_dt     = $_POST["requested_datetime"] ?? "";
       $started_dt       = $_POST["started_datetime"] ?? null;
       $completed_dt     = $_POST["completed_datetime"] ?? null;
       $summary          = trim($_POST["summary"] ?? "");
       // analyst_id and requested_by_id = current user
       $analyst_id       = $current_user_id;
       $requested_by_id  = $current_user_id;
       if (!$evidence_id || $analysis_type === "" || $requested_dt === "") {
           $msg = "Evidence, analysis type, and requested datetime are required.";
       } else {
           $sql = "INSERT INTO forensic_analysis
                       (evidence_id, analyst_id, requested_by_id,
                        analysis_type, lab_reference, analysis_status,
                        requested_datetime, started_datetime, completed_datetime, summary)
                   VALUES (?,?,?,?,?,?,?,?,?,?)";
           $stmt = $conn->prepare($sql);
           $stmt->bind_param(
               "iiisssssss",
               $evidence_id,
               $analyst_id,
               $requested_by_id,
               $analysis_type,
               $lab_reference,
               $analysis_status,
               $requested_dt,
               $started_dt,
               $completed_dt,
               $summary
           );
           if ($stmt->execute()) {
               $msg = "Analysis record added successfully.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "analysis insert");
           }
           $stmt->close();
       }
   }
}
/* =========================================================
  UPDATE ANALYSIS
  ========================================================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "update") {
   if (!$canUpdateAnalysis) {
       $msg = "You do not have permission to update forensic analysis records.";
   } else {
       $analysis_id      = (int)($_POST["analysis_id"] ?? 0);
       $analysis_type    = trim($_POST["analysis_type"] ?? "");
       $lab_reference    = trim($_POST["lab_reference"] ?? "");
       $analysis_status  = $_POST["analysis_status"] ?? "PENDING";
       $started_dt       = $_POST["started_datetime"] ?? null;
       $completed_dt     = $_POST["completed_datetime"] ?? null;
       $summary          = trim($_POST["summary"] ?? "");
       if (!$analysis_id || $analysis_type === "") {
           $msg = "Analysis type is required.";
       } else {
           $sql = "UPDATE forensic_analysis
                      SET analysis_type      = ?,
                          lab_reference      = ?,
                          analysis_status    = ?,
                          started_datetime   = ?,
                          completed_datetime = ?,
                          summary            = ?
                    WHERE analysis_id = ?";
           $stmt = $conn->prepare($sql);
           $stmt->bind_param(
               "ssssssi",
               $analysis_type,
               $lab_reference,
               $analysis_status,
               $started_dt,
               $completed_dt,
               $summary,
               $analysis_id
           );
           if ($stmt->execute()) {
               $msg = "Analysis updated successfully.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "analysis update");
           }
           $stmt->close();
       }
   }
}
/* =========================================================
  DELETE ANALYSIS  (SysAdmin only via RBAC)
  ========================================================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete") {
   if (!$canDeleteAnalysis) {
       $msg = "You do not have permission to delete forensic analysis records.";
   } else {
       $analysis_id = (int)($_POST["analysis_id"] ?? 0);
       if ($analysis_id) {
           $stmt = $conn->prepare("DELETE FROM forensic_analysis WHERE analysis_id = ?");
           $stmt->bind_param("i", $analysis_id);
           if ($stmt->execute()) {
               $msg = "Analysis deleted.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "analysis delete");
           }
           $stmt->close();
       }
   }
}
/* =========================================================
  EVIDENCE LIST for ADD form
  ========================================================= */
$evidenceList = $conn->query("
   SELECT evidence_id, evidence_code
   FROM evidence
   WHERE is_active = 1
   ORDER BY evidence_code
");
/* =========================================================
  RETRIEVE ANALYSIS LIST (filtered per role)
  ========================================================= */
switch ($current_role) {
   case "Analyst":
       // Only analyses assigned to this analyst
       $sqlList = "
           SELECT fa.*, e.evidence_code,
                  auser.full_name AS analyst_name,
                  ruser.full_name AS requested_by_name
           FROM forensic_analysis fa
           JOIN evidence e       ON fa.evidence_id     = e.evidence_id
           JOIN users   auser    ON fa.analyst_id      = auser.user_id
           LEFT JOIN users ruser ON fa.requested_by_id = ruser.user_id
           WHERE fa.analyst_id = {$current_user_id}
           ORDER BY fa.analysis_id DESC
       ";
       break;
   case "Investigator":
       // Analyses for cases this investigator is assigned to
       $sqlList = "
           SELECT fa.*, e.evidence_code,
                  auser.full_name AS analyst_name,
                  ruser.full_name AS requested_by_name
           FROM forensic_analysis fa
           JOIN evidence e          ON fa.evidence_id = e.evidence_id
           JOIN cases c             ON e.case_id      = c.case_id
           JOIN case_assignments ca ON ca.case_id     = c.case_id
           JOIN users   auser       ON fa.analyst_id  = auser.user_id
           LEFT JOIN users ruser    ON fa.requested_by_id = ruser.user_id
           WHERE ca.user_id = {$current_user_id}
           ORDER BY fa.analysis_id DESC
       ";
       break;
   case "CSI":
       // Analyses for evidence collected by this CSI
       $sqlList = "
           SELECT fa.*, e.evidence_code,
                  auser.full_name AS analyst_name,
                  ruser.full_name AS requested_by_name
           FROM forensic_analysis fa
           JOIN evidence e       ON fa.evidence_id     = e.evidence_id
           JOIN users   auser    ON fa.analyst_id      = auser.user_id
           LEFT JOIN users ruser ON fa.requested_by_id = ruser.user_id
           WHERE e.collected_by_id = {$current_user_id}
           ORDER BY fa.analysis_id DESC
       ";
       break;
   default:
       // SysAdmin (and any other roles with retrieve) see all
       $sqlList = "
           SELECT fa.*, e.evidence_code,
                  auser.full_name AS analyst_name,
                  ruser.full_name AS requested_by_name
           FROM forensic_analysis fa
           JOIN evidence e       ON fa.evidence_id     = e.evidence_id
           JOIN users   auser    ON fa.analyst_id      = auser.user_id
           LEFT JOIN users ruser ON fa.requested_by_id = ruser.user_id
           ORDER BY fa.analysis_id DESC
       ";
}
$analysisRows = $conn->query($sqlList);
/* =========================================================
  If editing, load one analysis row (?edit=ID)
  ========================================================= */
$editAnalysis = null;
if ($canUpdateAnalysis && isset($_GET["edit"])) {
   $edit_id = (int)$_GET["edit"];
   if ($edit_id > 0) {
       $stmt = $conn->prepare("
           SELECT analysis_id, evidence_id, analysis_type, lab_reference,
                  analysis_status, requested_datetime, started_datetime,
                  completed_datetime, summary
           FROM forensic_analysis
           WHERE analysis_id = ?
       ");
       $stmt->bind_param("i", $edit_id);
       $stmt->execute();
       $editAnalysis = $stmt->get_result()->fetch_assoc();
       $stmt->close();
   }
}
?>
<h2>Forensic Analysis</h2>
<p class="muted">
   Analyst and Requested By are automatically set to:
<strong><?= htmlspecialchars($current_user_name) ?></strong>
</p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAddAnalysis): ?>
<h3>Add Analysis</h3>
<form method="post" class="form-inline" action="index.php?page=analysis">
<?= csrf_field() ?>
<input type="hidden" name="action" value="add">
<div>
<label>Evidence *</label>
<select name="evidence_id" required>
<option value="">--Evidence--</option>
<?php while($ev = $evidenceList->fetch_assoc()): ?>
<option value="<?= $ev["evidence_id"] ?>">
<?= htmlspecialchars($ev["evidence_code"]) ?>
</option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Analysis Type *</label>
<input type="text" name="analysis_type" required>
</div>
<div>
<label>Lab Reference</label>
<input type="text" name="lab_reference">
</div>
<div>
<label>Status</label>
<select name="analysis_status">
<option value="PENDING">PENDING</option>
<option value="IN_PROGRESS">IN_PROGRESS</option>
<option value="COMPLETED">COMPLETED</option>
<option value="CANCELLED">CANCELLED</option>
</select>
</div>
<div>
<label>Requested Datetime *</label>
<input type="datetime-local" name="requested_datetime" required>
</div>
<div>
<label>Started Datetime</label>
<input type="datetime-local" name="started_datetime">
</div>
<div>
<label>Completed Datetime</label>
<input type="datetime-local" name="completed_datetime">
</div>
<div style="flex:1 1 100%;">
<label>Summary</label>
<input type="text" name="summary">
</div>
<button class="btn-primary" type="submit">Add Analysis</button>
</form>
<?php endif; ?>
<?php if ($canUpdateAnalysis && $editAnalysis): ?>
<h3 style="margin-top:25px;">
       Edit Analysis #<?= (int)$editAnalysis["analysis_id"] ?>
</h3>
<form method="post" class="form-inline" action="index.php?page=analysis">
<?= csrf_field() ?>
<input type="hidden" name="action" value="update">
<input type="hidden" name="analysis_id" value="<?= (int)$editAnalysis["analysis_id"] ?>">
<div>
<label>Analysis Type *</label>
<input type="text" name="analysis_type"
                  value="<?= htmlspecialchars($editAnalysis["analysis_type"]) ?>" required>
</div>
<div>
<label>Lab Reference</label>
<input type="text" name="lab_reference"
                  value="<?= htmlspecialchars($editAnalysis["lab_reference"]) ?>">
</div>
<div>
<label>Status</label>
<select name="analysis_status">
<?php
               $statuses = ['PENDING','IN_PROGRESS','COMPLETED','CANCELLED'];
               foreach ($statuses as $st):
                   $sel = ($st === $editAnalysis["analysis_status"]) ? "selected" : "";
               ?>
<option value="<?= $st ?>" <?= $sel ?>><?= $st ?></option>
<?php endforeach; ?>
</select>
</div>
<div>
<label>Started Datetime</label>
<input type="datetime-local" name="started_datetime"
                  value="<?= $editAnalysis["started_datetime"]
                               ? str_replace(' ', 'T', $editAnalysis["started_datetime"])
                               : '' ?>">
</div>
<div>
<label>Completed Datetime</label>
<input type="datetime-local" name="completed_datetime"
                  value="<?= $editAnalysis["completed_datetime"]
                               ? str_replace(' ', 'T', $editAnalysis["completed_datetime"])
                               : '' ?>">
</div>
<div style="flex:1 1 100%;">
<label>Summary</label>
<input type="text" name="summary"
                  value="<?= htmlspecialchars($editAnalysis["summary"]) ?>">
</div>
<button class="btn-primary" type="submit">Save Changes</button>
<a href="index.php?page=analysis" class="btn-secondary">Cancel</a>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">Existing Analyses</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Evidence</th>
<th>Type</th>
<th>Status</th>
<th>Analyst</th>
<th>Requested</th>
<th>Completed</th>
<?php if ($canUpdateAnalysis || $canDeleteAnalysis): ?>
<th>Action</th>
<?php endif; ?>
</tr>
<?php if ($analysisRows && $analysisRows->num_rows > 0): ?>
<?php while($fa = $analysisRows->fetch_assoc()): ?>
<tr>
<td><?= $fa["analysis_id"] ?></td>
<td><?= htmlspecialchars($fa["evidence_code"]) ?></td>
<td><?= htmlspecialchars($fa["analysis_type"]) ?></td>
<td><?= htmlspecialchars($fa["analysis_status"]) ?></td>
<td><?= htmlspecialchars($fa["analyst_name"]) ?></td>
<td><?= htmlspecialchars($fa["requested_datetime"]) ?></td>
<td><?= htmlspecialchars($fa["completed_datetime"]) ?></td>
<?php if ($canUpdateAnalysis || $canDeleteAnalysis): ?>
<td>
<?php if ($canUpdateAnalysis): ?>
<a class="btn-secondary"
                              style="display:inline-block;margin-right:4px;"
                              href="index.php?page=analysis&edit=<?= $fa['analysis_id'] ?>">
                               Edit
</a>
<?php endif; ?>
<?php if ($canDeleteAnalysis): ?>
<form method="post"
                                 action="index.php?page=analysis"
                                 style="display:inline;"
                                 onsubmit="return confirm('Delete this analysis record?');">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="analysis_id" value="<?= $fa['analysis_id'] ?>">
<button class="btn-danger" type="submit">Delete</button>
</form>
<?php endif; ?>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php else: ?>
<tr><td colspan="8">No analysis records.</td></tr>
<?php endif; ?>
</table>