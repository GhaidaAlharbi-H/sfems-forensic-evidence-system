<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();
$current_user_id   = (int)$_SESSION["user_id"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$current_role      = $_SESSION["role"] ?? "";
// --------------------------------------------------
// RBAC for LAB_REPORTS (analysis_reports table)
// --------------------------------------------------
$RBAC_TABLE_KEY   = "LAB_REPORTS"; // key from rbac.php
$canAddReport     = can_add($current_role, $RBAC_TABLE_KEY);
$canViewReport    = can_retrieve($current_role, $RBAC_TABLE_KEY);
$canUpdateReport  = can_update($current_role, $RBAC_TABLE_KEY);
$canDeleteReport  = can_delete($current_role, $RBAC_TABLE_KEY);
if (!$canViewReport) {
   die("<h2>You do NOT have permission to view lab / forensic reports.</h2>");
}
$msg = "";
/* =========================================================
  ADD REPORT
  ========================================================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {
   if (!$canAddReport) {
       $msg = "You do not have permission to add lab reports.";
   } else {
       $analysis_id      = (int)($_POST["analysis_id"] ?? 0);
       $report_title     = trim($_POST["report_title"] ?? "");
       $report_file_path = trim($_POST["report_file_path"] ?? "");
       $author_id        = $current_user_id;
       if (!$analysis_id || $report_title === "" || $report_file_path === "") {
           $msg = "Analysis, report title, and file path are required.";
       } else {
           // Fix #6: record a baseline hash at intake if the referenced file
           // actually exists under the app's own directory.
           $sha256 = null;
           $full = realpath(__DIR__ . "/../" . ltrim($report_file_path, "/"));
           $base = realpath(__DIR__ . "/..");
           if ($full !== false && strpos($full, $base) === 0) {
               $sha256 = sfems_hash_file($full);
           }
           $sql = "
               INSERT INTO analysis_reports
                   (analysis_id, report_title, report_file_path, file_sha256, created_by_id)
               VALUES (?,?,?,?,?)
           ";
           $stmt = $conn->prepare($sql);
           $stmt->bind_param("isssi", $analysis_id, $report_title, $report_file_path, $sha256, $author_id);
           if ($stmt->execute()) {
               $msg = $sha256 ? "Report added and hashed." : "Report added (no baseline hash recorded — file was not found under the app directory).";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "report insert");
           }
           $stmt->close();
       }
   }
}
/* =========================================================
  UPDATE REPORT
  ========================================================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "update") {
   if (!$canUpdateReport) {
       $msg = "You do not have permission to update lab reports.";
   } else {
       $report_id        = (int)($_POST["report_id"] ?? 0);
       $report_title     = trim($_POST["report_title"] ?? "");
       $report_file_path = trim($_POST["report_file_path"] ?? "");
       if (!$report_id || $report_title === "" || $report_file_path === "") {
           $msg = "Report title and file path are required.";
       } else {
           // Optionally restrict: AND created_by_id = ? (and bind $current_user_id) if you want
           $sql = "
               UPDATE analysis_reports
                  SET report_title     = ?,
                      report_file_path = ?
                WHERE report_id       = ?
           ";
           $stmt = $conn->prepare($sql);
           $stmt->bind_param("ssi", $report_title, $report_file_path, $report_id);
           if ($stmt->execute()) {
               $msg = "Report updated.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "report update");
           }
           $stmt->close();
       }
   }
}
/* =========================================================
  DELETE REPORT  (SysAdmin only via RBAC)
  ========================================================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete") {
   if (!$canDeleteReport) {
       $msg = "You do not have permission to delete lab reports.";
   } else {
       $report_id = (int)($_POST["report_id"] ?? 0);
       if ($report_id) {
           $stmt = $conn->prepare("DELETE FROM analysis_reports WHERE report_id = ?");
           $stmt->bind_param("i", $report_id);
           if ($stmt->execute()) {
               $msg = "Report deleted.";
           } else {
               $msg = sfems_generic_db_error($stmt->error, "report delete");
           }
           $stmt->close();
       }
   }
}
/* =========================================================
  HASH VERIFY
  ========================================================= */
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "verify") {
    $report_id = (int)($_POST["report_id"] ?? 0);
    if (!$canViewReport) {
        $msg = "You do NOT have permission to verify reports.";
    } elseif ($report_id > 0) {
        $stmt = $conn->prepare("
            SELECT r.report_id, fa.evidence_id, r.report_file_path, r.file_sha256
            FROM analysis_reports r
            JOIN forensic_analysis fa ON r.analysis_id = fa.analysis_id
            WHERE r.report_id = ?
        ");
        $stmt->bind_param("i", $report_id);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if ($row) {
            $full = realpath(__DIR__ . "/../" . ltrim($row["report_file_path"], "/"));
            $base = realpath(__DIR__ . "/..");
            $computed = ($full !== false && strpos($full, $base) === 0) ? sfems_hash_file($full) : null;
            if ($computed === null) {
                $result = "FILE_MISSING";
                $msg = "Verification FAILED: the file could not be found on disk.";
            } elseif (empty($row["file_sha256"])) {
                $result = "NO_BASELINE";
                $msg = "No baseline hash was recorded for this report at intake, so integrity cannot be confirmed.";
            } elseif (hash_equals($row["file_sha256"], $computed)) {
                $result = "MATCH";
                $msg = "Verified: file hash matches the value recorded at intake.";
            } else {
                $result = "MISMATCH";
                $msg = "INTEGRITY ALERT: the file's current hash does NOT match the value recorded at intake.";
            }
            log_hash_verification($conn, "analysis_reports", $report_id, (int)$row["evidence_id"], $row["file_sha256"], $computed, $current_user_id, $result);
        }
    }
}
/* =========================================================
  ANALYSIS LIST for ADD form
  ========================================================= */
$analysisList = $conn->query("
   SELECT fa.analysis_id,
          e.evidence_code,
          fa.analysis_type
   FROM forensic_analysis fa
   JOIN evidence e ON fa.evidence_id = e.evidence_id
   ORDER BY e.evidence_code, fa.analysis_id
");
/* =========================================================
  RETRIEVE REPORTS LIST
  ========================================================= */
$reportsSql = "
   SELECT r.report_id,
          r.analysis_id,
          r.report_title,
          r.report_file_path,
          r.file_sha256,
          r.created_at,
          u.full_name AS author_name,
          fa.analysis_type,
          e.evidence_code
   FROM analysis_reports r
   JOIN forensic_analysis fa ON r.analysis_id = fa.analysis_id
   JOIN evidence e          ON fa.evidence_id = e.evidence_id
   JOIN users   u           ON r.created_by_id = u.user_id
   ORDER BY r.report_id DESC
";
$reports = $conn->query($reportsSql);
?>
<h2>Lab / Forensic Reports</h2>
<p class="muted">
   Reports are authored as: <strong><?= htmlspecialchars($current_user_name) ?></strong>
</p>
<?php if ($msg): ?>
<div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAddReport): ?>
<h3>Add Report</h3>
<form method="post" action="index.php?page=reports" class="form-inline">
<?= csrf_field() ?>
<input type="hidden" name="action" value="add">
<div>
<label>Analysis *</label>
<select name="analysis_id" required>
<option value="">--Analysis--</option>
<?php while ($a = $analysisList->fetch_assoc()): ?>
<option value="<?= (int)$a["analysis_id"] ?>">
<?= htmlspecialchars($a["evidence_code"]) ?> — <?= htmlspecialchars($a["analysis_type"]) ?>
</option>
<?php endwhile; ?>
</select>
</div>
<div style="flex:1 1 100%;">
<label>Report Title *</label>
<input type="text" name="report_title" required>
</div>
<div style="flex:1 1 100%;">
<label>Report File Path *</label>
<input type="text" name="report_file_path" placeholder="/reports/filename.pdf" required>
</div>
<button class="btn-primary" type="submit">Add Report</button>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">Existing Reports</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Evidence</th>
<th>Analysis Type</th>
<th>Title</th>
<th>File</th>
<th>SHA-256</th>
<th>Author</th>
<th>Created</th>
<th>Integrity</th>
<?php if ($canUpdateReport || $canDeleteReport): ?>
<th>Actions</th>
<?php endif; ?>
</tr>
<?php if ($reports && $reports->num_rows > 0): ?>
<?php while ($r = $reports->fetch_assoc()): ?>
<tr>
<td><?= (int)$r["report_id"] ?></td>
<td><?= htmlspecialchars($r["evidence_code"] ?? "") ?></td>
<td><?= htmlspecialchars($r["analysis_type"] ?? "") ?></td>
<td><?= htmlspecialchars($r["report_title"] ?? "") ?></td>
<td><a href="download.php?type=report&id=<?= (int)$r['report_id'] ?>" target="_blank">Download</a></td>
<td style="font-family:monospace;font-size:11px;">
<?= $r["file_sha256"] ? htmlspecialchars(substr($r["file_sha256"], 0, 16)) . "…" : "—" ?>
</td>
<td><?= htmlspecialchars($r["author_name"] ?? "") ?></td>
<td><?= htmlspecialchars($r["created_at"] ?? "") ?></td>
<td>
<form method="post" action="index.php?page=reports" style="display:inline;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="verify">
<input type="hidden" name="report_id" value="<?= (int)$r['report_id'] ?>">
<button class="btn-secondary" type="submit">Verify</button>
</form>
</td>
<?php if ($canUpdateReport || $canDeleteReport): ?>
<td>
<?php if ($canUpdateReport): ?>
<!-- Inline UPDATE form -->
<form method="post" action="index.php?page=reports" style="display:inline-block; width:100%; margin:0 0 4px 0;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="update">
<input type="hidden" name="report_id" value="<?= (int)$r["report_id"] ?>">
<input type="text"
                                      name="report_title"
                                      placeholder="Report title"
                                      value="<?= htmlspecialchars($r["report_title"] ?? '') ?>"
                                      style="width:100%; margin-bottom:4px;">
<input type="text"
                                      name="report_file_path"
                                      placeholder="/reports/filename.pdf"
                                      value="<?= htmlspecialchars($r["report_file_path"] ?? '') ?>"
                                      style="width:100%; margin-bottom:4px;">
<button class="btn-secondary" type="submit">Update</button>
</form>
<?php endif; ?>
<?php if ($canDeleteReport): ?>
<!-- DELETE form -->
<form method="post" action="index.php?page=reports"
                                 style="display:inline-block; margin-top:4px;"
                                 onsubmit="return confirm('Delete this report?');">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="report_id" value="<?= (int)$r["report_id"] ?>">
<button class="btn-danger" type="submit">Delete</button>
</form>
<?php endif; ?>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php else: ?>
<tr>
<td colspan="<?= ($canUpdateReport || $canDeleteReport) ? 10 : 9; ?>">
               No reports found.
</td>
</tr>
<?php endif; ?>
</table>