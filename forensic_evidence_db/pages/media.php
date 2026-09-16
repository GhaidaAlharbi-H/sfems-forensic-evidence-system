<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_user_id   = (int)$_SESSION["user_id"];
$current_role      = $_SESSION["role"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$canAddMedia      = can_add($current_role, "MEDIA");
$canViewMedia     = can_retrieve($current_role, "MEDIA");
$canUpdateMedia   = can_update($current_role, "MEDIA");
$canDeleteMedia   = can_delete($current_role, "MEDIA");
$isProsecutor     = ($current_role === "Prosecutor");
$msg      = "";
$msgClass = "alert-success";
$editMode = false;
$editRow  = null;

// Real-MIME-type allowlist. Extension is derived from the DETECTED type,
// never trusted from the client filename — this plus a random filename and
// a non-executable upload directory (media/.htaccess) closes the RCE hole
// from fix #3.
const SFEMS_MEDIA_MAX_BYTES = 26214400; // 25 MB
const SFEMS_MEDIA_ALLOWED_MIME = [
    "image/jpeg" => "jpg",
    "image/png"  => "png",
    "image/gif"  => "gif",
    "image/webp" => "webp",
    "video/mp4"  => "mp4",
    "video/quicktime" => "mov",
    "audio/mpeg" => "mp3",
    "audio/wav"  => "wav",
    "audio/x-wav" => "wav",
    "application/pdf" => "pdf",
    "text/plain" => "txt",
];

// -------------------------------------------------------
// 1) HANDLE DELETE (soft delete, POST + CSRF — was a plain GET link, fix #12)
// -------------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "delete") {
   $media_id = (int)($_POST["media_id"] ?? 0);
   if (!$canDeleteMedia) {
       $msg = "You do NOT have permission to delete media.";
   } elseif ($media_id > 0) {
       $stmt = $conn->prepare("UPDATE evidence_media SET is_active = 0 WHERE media_id = ?");
       $stmt->bind_param("i", $media_id);
       if ($stmt->execute()) {
           $msg = "Media record deactivated. The underlying file is kept on disk for the audit trail.";
       } else {
           $msg = sfems_generic_db_error($stmt->error, "media soft-delete");
       }
       $stmt->close();
   }
}
// -------------------------------------------------------
// 1b) HANDLE HASH VERIFY
// -------------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "verify") {
    $media_id = (int)($_POST["media_id"] ?? 0);
    if (!$canViewMedia) {
        $msg = "You do NOT have permission to verify media.";
    } elseif ($media_id > 0) {
        $stmt = $conn->prepare("SELECT media_id, evidence_id, file_path, file_sha256 FROM evidence_media WHERE media_id = ?");
        $stmt->bind_param("i", $media_id);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        if ($row) {
            $fullPath = __DIR__ . "/../" . $row["file_path"];
            $computed = sfems_hash_file($fullPath);
            if ($computed === null) {
                $result = "FILE_MISSING";
                $msg = "Verification FAILED: the file could not be found on disk.";
            } elseif (empty($row["file_sha256"])) {
                $result = "NO_BASELINE";
                $msg = "No baseline hash was recorded for this file at intake, so integrity cannot be confirmed.";
            } elseif (hash_equals($row["file_sha256"], $computed)) {
                $result = "MATCH";
                $msg = "Verified: file hash matches the value recorded at intake.";
            } else {
                $result = "MISMATCH";
                $msg = "INTEGRITY ALERT: the file's current hash does NOT match the value recorded at intake.";
                $msgClass = "alert-error"; // tamper detection, not a success — was wrongly rendered green
            }
            log_hash_verification($conn, "evidence_media", $media_id, (int)$row["evidence_id"], $row["file_sha256"], $computed, $current_user_id, $result);
        }
    }
}
// -------------------------------------------------------
// 2) HANDLE ADD / UPDATE (POST)
// -------------------------------------------------------
if ($_SERVER["REQUEST_METHOD"] === "POST" && in_array($_POST["action"] ?? "", ["add", "update"], true)) {
   $action      = $_POST["action"];
   $evidence_id = (int)($_POST["evidence_id"] ?? 0);
   $media_type  = $_POST["media_type"] ?? "PHOTO";
   $description = trim($_POST["description"] ?? "");
   if ($action === "add") {
       if (!$canAddMedia) {
           $msg = "You do NOT have permission to add media.";
       } elseif (!isset($_FILES["media_file"]) || $_FILES["media_file"]["error"] !== UPLOAD_ERR_OK) {
           $msg = "Please choose a file to upload.";
       } elseif ($_FILES["media_file"]["size"] > SFEMS_MEDIA_MAX_BYTES) {
           $msg = "File is too large (25 MB max).";
       } else {
           $tmpPath = $_FILES["media_file"]["tmp_name"];
           $finfo   = finfo_open(FILEINFO_MIME_TYPE);
           $detectedMime = finfo_file($finfo, $tmpPath);
           finfo_close($finfo);

           if (!isset(SFEMS_MEDIA_ALLOWED_MIME[$detectedMime])) {
               $msg = "That file type is not allowed. Detected type: " . htmlspecialchars((string)$detectedMime);
           } else {
               $uploadDir = __DIR__ . "/../media/";
               $ext       = SFEMS_MEDIA_ALLOWED_MIME[$detectedMime];
               $newName   = bin2hex(random_bytes(16)) . "." . $ext; // never trust the client filename
               $targetPath = $uploadDir . $newName;
               $dbPath     = "media/" . $newName;

               if (!move_uploaded_file($tmpPath, $targetPath)) {
                   $msg = "Error: could not store uploaded file.";
               } else {
                   $sha256 = sfems_hash_file($targetPath); // fix #6: baseline hash recorded at intake
                   if ($evidence_id) {
                       $stmt = $conn->prepare("
                           INSERT INTO evidence_media
                               (evidence_id, media_type, file_path, file_sha256, description, uploaded_by_id)
                           VALUES (?,?,?,?,?,?)
                       ");
                       $stmt->bind_param("issssi", $evidence_id, $media_type, $dbPath, $sha256, $description, $current_user_id);
                       if ($stmt->execute()) {
                           $msg = "Media uploaded successfully.";
                       } else {
                           $msg = sfems_generic_db_error($stmt->error, "media insert");
                           @unlink($targetPath); // don't leave an orphaned file if the DB insert failed
                       }
                       $stmt->close();
                   } else {
                       @unlink($targetPath);
                       $msg = "Evidence selection is required.";
                   }
               }
           }
       }
   } elseif ($action === "update") {
       if (!$canUpdateMedia) {
           $msg = "You do NOT have permission to update media.";
       } else {
           $media_id = (int)($_POST["media_id"] ?? 0);
           $allowed  = true;
           if ($media_id && $evidence_id) {
               if ($isProsecutor) {
                   $check = $conn->prepare("SELECT uploaded_by_id FROM evidence_media WHERE media_id = ?");
                   $check->bind_param("i", $media_id);
                   $check->execute();
                   $row = $check->get_result()->fetch_assoc();
                   $check->close();
                   if (!$row || (int)$row["uploaded_by_id"] !== $current_user_id) {
                       $msg = "You may only edit media you uploaded.";
                       $allowed = false;
                   }
               }
               if ($allowed) {
                   $stmt = $conn->prepare("
                       UPDATE evidence_media
                       SET evidence_id = ?,
                           media_type  = ?,
                           description = ?
                       WHERE media_id = ?
                   ");
                   $stmt->bind_param("issi", $evidence_id, $media_type, $description, $media_id);
                   if ($stmt->execute()) {
                       $msg      = "Media record updated.";
                       $editMode = false;
                       $editRow  = null;
                   } else {
                       $msg = sfems_generic_db_error($stmt->error, "media update");
                   }
                   $stmt->close();
               }
           } else {
               $msg = "Evidence and media ID are required for update.";
           }
       }
   }
}
// -------------------------------------------------------
// 3) LOAD RECORD FOR EDIT (?edit_id=...) AFTER POST
// -------------------------------------------------------
if ($canUpdateMedia && isset($_GET["edit_id"]) && $_SERVER["REQUEST_METHOD"] === "GET") {
   $edit_id = (int)$_GET["edit_id"];
   if ($edit_id > 0) {
       $stmt = $conn->prepare("
           SELECT em.*, e.evidence_code, u.full_name
           FROM evidence_media em
           JOIN evidence e ON em.evidence_id = e.evidence_id
           JOIN users   u ON em.uploaded_by_id = u.user_id
           WHERE em.media_id = ? AND em.is_active = 1
       ");
       $stmt->bind_param("i", $edit_id);
       $stmt->execute();
       $result = $stmt->get_result();
       if ($row = $result->fetch_assoc()) {
           if ($isProsecutor && (int)$row["uploaded_by_id"] !== $current_user_id) {
               $msg = "You may only edit media you uploaded.";
           } else {
               $editMode = true;
               $editRow  = $row;
           }
       }
       $stmt->close();
   }
}
// -------------------------------------------------------
// 4) LOAD EVIDENCE DROPDOWN
// -------------------------------------------------------
$ev = $conn->query("
   SELECT evidence_id, evidence_code
   FROM evidence
   WHERE is_active = 1
   ORDER BY evidence_code
");
// -------------------------------------------------------
// 5) LIST MEDIA (RETRIEVE, WITH ROW-SCOPING) — active only
// -------------------------------------------------------
if (!$canViewMedia) {
   echo "<h2>You do NOT have permission to view media.</h2>";
   return;
}
if ($isProsecutor) {
   $list = $conn->query("
       SELECT em.*, e.evidence_code, u.full_name
       FROM evidence_media em
       JOIN evidence e ON em.evidence_id = e.evidence_id
       JOIN users   u ON em.uploaded_by_id = u.user_id
       WHERE em.uploaded_by_id = {$current_user_id} AND em.is_active = 1
       ORDER BY em.media_id DESC
   ");
} else {
   $list = $conn->query("
       SELECT em.*, e.evidence_code, u.full_name
       FROM evidence_media em
       JOIN evidence e ON em.evidence_id = e.evidence_id
       JOIN users   u ON em.uploaded_by_id = u.user_id
       WHERE em.is_active = 1
       ORDER BY em.media_id DESC
   ");
}
// -------------------------------------------------------
// 6) FORM PREFILL: ADD vs EDIT
// -------------------------------------------------------
$form_action     = $editMode ? "update" : "add";
$form_title      = $editMode ? "Edit Media" : "Add Media";
$form_button_txt = $editMode ? "Update Media" : "Add Media";
$form_media_id   = $editMode ? (int)$editRow["media_id"] : 0;
$form_evidence_id= $editMode ? (int)$editRow["evidence_id"] : 0;
$form_type       = $editMode ? $editRow["media_type"] : "PHOTO";
$form_desc       = $editMode ? $editRow["description"] : "";
?>
<h2>Evidence Media</h2>
<p class="muted">
   Upload and manage media files linked to evidence.<br>
<strong>Current User:</strong> <?= htmlspecialchars($current_user_name) ?>
</p>
<?php if ($msg): ?>
<div class="<?= htmlspecialchars($msgClass) ?>"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>
<?php if ($canAddMedia || ($editMode && $canUpdateMedia)): ?>
<h3><?= htmlspecialchars($form_title) ?></h3>
<form method="post" action="index.php?page=media" class="form-inline" enctype="multipart/form-data">
<?= csrf_field() ?>
<input type="hidden" name="action" value="<?= htmlspecialchars($form_action) ?>">
<?php if ($editMode): ?>
<input type="hidden" name="media_id" value="<?= $form_media_id ?>">
<?php endif; ?>
<div>
<label>Evidence *</label>
<select name="evidence_id" required>
<option value="">--Evidence--</option>
<?php
               $ev->data_seek(0);
               while ($e = $ev->fetch_assoc()):
                   $selected = ($form_evidence_id == (int)$e["evidence_id"]) ? "selected" : "";
               ?>
<option value="<?= $e['evidence_id'] ?>" <?= $selected ?>>
<?= htmlspecialchars($e['evidence_code']) ?>
</option>
<?php endwhile; ?>
</select>
</div>
<div>
<label>Media Type</label>
<select name="media_type">
<option <?= $form_type === "PHOTO"    ? "selected" : "" ?>>PHOTO</option>
<option <?= $form_type === "VIDEO"    ? "selected" : "" ?>>VIDEO</option>
<option <?= $form_type === "AUDIO"    ? "selected" : "" ?>>AUDIO</option>
<option <?= $form_type === "DOCUMENT" ? "selected" : "" ?>>DOCUMENT</option>
<option <?= $form_type === "OTHER"    ? "selected" : "" ?>>OTHER</option>
</select>
</div>
<?php if (!$editMode): ?>
<div>
<label>Upload File *</label>
<input type="file" name="media_file" required>
</div>
<?php else: ?>
<div>
<label>File</label>
<p class="muted" style="margin:0;">
                   File path remains the same. (File replace not implemented.)
</p>
</div>
<?php endif; ?>
<div style="flex:1 1 100%;">
<label>Description</label>
<input type="text" name="description" value="<?= htmlspecialchars($form_desc) ?>">
</div>
<button class="btn-primary" type="submit">
<?= htmlspecialchars($form_button_txt) ?>
</button>
<?php if ($editMode): ?>
<a href="index.php?page=media" class="btn-secondary">Cancel</a>
<?php endif; ?>
</form>
<?php endif; ?>
<h3 style="margin-top:25px;">Existing Media</h3>
<table class="table">
<tr>
<th>ID</th>
<th>Evidence</th>
<th>Type</th>
<th>File</th>
<th>SHA-256</th>
<th>Description</th>
<th>Uploaded By</th>
<th>When</th>
<th>Integrity</th>
<?php if ($canUpdateMedia): ?>
<th>Edit</th>
<?php endif; ?>
<?php if ($canDeleteMedia): ?>
<th>Delete</th>
<?php endif; ?>
</tr>
<?php if ($list && $list->num_rows > 0): ?>
<?php while ($m = $list->fetch_assoc()): ?>
<tr>
<td><?= $m["media_id"] ?></td>
<td><?= htmlspecialchars($m["evidence_code"]) ?></td>
<td><?= htmlspecialchars($m["media_type"]) ?></td>
<td>
<a href="download.php?type=media&id=<?= (int)$m['media_id'] ?>" target="_blank">Download</a>
</td>
<td style="font-family:monospace;font-size:11px;">
<?= $m["file_sha256"] ? htmlspecialchars(substr($m["file_sha256"], 0, 16)) . "…" : "—" ?>
</td>
<td><?= htmlspecialchars($m["description"]) ?></td>
<td><?= htmlspecialchars($m["full_name"]) ?></td>
<td><?= htmlspecialchars($m["uploaded_at"]) ?></td>
<td>
<form method="post" action="index.php?page=media" style="display:inline;">
<?= csrf_field() ?>
<input type="hidden" name="action" value="verify">
<input type="hidden" name="media_id" value="<?= (int)$m['media_id'] ?>">
<button class="btn-secondary" type="submit">Verify</button>
</form>
</td>
<?php if ($canUpdateMedia): ?>
<td>
<a href="index.php?page=media&edit_id=<?= $m['media_id'] ?>"
                          class="btn-secondary">
                           Edit
</a>
</td>
<?php endif; ?>
<?php if ($canDeleteMedia): ?>
<td>
<form method="post" action="index.php?page=media" style="display:inline;"
      onsubmit="return confirm('Deactivate this media record? The file stays on disk.');">
<?= csrf_field() ?>
<input type="hidden" name="action" value="delete">
<input type="hidden" name="media_id" value="<?= (int)$m['media_id'] ?>">
<button class="btn-danger" type="submit">Delete</button>
</form>
</td>
<?php endif; ?>
</tr>
<?php endwhile; ?>
<?php else: ?>
<tr>
<td colspan="<?=
               9 + ($canUpdateMedia ? 1 : 0) + ($canDeleteMedia ? 1 : 0);
           ?>">
               No media uploaded.
</td>
</tr>
<?php endif; ?>
</table>
