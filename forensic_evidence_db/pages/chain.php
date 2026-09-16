<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$current_user_id   = (int)$_SESSION["user_id"];
$current_user_name = $_SESSION["full_name"] ?? "Current User";
$current_role      = $_SESSION["role"] ?? "";

// RBAC for CHAIN_OF_CUSTODY table
$canAdd      = can_add($current_role, "CHAIN_OF_CUSTODY");
$canRetrieve = can_retrieve($current_role, "CHAIN_OF_CUSTODY");

// Per policy: NO ONE can update or delete chain_of_custody
$msg = "";

/* -------------------------------------------------------
   Build evidence list for the ADD form based on role
   ------------------------------------------------------- */
function addEvidenceOptionsSQL(string $role, int $userId): string
{
    switch ($role) {
        case "CSI":
            // CSI: only their evidence, and only if NO prior chain rows (initial entry)
            return "
                SELECT e.evidence_id, e.evidence_code
                FROM evidence e
                WHERE e.collected_by_id = {$userId}
                  AND e.is_active = 1
                  AND NOT EXISTS (
                        SELECT 1 FROM chain_of_custody c
                        WHERE c.evidence_id = e.evidence_id
                  )
                ORDER BY e.evidence_code
            ";

        case "Analyst":
            // Analyst: only evidence assigned to this analyst in forensic_analysis table
            return "
                SELECT DISTINCT e.evidence_id, e.evidence_code
                FROM evidence e
                JOIN forensic_analysis fa ON fa.evidence_id = e.evidence_id
                WHERE fa.analyst_id = {$userId} AND e.is_active = 1
                ORDER BY e.evidence_code
            ";

        case "Custodian":
        case "SysAdmin":

            // Custodian / SysAdmin: all active evidence
            return "SELECT evidence_id, evidence_code FROM evidence WHERE is_active = 1 ORDER BY evidence_code";

        default:
            // No add rights → empty set
            return "SELECT evidence_id, evidence_code FROM evidence WHERE 1=0";
    }
}

/* -------------------------------------------------------
   Handle ADD transfer (server-side RBAC)
   ------------------------------------------------------- */
if ($canAdd && $_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {

    $evidence_id  = (int)($_POST["evidence_id"] ?? 0);
    $to_user_id   = (int)($_POST["to_user_id"] ?? 0);
    $from_loc_id  = ($_POST["from_location_id"] !== "") ? (int)$_POST["from_location_id"] : null;
    $to_loc_id    = ($_POST["to_location_id"]   !== "") ? (int)$_POST["to_location_id"]   : null;
    $purpose      = trim($_POST["purpose"] ?? "");
    $dt           = $_POST["transfer_datetime"] ?? "";
    $condition    = trim($_POST["condition_notes"] ?? "");
    $from_user_id = $current_user_id;

    if (!$evidence_id || !$to_user_id || !$dt) {
        $msg = "Evidence, recipient and datetime are required.";
    } else {

        $ok = false;

        if ($current_role === "CSI") {
            // Must be their evidence AND this must be the first chain entry
            $row = $conn->query("
                SELECT
                    (SELECT COUNT(*) FROM chain_of_custody c WHERE c.evidence_id = {$evidence_id}) AS cnt,
                    (SELECT collected_by_id FROM evidence WHERE evidence_id = {$evidence_id}) AS collector
            ")->fetch_assoc();

            $ok = ($row && (int)$row["collector"] === $current_user_id && (int)$row["cnt"] === 0);
            if (!$ok) {
                $msg = "CSI may only log the initial entry for evidence they collected.";
            }

        } elseif ($current_role === "Analyst") {
            // Must be assigned in forensic_analysis
            $row = $conn->query("
                SELECT 1
                FROM forensic_analysis fa
                WHERE fa.evidence_id = {$evidence_id}
                  AND fa.analyst_id  = {$current_user_id}
                LIMIT 1
            ");
            $ok = ($row && $row->num_rows > 0);
            if (!$ok) {
                $msg = "Analyst can only log transfers for evidence assigned to them.";
            }

        } elseif ($current_role === "Custodian" || $current_role === "SysAdmin") {
            // Custodian & SysAdmin can log any transfer
            $ok = true;

        } else {
            $ok = false;
            $msg = "You are not allowed to add chain-of-custody transfers.";
        }

        if ($ok) {
            $sql = "INSERT INTO chain_of_custody
                    (evidence_id, from_user_id, to_user_id, from_location_id, to_location_id,
                     purpose, transfer_datetime, condition_notes)
                    VALUES (?,?,?,?,?,?,?,?)";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param(
                "iiiissss",
                $evidence_id,
                $from_user_id,
                $to_user_id,
                $from_loc_id,
                $to_loc_id,
                $purpose,
                $dt,
                $condition
            );

            if ($stmt->execute()) {
                $msg = "Transfer logged.";
            } else {
                $msg = sfems_generic_db_error($stmt->error, "chain_of_custody insert");
            }
            $stmt->close();
        }
    }

} elseif ($_SERVER["REQUEST_METHOD"] === "POST" && ($_POST["action"] ?? "") === "add") {
    // POST attempted but role cannot add
    $msg = "You do not have permission to add chain-of-custody transfers.";
}

/* -------------------------------------------------------
   Data for dropdowns (for ADD form)
   ------------------------------------------------------- */
$evidenceForAdd = $conn->query(addEvidenceOptionsSQL($current_role, $current_user_id));
$users          = $conn->query("SELECT user_id, full_name FROM users WHERE is_active = 1 ORDER BY full_name");
$locs1          = $conn->query("SELECT location_id, location_code FROM storage_locations ORDER BY location_code");
$locs2          = $conn->query("SELECT location_id, location_code FROM storage_locations ORDER BY location_code");

/* -------------------------------------------------------
   RETRIEVE list (role-scoped)
   ------------------------------------------------------- */
if (!$canRetrieve) {
    die("<h2>You do NOT have permission to view chain-of-custody logs.</h2>");
}

switch ($current_role) {

    case "CSI":
        // CSI: chain logs only for evidence they collected
        $sqlList = "
            SELECT c.transfer_id, e.evidence_code,
                   fu.full_name AS from_user, tu.full_name AS to_user,
                   fl.location_code AS from_loc, tl.location_code AS to_loc,
                   c.purpose, c.transfer_datetime, c.condition_notes
            FROM chain_of_custody c
            JOIN evidence e ON c.evidence_id = e.evidence_id
            LEFT JOIN users fu ON c.from_user_id = fu.user_id
            JOIN users tu ON c.to_user_id = tu.user_id
            LEFT JOIN storage_locations fl ON c.from_location_id = fl.location_id
            LEFT JOIN storage_locations tl ON c.to_location_id = tl.location_id
            WHERE e.collected_by_id = {$current_user_id}
            ORDER BY c.transfer_datetime DESC
        ";
        break;

    case "Analyst":
        // Analyst: logs for evidence assigned in forensic_analysis
        $sqlList = "
            SELECT DISTINCT c.transfer_id, e.evidence_code,
                   fu.full_name AS from_user, tu.full_name AS to_user,
                   fl.location_code AS from_loc, tl.location_code AS to_loc,
                   c.purpose, c.transfer_datetime, c.condition_notes
            FROM chain_of_custody c
            JOIN evidence e ON c.evidence_id = e.evidence_id
            JOIN forensic_analysis fa ON fa.evidence_id = e.evidence_id
            LEFT JOIN users fu ON c.from_user_id = fu.user_id
            JOIN users tu ON c.to_user_id = tu.user_id
            LEFT JOIN storage_locations fl ON c.from_location_id = fl.location_id
            LEFT JOIN storage_locations tl ON c.to_location_id = tl.location_id
            WHERE fa.analyst_id = {$current_user_id}
            ORDER BY c.transfer_datetime DESC
        ";
        break;

    case "Investigator":
        // Investigator: full timelines for cases they are assigned to
        $sqlList = "
            SELECT c.transfer_id, e.evidence_code,
                   fu.full_name AS from_user, tu.full_name AS to_user,
                   fl.location_code AS from_loc, tl.location_code AS to_loc,
                   c.purpose, c.transfer_datetime, c.condition_notes
            FROM chain_of_custody c
            JOIN evidence e ON c.evidence_id = e.evidence_id
            JOIN cases cs ON cs.case_id = e.case_id
            JOIN case_assignments ca ON ca.case_id = cs.case_id
            LEFT JOIN users fu ON c.from_user_id = fu.user_id
            JOIN users tu ON c.to_user_id = tu.user_id
            LEFT JOIN storage_locations fl ON c.from_location_id = fl.location_id
            LEFT JOIN storage_locations tl ON c.to_location_id = tl.location_id
            WHERE ca.user_id = {$current_user_id}
            ORDER BY c.transfer_datetime DESC
        ";
        break;

    case "Prosecutor":
        // Prosecutor: read-only view of all logs
        $sqlList = "
            SELECT c.transfer_id, e.evidence_code,
                   fu.full_name AS from_user, tu.full_name AS to_user,
                   fl.location_code AS from_loc, tl.location_code AS to_loc,
                   c.purpose, c.transfer_datetime, c.condition_notes
            FROM chain_of_custody c
            JOIN evidence e ON c.evidence_id = e.evidence_id
            LEFT JOIN users fu ON c.from_user_id = fu.user_id
            JOIN users tu ON c.to_user_id = tu.user_id
            LEFT JOIN storage_locations fl ON c.from_location_id = fl.location_id
            LEFT JOIN storage_locations tl ON c.to_location_id = tl.location_id
            ORDER BY c.transfer_datetime DESC
        ";
        break;

    default:
        // Custodian + SysAdmin → all logs
        $sqlList = "
            SELECT c.transfer_id, e.evidence_code,
                   fu.full_name AS from_user, tu.full_name AS to_user,
                   fl.location_code AS from_loc, tl.location_code AS to_loc,
                   c.purpose, c.transfer_datetime, c.condition_notes
            FROM chain_of_custody c
            JOIN evidence e ON c.evidence_id = e.evidence_id
            LEFT JOIN users fu ON c.from_user_id = fu.user_id
            JOIN users tu ON c.to_user_id = tu.user_id
            LEFT JOIN storage_locations fl ON c.from_location_id = fl.location_id
            LEFT JOIN storage_locations tl ON c.to_location_id = tl.location_id
            ORDER BY c.transfer_datetime DESC
        ";
}

$list = $conn->query($sqlList);
?>
<h2>Chain of Custody</h2>

<p class="muted">
    Transfers you record will show as from:
    <strong><?= htmlspecialchars($current_user_name) ?></strong>
</p>

<?php if ($msg): ?>
    <div class="alert-success"><?= htmlspecialchars($msg) ?></div>
<?php endif; ?>

<?php if ($canAdd): ?>
    <h3>Log Transfer</h3>
    <form method="post" action="index.php?page=chain" class="form-inline">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="add">

        <div>
            <label>Evidence *</label>
            <select name="evidence_id" required>
                <option value="">--Evidence--</option>
                <?php while($e = $evidenceForAdd->fetch_assoc()): ?>
                    <option value="<?= $e["evidence_id"] ?>">
                        <?= htmlspecialchars($e["evidence_code"]) ?>
                    </option>
                <?php endwhile; ?>
            </select>
        </div>

        <div>
            <label>To User *</label>
            <select name="to_user_id" required>
                <option value="">--User--</option>
                <?php while($u = $users->fetch_assoc()): ?>
                    <option value="<?= $u["user_id"] ?>">
                        <?= htmlspecialchars($u["full_name"]) ?>
                    </option>
                <?php endwhile; ?>
            </select>
        </div>

        <div>
            <label>From Location</label>
            <select name="from_location_id">
                <option value="">--None--</option>
                <?php while($l = $locs1->fetch_assoc()): ?>
                    <option value="<?= $l["location_id"] ?>">
                        <?= htmlspecialchars($l["location_code"]) ?>
                    </option>
                <?php endwhile; ?>
            </select>
        </div>

        <div>
            <label>To Location</label>
            <select name="to_location_id">
                <option value="">--None--</option>
                <?php while($l = $locs2->fetch_assoc()): ?>
                    <option value="<?= $l["location_id"] ?>">
                        <?= htmlspecialchars($l["location_code"]) ?>
                    </option>
                <?php endwhile; ?>
            </select>
        </div>

        <div>
            <label>Transfer Datetime *</label>
            <input type="datetime-local" name="transfer_datetime" required>
        </div>

        <div style="flex:1 1 100%;">
            <label>Purpose</label>
            <input type="text" name="purpose">
        </div>

        <div style="flex:1 1 100%;">
            <label>Condition Notes</label>
            <input type="text" name="condition_notes">
        </div>

        <button class="btn-primary" type="submit">Log Transfer</button>
    </form>
<?php endif; ?>

<h3 style="margin-top:25px;">Custody History</h3>
<table class="table">
    <tr>
        <th>ID</th>
        <th>Evidence</th>
        <th>From</th>
        <th>To</th>
        <th>From Loc</th>
        <th>To Loc</th>
        <th>Purpose</th>
        <th>When</th>
        <th>Condition</th>
    </tr>

    <?php if ($list && $list->num_rows > 0): ?>
        <?php while($c = $list->fetch_assoc()): ?>
            <tr>
                <td><?= $c["transfer_id"] ?></td>
                <td><?= htmlspecialchars($c["evidence_code"]) ?></td>
                <td><?= htmlspecialchars($c["from_user"]) ?></td>
                <td><?= htmlspecialchars($c["to_user"]) ?></td>
                <td><?= htmlspecialchars($c["from_loc"]) ?></td>
                <td><?= htmlspecialchars($c["to_loc"]) ?></td>
                <td><?= htmlspecialchars($c["purpose"]) ?></td>
                <td><?= htmlspecialchars($c["transfer_datetime"]) ?></td>
                <td><?= htmlspecialchars($c["condition_notes"]) ?></td>
            </tr>
        <?php endwhile; ?>
    <?php else: ?>
        <tr><td colspan="9">No chain-of-custody records.</td></tr>
    <?php endif; ?>
</table>
