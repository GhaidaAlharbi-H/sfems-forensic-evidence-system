<?php
require __DIR__ . "/../bootstrap.php";
sfems_require_login();

$counts = [
    "cases"       => 0,
    "evidence"    => 0,
    "analysis"    => 0,
    "users"       => 0,
    "chain"       => 0,
    "disposed"    => 0,
];

$counts["cases"]    = $conn->query("SELECT COUNT(*) c FROM cases")->fetch_assoc()["c"];
$counts["evidence"] = $conn->query("SELECT COUNT(*) c FROM evidence WHERE is_active = 1")->fetch_assoc()["c"];
$counts["analysis"] = $conn->query("SELECT COUNT(*) c FROM forensic_analysis")->fetch_assoc()["c"];
$counts["users"]    = $conn->query("SELECT COUNT(*) c FROM users WHERE is_active = 1")->fetch_assoc()["c"];
$counts["chain"]    = $conn->query("SELECT COUNT(*) c FROM chain_of_custody")->fetch_assoc()["c"];
$counts["disposed"] = $conn->query("SELECT COUNT(*) c FROM disposition")->fetch_assoc()["c"];

$recent = $conn->query("
    SELECT e.evidence_code, e.evidence_type, c.case_number, e.collected_datetime
    FROM evidence e
    JOIN cases c ON e.case_id = c.case_id
    WHERE e.is_active = 1
    ORDER BY e.collected_datetime DESC
    LIMIT 5
");
?>
<h2>Dashboard</h2>
<p class="muted">Overview of cases, evidence, and analysis activity.</p>

<div class="cards">
    <div class="card">Cases: <strong><?= $counts["cases"] ?></strong></div>
    <div class="card">Evidence: <strong><?= $counts["evidence"] ?></strong></div>
    <div class="card">Forensic Analyses: <strong><?= $counts["analysis"] ?></strong></div>
    <div class="card">Users: <strong><?= $counts["users"] ?></strong></div>
    <div class="card">Chain Transfers: <strong><?= $counts["chain"] ?></strong></div>
    <div class="card">Dispositions: <strong><?= $counts["disposed"] ?></strong></div>
</div>

<h3>Recent Evidence</h3>
<table class="table">
<tr>
    <th>Case</th><th>Code</th><th>Type</th><th>Collected At</th>
</tr>
<?php while($row = $recent->fetch_assoc()): ?>
<tr>
    <td><?= htmlspecialchars($row["case_number"]) ?></td>
    <td><?= htmlspecialchars($row["evidence_code"]) ?></td>
    <td><?= htmlspecialchars($row["evidence_type"]) ?></td>
    <td><?= htmlspecialchars($row["collected_datetime"]) ?></td>
</tr>
<?php endwhile; ?>
</table>
