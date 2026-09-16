<?php
// =======================================================
// SFEMS - Role-Based Access Control (RBAC)
// =======================================================
// 1) Which ROLES can open which PAGES      => $PAGE_ROLES
// 2) What each ROLE can do on each TABLE   => $TABLE_PERMISSIONS
//      Actions: ADD / RETRIEVE / UPDATE / DELETE
// =======================================================

// -------------------------------------------------------
// 1. PAGE ACCESS
// -------------------------------------------------------
$PAGE_ROLES = [
   // Everyone who can log in gets a dashboard
   "dashboard" => ["SysAdmin", "CSI", "Custodian", "Analyst", "Investigator", "Prosecutor"],
   // System administration
   "users"  => ["SysAdmin"],
   "roles"  => ["SysAdmin"],
   "access" => ["SysAdmin"],    // audit / access log page
   // Cases & assignments
   "cases"       => ["SysAdmin", "Investigator", "Prosecutor", "CSI", "Custodian", "Analyst"],
   "assignments" => ["SysAdmin", "Investigator"],
   // Evidence
   "evidence"      => ["SysAdmin", "CSI", "Custodian", "Analyst", "Investigator", "Prosecutor"],
   "edit_evidence" => ["SysAdmin", "CSI", "Custodian", "Investigator"],
   // Evidence intake
   "intake" => ["SysAdmin", "Custodian"],
   // Chain of custody
   "chain" => ["SysAdmin", "CSI", "Custodian", "Analyst", "Investigator", "Prosecutor"],
   // Storage locations
   "locations" => ["SysAdmin", "Custodian", "Analyst", "Investigator", "Prosecutor"],
   // Forensic analysis (lab requests / work)
   "analysis" => ["SysAdmin", "Analyst", "Investigator"],
   // Lab / forensic reports
   "reports" => ["SysAdmin", "Analyst", "Investigator", "Prosecutor"],
   // Media & notes
   "media" => ["SysAdmin", "CSI", "Custodian", "Analyst", "Investigator", "Prosecutor"],
   "notes" => ["SysAdmin", "CSI", "Custodian", "Analyst", "Investigator", "Prosecutor"],
   // Evidence disposition
   "disposition" => ["SysAdmin", "Custodian", "Prosecutor"],
   // Optional global search
   "search" => ["SysAdmin", "CSI", "Custodian", "Analyst", "Investigator", "Prosecutor"],
];
// Helper for page access
function can_access_page(string $page, string $role, array $PAGE_ROLES): bool
{
   return isset($PAGE_ROLES[$page]) && in_array($role, $PAGE_ROLES[$page], true);
}

// -------------------------------------------------------
// 2. TABLE-LEVEL PRIVILEGES
// -------------------------------------------------------
$TABLE_PERMISSIONS = [
   // --------------------------------------------
   // ROLES
   // --------------------------------------------
   "ROLES" => [
       "CSI"          => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Custodian"    => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Investigator" => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => true],
   ],
   // --------------------------------------------
   // USERS
   // --------------------------------------------
   "USERS" => [
       "CSI"          => ["add" => false, "retrieve" => true, "update" => true, "delete" => false],
       "Custodian"    => ["add" => false, "retrieve" => true, "update" => true, "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => true, "update" => true, "delete" => false],
       "Investigator" => ["add" => false, "retrieve" => true, "update" => true, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => true, "update" => true, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true, "update" => true, "delete" => true],
   ],
   // --------------------------------------------
   // CASES
   // --------------------------------------------
   "CASES" => [
       "CSI"          => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "Custodian"    => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "Investigator" => ["add" => true,  "retrieve" => true, "update" => true, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true, "update" => true, "delete" => true],
   ],
   // --------------------------------------------
   // EVIDENCE
   // --------------------------------------------
   "EVIDENCE" => [
       "CSI"          => ["add" => true,  "retrieve" => true, "update" => true,  "delete" => false],
       "Custodian"    => ["add" => false, "retrieve" => true, "update" => true,  "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "Investigator" => ["add" => true,  "retrieve" => true, "update" => true,  "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true, "update" => true, "delete" => true],
   ],
   // --------------------------------------------
   // INTAKE (evidence_intake) — added for intake.php auth fix
   // --------------------------------------------
   "INTAKE" => [
       "CSI"          => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Custodian"    => ["add" => true,  "retrieve" => true,  "update" => false, "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Investigator" => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => false],
   ],
   // --------------------------------------------
   // CASE_ASSIGNMENTS — added for assignments.php auth fix
   // --------------------------------------------
   "CASE_ASSIGNMENTS" => [
       "CSI"          => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Custodian"    => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Investigator" => ["add" => true,  "retrieve" => true,  "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => true],
   ],
   // --------------------------------------------
   // CHAIN_OF_CUSTODY (never delete)
   // --------------------------------------------
   "CHAIN_OF_CUSTODY" => [
       "CSI"          => ["add" => true,  "retrieve" => true, "update" => false, "delete" => false],
       "Custodian"    => ["add" => true,  "retrieve" => true, "update" => false, "delete" => false],
       "Analyst"      => ["add" => true,  "retrieve" => true, "update" => false, "delete" => false],
       "Investigator" => ["add" => true,  "retrieve" => true, "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true, "update" => false, "delete" => false],
   ],
   // --------------------------------------------
   // STORAGE_LOCATIONS
   // --------------------------------------------
   "STORAGE_LOCATIONS" => [
       "CSI"          => ["add" => true,  "retrieve" => true, "update" => false, "delete" => false],
       "Custodian"    => ["add" => true,  "retrieve" => true, "update" => true,  "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "Investigator" => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => true, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true, "update" => true,  "delete" => true],
   ],
   // --------------------------------------------
   // NOTES (evidence_notes)
   // Custodian can UPDATE now (per your request)
// --------------------------------------------
   "NOTES" => [
       "CSI"          => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Custodian"    => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Analyst"      => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Investigator" => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Prosecutor"   => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "SysAdmin"     => ["add" => true, "retrieve" => true, "update" => true, "delete" => true],
   ],
   // --------------------------------------------
   // ANALYSIS (forensic_analysis)
   // --------------------------------------------
   "ANALYSIS" => [
       "CSI"          => ["add" => false, "retrieve" => true,  "update" => false, "delete" => false],
       "Custodian"    => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Analyst"      => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => false],
       "Investigator" => ["add" => false, "retrieve" => true,  "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => true],
   ],
   // --------------------------------------------
   // DISPOSITION (destroy / return / store)
   // --------------------------------------------
   "DISPOSITION" => [
       "CSI"          => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Custodian"    => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => false],
       "Analyst"      => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Investigator" => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => true],
   ],
   // --------------------------------------------
   // MEDIA (evidence_media)
   // --------------------------------------------
   "MEDIA" => [
       "CSI"          => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Custodian"    => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Analyst"      => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Investigator" => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "Prosecutor"   => ["add" => true, "retrieve" => true, "update" => true, "delete" => false],
       "SysAdmin"     => ["add" => true, "retrieve" => true, "update" => true, "delete" => true],
   ],
   // --------------------------------------------
   // LAB_REPORTS (lab_reports table)
   // --------------------------------------------
   "LAB_REPORTS" => [
       "CSI"          => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Custodian"    => ["add" => false, "retrieve" => false, "update" => false, "delete" => false],
       "Analyst"      => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => false],
       "Investigator" => ["add" => false, "retrieve" => true,  "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => true,  "retrieve" => true,  "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true,  "retrieve" => true,  "update" => true,  "delete" => true],
   ],
   // --------------------------------------------
   // AUDIT_LOGS
   // --------------------------------------------
   "AUDIT_LOGS" => [
       "CSI"          => ["add" => true, "retrieve" => false, "update" => false, "delete" => false],
       "Custodian"    => ["add" => true, "retrieve" => false, "update" => false, "delete" => false],
       "Analyst"      => ["add" => true, "retrieve" => false, "update" => false, "delete" => false],
       "Investigator" => ["add" => true, "retrieve" => false, "update" => false, "delete" => false],
       "Prosecutor"   => ["add" => true, "retrieve" => false, "update" => false, "delete" => false],
       "SysAdmin"     => ["add" => true, "retrieve" => true,  "update" => false, "delete" => false],
   ],
];

// -------------------------------------------------------
// 3. Helper functions
// -------------------------------------------------------
function can_do(string $role, string $table, string $action): bool
{
   global $TABLE_PERMISSIONS;
   $action = strtolower($action);
   if (!isset($TABLE_PERMISSIONS[$table][$role])) {
       return false;
   }
   $perms = $TABLE_PERMISSIONS[$table][$role];
   return !empty($perms[$action]);
}
function can_add(string $role, string $table): bool
{
   return can_do($role, $table, 'add');
}
function can_retrieve(string $role, string $table): bool
{
   return can_do($role, $table, 'retrieve');
}
function can_update(string $role, string $table): bool
{
   return can_do($role, $table, 'update');
}
function can_delete(string $role, string $table): bool
{
   return can_do($role, $table, 'delete');
}