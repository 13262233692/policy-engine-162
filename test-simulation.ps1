# Policy Simulation & Impact Analysis Test Script

$ErrorActionPreference = "Stop"

Write-Host "=== Test 1: Single Scenario Simulation ===" -ForegroundColor Cyan
$body1 = @{
    policy_id = "abac/policy"
    policy_content = @'
package abac

default allow := false

allow if {
    input.action.name == "write"
    "viewer" in input.subject.roles
    input.resource.classification == "public"
}

obligations := {
    "log_access": true,
} if {
    allow
}
'@
    subject = @{
        id = "viewer1"
        roles = @("viewer")
        department = "engineering"
    }
    resource = @{
        id = "doc-public"
        type = "document"
        classification = "public"
    }
    action = @{
        name = "write"
    }
    context = @{}
} | ConvertTo-Json -Depth 10

try {
    $r1 = Invoke-RestMethod -Uri http://localhost:8080/api/v1/simulation/evaluate -Method POST -ContentType "application/json" -Body $body1
    Write-Host "Result: $($r1.change)"
    Write-Host "  Current: allowed=$($r1.current.allowed)"
    Write-Host "  Proposed: allowed=$($r1.proposed.allowed)"
    Write-Host "  Diff: $($r1.diff)"
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Test 2: Multi-Scenario Impact Analysis (Data Change) ===" -ForegroundColor Cyan

$body2 = @{
    data_changes = @{
        roles = @{
            admin = @(
                @{ action = "read"; resource = "*" },
                @{ action = "write"; resource = "*" }
            )
            editor = @(
                @{ action = "read"; resource = "*" },
                @{ action = "write"; resource = "document" }
            )
            viewer = @(
                @{ action = "read"; resource = "*" }
            )
            employee = @(
                @{ action = "read"; resource = "document" }
            )
        }
    }
    scenarios = @(
        @{
            name = "Admin delete document"
            subject = @{ id = "admin1"; roles = @("admin"); department = "eng" }
            resource = @{ id = "d1"; type = "document" }
            action = @{ name = "delete" }
            context = @{}
        },
        @{
            name = "Admin write document"
            subject = @{ id = "admin1"; roles = @("admin"); department = "eng" }
            resource = @{ id = "d1"; type = "document" }
            action = @{ name = "write" }
            context = @{}
        },
        @{
            name = "Viewer read document"
            subject = @{ id = "viewer1"; roles = @("viewer"); department = "eng" }
            resource = @{ id = "d1"; type = "document" }
            action = @{ name = "read" }
            context = @{}
        },
        @{
            name = "Viewer delete document"
            subject = @{ id = "viewer1"; roles = @("viewer"); department = "eng" }
            resource = @{ id = "d1"; type = "document" }
            action = @{ name = "delete" }
            context = @{}
        }
    )
} | ConvertTo-Json -Depth 10

try {
    $r2 = Invoke-RestMethod -Uri http://localhost:8080/api/v1/simulation/analyze/data -Method POST -ContentType "application/json" -Body $body2
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Impact Analysis Summary:" -ForegroundColor Yellow
Write-Host "  Total scenarios: $($r2.total_scenarios)"
Write-Host "  Granted:        $($r2.granted_count)"
Write-Host "  Revoked:        $($r2.revoked_count)"
Write-Host "  No change:      $($r2.no_change_count)"

Write-Host ""
Write-Host "Change Matrix:" -ForegroundColor Yellow
$r2.change_matrix | ConvertTo-Json

Write-Host ""
Write-Host "Scenario Details:" -ForegroundColor Yellow
foreach ($result in $r2.results) {
    $beforeAllowed = $result.before.allowed
    $afterAllowed = $result.after.allowed
    $change = $result.change
    $color = "White"
    if ($change -eq "granted") { $color = "Green" }
    if ($change -eq "revoked") { $color = "Red" }
    Write-Host "  [$change] $($result.name): before=$beforeAllowed, after=$afterAllowed" -ForegroundColor $color
    if ($change -ne "no_change") {
        Write-Host "     Note: $($result.description)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "=== Test 3: Visual Permission Change Matrix ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Scenario             | Change    | Before | After"
Write-Host "  ---------------------|-----------|--------|-------"
foreach ($result in $r2.results) {
    $name = $result.name.PadRight(20)
    $change = $result.change.PadRight(9)
    $before = ($result.before.allowed.ToString()).PadRight(6)
    $after = ($result.after.allowed.ToString()).PadRight(5)
    $line = "  $name| $change| $before| $after"
    if ($result.change -eq "granted") {
        Write-Host $line -ForegroundColor Green
    } elseif ($result.change -eq "revoked") {
        Write-Host $line -ForegroundColor Red
    } else {
        Write-Host $line -ForegroundColor Gray
    }
}
Write-Host ""
Write-Host "  Statistics:" -ForegroundColor Yellow
Write-Host "    [+] Granted:   $($r2.granted_count) scenarios" -ForegroundColor Green
Write-Host "    [-] Revoked:   $($r2.revoked_count) scenarios" -ForegroundColor Red
Write-Host "    [=] No Change: $($r2.no_change_count) scenarios" -ForegroundColor Gray

Write-Host ""
Write-Host "All tests completed successfully!" -ForegroundColor Green
