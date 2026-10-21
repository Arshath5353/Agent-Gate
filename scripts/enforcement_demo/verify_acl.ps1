param([Parameter(Mandatory = $true)][string]$AgentIdentity)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$demo = (Resolve-Path (Join-Path $repo 'controlled_workspace\enforcement_demo')).Path
$fixture = (Resolve-Path (Join-Path $demo 'protected_demo.txt')).Path
if (-not $fixture.StartsWith($demo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resolved fixture is outside enforcement_demo.'
}
$sid = ([Security.Principal.NTAccount]$AgentIdentity).Translate([Security.Principal.SecurityIdentifier]).Value
$denyRule = (Get-Acl -LiteralPath $fixture).Access | Where-Object {
    $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid -and
    ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne 0
} | Select-Object -First 1
if (-not $denyRule) {
    Write-Output 'ACL DEMO: FAIL — expected deny ACE for the restricted identity was not found.'
    exit 1
}
Write-Output 'ACL DEMO: PASS — protected fixture has a deny-all ACE for the designated agent identity.'
Write-Output 'Run the documented read/write probe as that identity to verify Windows access denial.'
