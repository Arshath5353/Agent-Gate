param(
    [Parameter(Mandatory = $true)][string]$AgentIdentity,
    [Parameter(Mandatory = $true)][string]$BrokerIdentity
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$demo = Join-Path $repo 'controlled_workspace\enforcement_demo'
$fixture = Join-Path $demo 'protected_demo.txt'
New-Item -ItemType Directory -Path $demo -Force | Out-Null
if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    Set-Content -LiteralPath $fixture -Value 'Protected AgentGate demo fixture.' -Encoding utf8
}
$resolvedDemo = (Resolve-Path -LiteralPath $demo).Path
$resolvedFixture = (Resolve-Path -LiteralPath $fixture).Path
if (-not $resolvedFixture.StartsWith($resolvedDemo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resolved fixture is outside enforcement_demo; refusing ACL changes.'
}
$beforeAcl = Get-Acl -LiteralPath $resolvedFixture
if ($beforeAcl.AreAccessRulesProtected) {
    throw 'Fixture already has a protected/custom DACL. Restore or review it manually before setup; refusing to overwrite it.'
}
function Resolve-Sid([string]$Identity) {
    return ([Security.Principal.NTAccount]$Identity).Translate([Security.Principal.SecurityIdentifier]).Value
}
$agentSid = Resolve-Sid $AgentIdentity
$brokerSid = Resolve-Sid $BrokerIdentity
if ($agentSid -eq $brokerSid) { throw 'AgentIdentity and BrokerIdentity must be different Windows accounts.' }
# The DACL change applies to this one demo file only. The broker identity retains Modify;
# the designated agent identity is denied access. SYSTEM remains available for recovery.
& icacls.exe $resolvedFixture /inheritance:r /grant:r "*S-1-5-18:(F)" "*$($brokerSid):(M)" /deny "*$($agentSid):(F)"
if ($LASTEXITCODE -ne 0) { throw 'icacls failed while configuring the demo fixture.' }
Write-Output "ACL configured only on $resolvedFixture"
