$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$demo = (Resolve-Path (Join-Path $repo 'controlled_workspace\enforcement_demo')).Path
$fixturePath = Join-Path $demo 'protected_demo.txt'
if (Test-Path -LiteralPath $fixturePath -PathType Leaf) {
    $fixture = (Resolve-Path -LiteralPath $fixturePath).Path
    if (-not $fixture.StartsWith($demo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Resolved fixture is outside enforcement_demo; refusing ACL cleanup.'
    }
    & icacls.exe $fixture /reset
    if ($LASTEXITCODE -ne 0) { throw 'Unable to restore inherited ACL on the demo fixture.' }
    Write-Output "Inherited ACL restored on $fixture"
}
