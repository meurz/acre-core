# Run repeatable, read-only scans and save reports for local analysis.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [ValidateSet('auto', 'mft', 'walk', 'ntfs-reader', 'ntfs-reader-full')]
    [string]$Backend = 'auto',
    [ValidateRange(1, 100)][int]$Rounds = 3,
    [string]$Out = (Join-Path $PSScriptRoot '..\bench-out'),
    [string]$Executable = (Join-Path $PSScriptRoot '..\target\release\acre-bench.exe')
)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path -LiteralPath $Out).Path
$scanRoot = (Resolve-Path -LiteralPath $Root).Path
$tag = $scanRoot.TrimEnd('\').Replace(':', '') -replace '[^A-Za-z0-9._]', '_'
if (-not $tag) { $tag = 'root' }

function Invoke-Benchmark([string[]]$Arguments) {
    # Windows PowerShell turns redirected native stderr into error records.
    # The CLI writes progress there, so determine success from its exit code.
    $ErrorActionPreference = 'Continue'
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "acre-bench failed with exit code $LASTEXITCODE."
    }
}

for ($round = 1; $round -le $Rounds; $round++) {
    $report = Join-Path $Out "$Backend-$tag-r$round.json"
    Write-Host "Round $round/$Rounds ($Backend): $scanRoot"
    Invoke-Benchmark -Arguments @('scan', $scanRoot, '--backend', $Backend, '--out', $report)
}
Invoke-Benchmark -Arguments @('summarize', $Out)
