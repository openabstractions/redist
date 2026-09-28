param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][string]$ExpectedSid,
    [Parameter(Mandatory)][string]$ExpectedProgram,
    [Parameter(Mandatory)][string]$PythonPath,
    [Parameter(Mandatory)][string]$NodePath
)
$ErrorActionPreference = 'Stop'
$Directory = (Resolve-Path -LiteralPath $Directory).Path
$manifest = Get-Content -LiteralPath (Join-Path $Directory 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.schema -ne 1 -or -not $manifest.files) { throw 'Installed SDK smoke manifest is invalid' }
foreach ($entry in $manifest.files.PSObject.Properties) {
    if ($entry.Name -match '(^|/)\.\.(/|$)' -or $entry.Name -match '^(/|[A-Za-z]:)' -or $entry.Name.Contains('\')) {
        throw 'Installed SDK smoke manifest has an invalid relative path'
    }
    $file = Join-Path $Directory ($entry.Name.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.Value) {
        throw "Installed SDK smoke input differs from prepared manifest: $($entry.Name)"
    }
}
$env:ABSTRACTION_RUNTIME_ENDPOINT = $null
$env:ABSTRACTION_IPC_LIBRARY = $null
$env:ABSTRACTION_IPC_PREFIX = $null
$env:ABSTRACTION_IPC_NODE = $null
$env:OA_LIVE_PANEL = $null
$env:PYTHONPATH = Join-Path $Directory 'python'

function Invoke-Probe([string]$Name, [string]$Image, [string[]]$Arguments) {
    if (-not (Test-Path -LiteralPath $Image -PathType Leaf)) { throw "Missing installed SDK smoke input: $Image" }
    $output = & $Image @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $output -notmatch "(?m)^PASS $Name installed selection, default discovery and config ReadUser") {
        throw "$Name SDK smoke failed (exit $LASTEXITCODE): $output"
    }
    $output.TrimEnd()
}

Invoke-Probe Go (Join-Path $Directory 'go_probe.exe') @($ExpectedSid, $ExpectedProgram)
Invoke-Probe Cpp (Join-Path $Directory 'cpp_probe.exe') @($ExpectedSid, $ExpectedProgram)
Invoke-Probe Python $PythonPath @((Join-Path $Directory 'python_probe.py'), $ExpectedSid, $ExpectedProgram)
Invoke-Probe Rust (Join-Path $Directory 'rust_probe.exe') @($ExpectedSid, $ExpectedProgram)
Invoke-Probe JavaScript $NodePath @((Join-Path $Directory 'javascript_probe.mjs'), $ExpectedSid, $ExpectedProgram)
