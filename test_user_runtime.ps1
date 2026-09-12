param(
    [ValidateSet('ValidateOnly','Verify','User')][string]$Mode = 'ValidateOnly',
    [string]$MsiPath,
    [string]$ExpectedSid,
    [string]$ResultDirectory = (Join-Path (Get-Location) 'user-runtime-diagnostics')
)
$ErrorActionPreference = 'Stop'
if ($Mode -eq 'ValidateOnly') {
    'Per-user fixture parsed; no accounts, processes, installations or registrations changed.'
    exit 0
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This mutating fixture requires a disposable GitHub-hosted runner.'
}
function Invoke-Bounded([string]$Image, [string[]]$Arguments, [int]$Seconds = 90) {
    $process = Start-Process -FilePath $Image -ArgumentList $Arguments -WindowStyle Hidden -PassThru
    try {
        if (-not $process.WaitForExit($Seconds * 1000)) {
            $process.Kill(); $process.WaitForExit(5000) | Out-Null
            throw "Process exceeded ${Seconds}s: $([IO.Path]::GetFileName($Image))"
        }
        $process.Refresh()
        if ($process.ExitCode -ne 0) { throw "$([IO.Path]::GetFileName($Image)) exited $($process.ExitCode)" }
    } finally { $process.Dispose() }
}
function Assert-NoRuntime([string]$Sid) {
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
    $remaining = @(Get-CimInstance Win32_Process -Filter "Name='jobdw.exe' OR Name='openabstractions.exe'" | Where-Object {
        $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid
        if ($owner.ReturnValue -ne 0) { throw 'Cannot establish runtime process owner' }
        $owner.Sid -eq $Sid
    })
    $prefix = "openabstractions-user-$Sid-"
    $pipes = @([IO.Directory]::GetFiles('\\.\pipe\') | Where-Object {
        [IO.Path]::GetFileName($_) -in @("${prefix}runtime-v1", "${prefix}logging-v1", "${prefix}config-v1", "${prefix}job-acceptance-v1")
    })
        if ($remaining.Count -eq 0 -and $pipes.Count -eq 0) { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Uninstall left account runtime processes or capability endpoints'
}
if ($Mode -eq 'User') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($identity.User.Value -ne $ExpectedSid -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Fixture requires the exact private non-admin account'
    }
    $env:ABSTRACTION_RUNTIME_ENDPOINT = $null
    $env:ABSTRACTION_STORE = $null
    $env:MODELGET_STORE = $null
    $tools = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\OpenAbstractions\tools'
    $shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'Abstraction supervisor.lnk'
    $installed = $false
    try {
        Invoke-Bounded msiexec.exe @('/i', "`"$MsiPath`"", '/qn', '/norestart', 'ALLUSERS=2', 'MSIINSTALLPERUSER=1', '/l*v', 'user-install.log')
        $installed = $true
        if (@(Get-Service | Where-Object { $_.Name -like 'OpenAbstractionsSupervisor*' }).Count) { throw 'Per-user install registered a service' }
        if (-not (Test-Path -LiteralPath $shortcutPath)) { throw 'Installed Startup shortcut missing' }
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        if ($shortcut.TargetPath -ne (Join-Path $tools 'jobdw.exe') -or $shortcut.Arguments -ne 'start --runtime' -or $shortcut.WorkingDirectory -ne $tools) {
            throw 'Installed shortcut target, runtime arguments or working directory differ'
        }
        Push-Location $shortcut.WorkingDirectory
        try { Invoke-Bounded $shortcut.TargetPath @($shortcut.Arguments) 30 } finally { Pop-Location }
        $central = Join-Path $tools 'openabstractions.exe'
        $probe = Start-Process -FilePath $central -ArgumentList @('status','--json','--timeout','5s') -WindowStyle Hidden -PassThru -RedirectStandardOutput 'runtime-status.json' -RedirectStandardError 'runtime-status.err'
        try {
            if (-not $probe.WaitForExit(10000)) { $probe.Kill(); $probe.WaitForExit(5000) | Out-Null; throw 'Runtime status deadline' }
            $probe.Refresh()
            if ($probe.ExitCode -ne 0) { throw 'Runtime status failed' }
        } finally { $probe.Dispose() }
        $status = Get-Content 'runtime-status.json' -Raw | ConvertFrom-Json
        foreach ($capability in @('abstraction.logging','abstraction.config')) {
            if (@($status.capabilities | Where-Object { $_.capability -eq $capability -and $_.status -eq 'resolved' }).Count -ne 1) {
                throw "Missing ready capability: $capability"
            }
        }
        'ok: installed shortcut invocation resolved logging/config as a non-admin account' | Set-Content 'activation.txt'
        Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'user-uninstall.log')
        $installed = $false
        # These assertions precede outer fixture cleanup and its process termination.
        Assert-NoRuntime $ExpectedSid
        if (Test-Path -LiteralPath $shortcutPath) { throw 'Startup shortcut survived uninstall' }
        foreach ($name in @('jobdw.exe','openabstractions.exe')) {
            if (Test-Path -LiteralPath (Join-Path $tools $name)) { throw "Installed $name survived uninstall" }
        }
        'ok: uninstall removed processes, endpoints, shortcut and runtime binaries before fixture cleanup' | Set-Content 'removal.txt'
    } finally {
        if ($installed) {
            try { Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'user-cleanup-uninstall.log') } catch { Write-Warning $_ }
        }
    }
    exit 0
}

$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
if ([IO.Path]::GetExtension($MsiPath) -ne '.msi') { throw 'Expected an MSI package' }
if (@(Get-Service | Where-Object { $_.Name -like 'OpenAbstractionsSupervisor*' }).Count) { throw 'Run per-user verification on a separate clean runner' }
$user = 'oa_ci_' + [Guid]::NewGuid().ToString('N').Substring(0,10)
$directory = Join-Path $env:ProgramData ('OA-User-Test-' + [Guid]::NewGuid().ToString('N'))
$account = $null
$child = $null
$bytes = New-Object byte[] 30
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$password = 'Aa1!' + [Convert]::ToBase64String($bytes)
Write-Output "::add-mask::$password"
try {
    $account = New-LocalUser -Name $user -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $account
    New-Item -ItemType Directory -Path $directory | Out-Null
    & icacls.exe $directory /grant "*$($account.SID.Value):(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant private fixture directory access' }
    Copy-Item -LiteralPath $MsiPath -Destination (Join-Path $directory 'package.msi')
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $directory 'fixture.ps1')
    $credential = New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $password -AsPlainText -Force))
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$directory\fixture.ps1`"",'-Mode','User','-MsiPath',"`"$directory\package.msi`"",'-ExpectedSid',$account.SID.Value)
    $child = Start-Process powershell.exe -ArgumentList $arguments -Credential $credential -LoadUserProfile -WorkingDirectory $directory -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $directory 'fixture.log') -RedirectStandardError (Join-Path $directory 'fixture.err')
    if (-not $child.WaitForExit(300000)) { $child.Kill(); $child.WaitForExit(5000) | Out-Null; throw 'Per-user fixture exceeded five minutes' }
    $child.Refresh()
    if ($child.ExitCode -ne 0) { throw "Per-user fixture exited $($child.ExitCode); inspect diagnostics" }
    Assert-NoRuntime $account.SID.Value
} finally {
    if ($child) { $child.Dispose() }
    try {
        if (Test-Path -LiteralPath $directory) {
            New-Item -ItemType Directory -Force -Path $ResultDirectory | Out-Null
            Get-ChildItem -LiteralPath $directory -File | Where-Object { $_.Extension -in @('.log','.err','.txt','.json') } | Copy-Item -Destination $ResultDirectory
        }
    } catch { Write-Warning "Could not preserve all fixture diagnostics: $_" }
    if ($account) {
        $current = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
        if (-not $current -or $current.SID.Value -ne $account.SID.Value) { throw 'Cleanup account identity changed' }
        # Account-owned leftovers are cleanup only; no assertion becomes green here.
        foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='jobdw.exe' OR Name='openabstractions.exe'")) {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
            if ($owner.ReturnValue -eq 0 -and $owner.Sid -eq $account.SID.Value) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-LocalUser -Name $user
    }
    # Retain the fixture directory for runner disposal; never recursively delete
    # a path writable by the test account, which could contain reparse points.
}
