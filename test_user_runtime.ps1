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
function Invoke-FixtureProcess([Diagnostics.ProcessStartInfo]$StartInfo, [int]$Seconds) {
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    if (-not $StartInfo.WorkingDirectory) { $StartInfo.WorkingDirectory = (Get-Location).Path }
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $StartInfo
    try {
        if (-not $process.Start()) { throw 'Fixture process did not start' }
        $output = $process.StandardOutput.ReadToEndAsync()
        $diagnostics = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Seconds * 1000)) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw 'Fixture process termination was not observed' }
            throw "Fixture process exceeded ${Seconds}s"
        }
        if (-not $output.Wait(5000) -or -not $diagnostics.Wait(5000)) { throw 'Fixture process output did not close' }
        $code = $process.ExitCode
        if ($null -eq $code) { throw 'Fixture process exit code was not observed' }
        return [pscustomobject]@{ ExitCode=$code; Output=$output.Result; Diagnostics=$diagnostics.Result }
    } finally { $process.Dispose() }
}
function Invoke-Bounded([string]$Image, [string[]]$Arguments, [int]$Seconds = 90) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Image
    $info.Arguments = $Arguments -join ' '
    $result = Invoke-FixtureProcess $info $Seconds
    if ($result.ExitCode -ne 0) { throw "$([IO.Path]::GetFileName($Image)) exited $($result.ExitCode)" }
}
function Get-ProfileFolder([Environment+SpecialFolder]$Folder, [scriptblock]$Resolve = {
    param($Name, $Option)
    [Environment]::GetFolderPath($Name, $Option)
}) {
    # A newly loaded profile may have a configured folder which is not on disk.
    $path = & $Resolve $Folder ([Environment+SpecialFolderOption]::DoNotVerify)
    if ([string]::IsNullOrWhiteSpace($path)) { throw "Profile folder is unavailable: $Folder" }
    return $path
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
function Assert-RuntimeReady([string]$central, [string]$Evidence) {
    $probeInfo = New-Object Diagnostics.ProcessStartInfo
    $probeInfo.FileName = $central
    $probeInfo.Arguments = 'status --json --timeout 5s'
    $probe = Invoke-FixtureProcess $probeInfo 10
    $probe.Output | Set-Content -Encoding UTF8 "$Evidence.json"
    $probe.Diagnostics | Set-Content -Encoding UTF8 "$Evidence.err"
    if ($probe.ExitCode -ne 0) { throw "Runtime status exited $($probe.ExitCode)" }
    $status = Get-Content "$Evidence.json" -Raw | ConvertFrom-Json
    foreach ($capability in @('abstraction.logging','abstraction.config')) {
        if (@($status.capabilities | Where-Object { $_.capability -eq $capability -and $_.status -eq 'resolved' }).Count -ne 1) {
            throw "Missing ready capability: $capability"
        }
    }
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
    $tools = Join-Path (Get-ProfileFolder LocalApplicationData) 'Programs\OpenAbstractions\tools'
    $installed = $false
    $installAttempted = $false
    try {
        $installAttempted = $true
        Invoke-Bounded msiexec.exe @('/i', "`"$MsiPath`"", '/qn', '/norestart', 'ALLUSERS=2', 'MSIINSTALLPERUSER=1', '/l*v', 'user-install.log')
        $installed = $true
        $central = Join-Path $tools 'openabstractions.exe'
        Assert-RuntimeReady $central post-install-status
        'ok: logging/config ready immediately after MSI completion' | Set-Content 'post-install-activation.txt'
        $shortcutPath = Join-Path (Get-ProfileFolder Startup) 'Abstraction supervisor.lnk'
        if (@(Get-Service | Where-Object { $_.Name -like 'OpenAbstractionsSupervisor*' }).Count) { throw 'Per-user install registered a service' }
        if (-not (Test-Path -LiteralPath $shortcutPath)) { throw 'Installed Startup shortcut missing' }
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        if ($shortcut.TargetPath -ne (Join-Path $tools 'jobdw.exe') -or $shortcut.Arguments -ne 'start --runtime' -or $shortcut.WorkingDirectory -ne $tools) {
            throw 'Installed shortcut target, runtime arguments or working directory differ'
        }
        Push-Location $shortcut.WorkingDirectory
        try { Invoke-Bounded $shortcut.TargetPath @($shortcut.Arguments) 30 } finally { Pop-Location }
        Assert-RuntimeReady $central runtime-status
        'ok: installed shortcut invocation resolved logging/config as a non-admin account' | Set-Content 'activation.txt'
        Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'user-uninstall.log')
        $installed = $false
        $installAttempted = $false
        # These assertions precede outer fixture cleanup and its process termination.
        Assert-NoRuntime $ExpectedSid
        if (Test-Path -LiteralPath $shortcutPath) { throw 'Startup shortcut survived uninstall' }
        foreach ($name in @('jobdw.exe','openabstractions.exe')) {
            if (Test-Path -LiteralPath (Join-Path $tools $name)) { throw "Installed $name survived uninstall" }
        }
        'ok: uninstall removed processes, endpoints, shortcut and runtime binaries before fixture cleanup' | Set-Content 'removal.txt'
    } finally {
        if ($installed -or $installAttempted) {
            # A post-InstallFinalize activation error can leave committed files.
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
    # Credential logon creates a fresh environment. This parent has already
    # checked both runner markers; carry only those markers to the child.
    $launcher = @'
$ErrorActionPreference = 'Stop'
$env:GITHUB_ACTIONS = 'true'
$env:RUNNER_ENVIRONMENT = 'github-hosted'
& (Join-Path $PSScriptRoot 'fixture.ps1') @args
exit $LASTEXITCODE
'@
    Set-Content -LiteralPath (Join-Path $directory 'launcher.ps1') -Value $launcher -Encoding UTF8
    $credential = New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $password -AsPlainText -Force))
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$directory\launcher.ps1`"",'-Mode','User','-MsiPath',"`"$directory\package.msi`"",'-ExpectedSid',$account.SID.Value)
    $childInfo = New-Object Diagnostics.ProcessStartInfo
    $childInfo.FileName = 'powershell.exe'
    $childInfo.Arguments = $arguments -join ' '
    $childInfo.WorkingDirectory = $directory
    $childInfo.UserName = $user
    $childInfo.Domain = $env:COMPUTERNAME
    $childInfo.Password = $credential.Password
    $childInfo.LoadUserProfile = $true
    $child = Invoke-FixtureProcess $childInfo 300
    $child.Output | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.log')
    $child.Diagnostics | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.err')
    if ($child.ExitCode -ne 0) { throw "Per-user fixture exited $($child.ExitCode); inspect diagnostics" }
    Assert-NoRuntime $account.SID.Value
} finally {
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
