# Shared helpers for OpenAbstractions installation fixtures on disposable
# GitHub-hosted Windows runners: bounded processes, disposable standard
# accounts and their processes, process owners, runtime process and pipe
# checks, MSI product enumeration, PATH matching and diagnostic redaction.
# Functions that create accounts or start account processes refuse to run
# anywhere else. Read-only functions run anywhere.
#
#   Import-Module (Join-Path $PSScriptRoot 'OAFixture.psm1') -Force
#
# installer/test_user_runtime.ps1 and installer/test_service_session.ps1 import
# it from beside themselves; redist publishes it at its root beside both.
# adopters/shared-runtime/two-adopter-download-removal/run.ps1 imports it too.
Set-StrictMode -Version 2.0

function Assert-DisposableRunner {
    if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
        throw 'This mutating fixture requires a disposable GitHub-hosted Windows runner.'
    }
}

# Runs StartInfo with redirected output and keeps the creation handle, so an
# already-exited child still reports its exit code. Kills and throws after $Seconds.
function Invoke-FixtureProcess {
    param([Parameter(Mandatory)][Diagnostics.ProcessStartInfo]$StartInfo, [Parameter(Mandatory)][ValidateRange(1, 86400)][int]$Seconds)
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

# Runs one image with arguments. A nonzero exit throws with redacted output; a
# timeout throws. Success returns nothing.
function Invoke-Bounded {
    param([Parameter(Mandatory)][string]$Image, [string[]]$Arguments = @(), [ValidateRange(1, 86400)][int]$Seconds = 90)
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Image
    $info.Arguments = $Arguments -join ' '
    $result = Invoke-FixtureProcess $info $Seconds
    if ($result.ExitCode -ne 0) { throw "$([IO.Path]::GetFileName($Image)) exited $($result.ExitCode): $(Protect-DiagnosticText ($result.Output + $result.Diagnostics))" }
}

# Bounded text with credentials, bearer tokens and URL user information masked.
function Protect-DiagnosticText([string]$Text) {
    $Text = $Text.Substring(0, [Math]::Min(8192, $Text.Length))
    $Text = $Text -replace '(?i)(password|token|secret|authorization|api[_-]?key)(\s*[:=]\s*)\S+', '$1$2[redacted]'
    $Text = $Text -replace '(?i)Bearer\s+\S+', 'Bearer [redacted]'
    return $Text -replace '(https?://)[^/\s@]+@', '$1[redacted]@'
}

# Creates a local account with a random password, masked in the Actions log, in
# Users (S-1-5-32-545) or the group named by GroupSid. Returns Name, Sid and
# Credential. A caller that must record the name before creation passes -Name.
function New-DisposableAccount {
    param([ValidatePattern('^[a-z][a-z0-9_]{1,9}$')][string]$Prefix = 'oa_ci',
          [ValidatePattern('^[a-z][a-z0-9_]{1,19}$')][string]$Name,
          [ValidatePattern('^S-1-5-32-\d+$')][string]$GroupSid = 'S-1-5-32-545')
    Assert-DisposableRunner
    if (-not $Name) { $Name = $Prefix + '_' + [Guid]::NewGuid().ToString('N').Substring(0, 10) }
    $bytes = New-Object byte[] 30
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $plain = 'Aa1!' + [Convert]::ToBase64String($bytes)
    Write-Host "::add-mask::$plain"
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    $account = New-LocalUser -Name $Name -Password $secure -AccountNeverExpires
    Add-LocalGroupMember -Group (Get-LocalGroup -SID $GroupSid) -Member $account
    return [pscustomobject]@{
        Name = $Name
        Sid = $account.SID.Value
        Credential = New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\$Name", $secure)
    }
}

# Grants the account Modify or ReadExecute on a directory tree.
function Grant-AccountAccess {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sid, [ValidateSet('Modify', 'ReadExecute')][string]$Access = 'Modify')
    Assert-DisposableRunner
    $right = if ($Access -eq 'Modify') { 'M' } else { 'RX' }
    & icacls.exe $Path /grant "*${Sid}:(OI)(CI)$right" /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot grant $Access on $Path" }
}

# Runs a process as the account through a credential logon with its profile loaded.
function Invoke-AccountProcess {
    param([Parameter(Mandatory)]$Account, [Parameter(Mandatory)][string]$FileName, [string[]]$Arguments = @(),
          [Parameter(Mandatory)][string]$WorkingDirectory, [ValidateRange(1, 86400)][int]$Seconds = 600)
    Assert-DisposableRunner
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $FileName
    $info.Arguments = $Arguments -join ' '
    $info.WorkingDirectory = $WorkingDirectory
    $info.UserName = $Account.Name
    $info.Domain = $env:COMPUTERNAME
    $info.Password = $Account.Credential.Password
    $info.LoadUserProfile = $true
    return Invoke-FixtureProcess $info $Seconds
}

function Test-CimNotFound([Exception]$Exception) {
    for ($e = $Exception; $e; $e = $e.InnerException) {
        # WBEM_E_NOT_FOUND, surfaced as an HRESULT or as MI NativeErrorCode NotFound.
        if ($e.HResult -eq -2147217406 -or $e.Message -match '0x80041002') { return $true }
        $native = $e.PSObject.Properties['NativeErrorCode']
        if ($native -and [string]$native.Value -eq 'NotFound') { return $true }
    }
    return $false
}
# Gone only when the owner query reported not-found (or no error) and no process
# with the same PID and creation time exists any more.
function Test-ProcessGone($Process, [Exception]$Exception) {
    if ($Exception -and -not (Test-CimNotFound $Exception)) { return $false }
    foreach ($current in @(Get-CimInstance Win32_Process -Filter "ProcessId=$([uint32]$Process.ProcessId)")) {
        if ($current.CreationDate -eq $Process.CreationDate) { return $false }
    }
    return $true
}
# Owner SID, or $null for a process that exited after enumeration. Any other
# failure to establish the owner throws.
function Get-ProcessOwnerSid($Process) {
    try { $owner = Invoke-CimMethod -InputObject $Process -MethodName GetOwnerSid -ErrorAction Stop }
    catch {
        if (Test-ProcessGone $Process $_.Exception) { return $null }
        throw
    }
    if ($owner.ReturnValue -ne 0) {
        if (Test-ProcessGone $Process $null) { return $null }
        throw "Cannot establish owner of process $($Process.ProcessId): GetOwnerSid returned $($owner.ReturnValue)"
    }
    return [string]$owner.Sid
}

# Stops the account's processes and deletes the account after checking its SID.
# -RuntimeProcessesOnly stops only its jobd, jobdw and openabstractions
# processes, whose owners must be established; otherwise every process whose
# owner is readable is considered. -RequirePresent treats a missing account as
# a changed identity.
function Remove-DisposableAccount {
    param([Parameter(Mandatory)]$Account, [switch]$RuntimeProcessesOnly, [switch]$RequirePresent)
    Assert-DisposableRunner
    $current = Get-LocalUser -Name $Account.Name -ErrorAction SilentlyContinue
    if (-not $current) {
        if ($RequirePresent) { throw 'Cleanup account identity changed' }
        return
    }
    if ($current.SID.Value -ne $Account.Sid) { throw 'Cleanup account identity changed' }
    if ($RuntimeProcessesOnly) {
        foreach ($process in @(Get-RuntimeProcesses $Account.Sid)) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } else {
        foreach ($process in @(Get-CimInstance Win32_Process)) {
            try { $owner = Get-ProcessOwnerSid $process }
            catch { if ($_.Exception.Message -like 'Cannot establish owner of process*') { continue }; throw }
            if ($owner -eq $Account.Sid) { Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue }
        }
    }
    Remove-LocalUser -Name $Account.Name
}

# jobd, jobdw and openabstractions processes owned by the SID.
function Get-RuntimeProcesses([string]$Sid) {
    foreach ($candidate in @(Get-CimInstance Win32_Process -Filter "Name='jobd.exe' OR Name='jobdw.exe' OR Name='openabstractions.exe'")) {
        $owner = Get-ProcessOwnerSid $candidate
        if ($null -ne $owner -and $owner -eq $Sid) { $candidate }
    }
}

function Get-PipeNames { [IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [IO.Path]::GetFileName($_) } }
# Named pipes of the SID's capabilities. -Runtime names exactly the runtime,
# logging, config and job acceptance endpoints; otherwise any pipe carrying the
# SID's capability prefix.
function Get-CapabilityPipes([string]$Sid, [switch]$Runtime) {
    $prefix = "openabstractions-user-$Sid-"
    if ($Runtime) {
        $names = @('runtime-v1','logging-v1','config-v1','job-acceptance-v1' | ForEach-Object { $prefix + $_ })
        return @(Get-PipeNames | Where-Object { $_ -in $names })
    }
    @(Get-PipeNames | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
}

# Throws unless the SID has no runtime process and no capability pipe within $Seconds.
function Assert-NoRuntime {
    param([Parameter(Mandatory)][string]$Sid, [ValidateRange(0, 600)][int]$Seconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $processes = @(Get-RuntimeProcesses $Sid)
        $pipes = @(Get-CapabilityPipes $Sid)
        if ($processes.Count -eq 0 -and $pipes.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Runtime removal left processes $(@($processes | ForEach-Object ProcessId) -join ',') or pipes $($pipes -join ',')"
}

# Installed MSI products through WindowsInstaller.Installer.ProductsEx.
# Context: 1 user-managed, 2 user-unmanaged, 4 machine, 7 all. UserSid '' with
# machine context; a SID or 's-1-1-0' (everyone) with user contexts. The default
# is the invoking user's unmanaged products.
function Get-InstalledProducts {
    param([string]$UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
          [ValidateSet(1, 2, 4, 7)][int]$Context = 2, [string]$ProductName)
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        $products = $installer.ProductsEx('', $(if ($Context -eq 4) { '' } else { $UserSid }), $Context)
        try {
            foreach ($product in $products) {
                try {
                    $item = [pscustomobject]@{
                        ProductCode = [string]$product.GetType().InvokeMember('ProductCode', [Reflection.BindingFlags]::GetProperty, $null, $product, $null)
                        ProductName = [string]$product.InstallProperty('ProductName')
                        VersionString = [string]$product.InstallProperty('VersionString')
                        State = [string]$product.InstallProperty('State')
                        Context = [int]$product.GetType().InvokeMember('Context', [Reflection.BindingFlags]::GetProperty, $null, $product, $null)
                        UserSid = [string]$product.GetType().InvokeMember('UserSid', [Reflection.BindingFlags]::GetProperty, $null, $product, $null)
                    }
                    if (-not $ProductName -or $item.ProductName -eq $ProductName) { $item }
                } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($product) }
            }
        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($products) }
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
}

# True when a PATH value names the directory, ignoring case, quotes, slash
# direction and a trailing separator.
function Test-PathNames {
    param([AllowEmptyString()][AllowNull()][string]$Value, [Parameter(Mandatory)][string]$Directory)
    $normalize = { param($text) $text.Trim().Trim('"').Replace('/', '\').TrimEnd('\').ToLowerInvariant() }
    $want = & $normalize $Directory
    if (-not $want -or -not $Value) { return $false }
    foreach ($entry in ($Value -split ';')) {
        if ((& $normalize $entry) -eq $want) { return $true }
    }
    return $false
}

Export-ModuleMember -Function Assert-DisposableRunner, Invoke-FixtureProcess, Invoke-Bounded, Protect-DiagnosticText,
    New-DisposableAccount, Grant-AccountAccess, Invoke-AccountProcess, Test-CimNotFound, Test-ProcessGone,
    Get-ProcessOwnerSid, Remove-DisposableAccount, Get-RuntimeProcesses, Get-PipeNames, Get-CapabilityPipes,
    Assert-NoRuntime, Get-InstalledProducts, Test-PathNames
