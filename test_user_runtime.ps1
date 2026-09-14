param(
    [ValidateSet('ValidateOnly','Verify','User')][string]$Mode = 'ValidateOnly',
    [string]$MsiPath,
    [string]$ExpectedSid,
    [switch]$CheckTools,
    [string]$PythonPath,
    [string]$PredecessorMsiPath,
    [string]$PredecessorSHA256,
    [string]$ExpectedVersion,
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
    if ($result.ExitCode -ne 0) { throw "$([IO.Path]::GetFileName($Image)) exited $($result.ExitCode): $(Protect-DiagnosticText ($result.Output + $result.Diagnostics))" }
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
function Assert-NoRuntime([string]$Sid, [string]$DiagnosticPath, [string]$Folder, [int]$Seconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $remaining = @(Get-AccountFixtureProcesses $Sid)
        $pipes = @(Get-CapabilityPipes $Sid)
        if ($remaining.Count -eq 0 -and $pipes.Count -eq 0) { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    # Diagnostics are evidence only. Their failure never changes the verdict.
    if ($DiagnosticPath) {
        try { Save-RuntimeSnapshot $DiagnosticPath $Sid 'removal-deadline' $Folder }
        catch { Write-Warning ('Removal diagnostics failed: ' + (Protect-DiagnosticText $_.Exception.Message)) }
    }
    throw 'Uninstall left account runtime processes or capability endpoints'
}
function Get-FixtureProcessCandidates {
    Get-CimInstance Win32_Process -Filter "Name='jobd.exe' OR Name='jobdw.exe' OR Name='openabstractions.exe'"
}
function Get-FixtureProcessById($Id) {
    Get-CimInstance Win32_Process -Filter "ProcessId=$([uint32]$Id)"
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
# A listed process is gone only when the owner query reported not-found (or no
# error) and no process with the same PID and creation time exists any more.
function Test-FixtureProcessGone($Candidate, [Exception]$Exception) {
    if ($Exception -and -not (Test-CimNotFound $Exception)) { return $false }
    foreach ($current in @(Get-FixtureProcessById $Candidate.ProcessId)) {
        if ($current.CreationDate -eq $Candidate.CreationDate) { return $false }
    }
    return $true
}
# Returns the owner SID, or $null for a process that exited after enumeration.
function Get-FixtureProcessOwner($Candidate) {
    try { $owner = Invoke-CimMethod -InputObject $Candidate -MethodName GetOwnerSid -ErrorAction Stop }
    catch {
        if (Test-FixtureProcessGone $Candidate $_.Exception) { return $null }
        throw
    }
    if ($owner.ReturnValue -ne 0) {
        if (Test-FixtureProcessGone $Candidate $null) { return $null }
        throw "Cannot establish owner of process $($Candidate.ProcessId): GetOwnerSid returned $($owner.ReturnValue)"
    }
    return [string]$owner.Sid
}
function Get-AccountFixtureProcesses([string]$Sid) {
    foreach ($candidate in @(Get-FixtureProcessCandidates)) {
        $owner = Get-FixtureProcessOwner $candidate
        if ($null -ne $owner -and $owner -eq $Sid) { $candidate }
    }
}
function Get-PipeNames { [IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [IO.Path]::GetFileName($_) } }
function Get-CapabilityPipes([string]$Sid) {
    $prefix = "openabstractions-user-$Sid-"
    $names = @('runtime-v1','logging-v1','config-v1','job-acceptance-v1' | ForEach-Object { $prefix + $_ })
    @(Get-PipeNames | Where-Object { $_ -in $names })
}
function Get-AccountProcessDetails([string]$Sid) {
    foreach ($process in @(Get-AccountFixtureProcesses $Sid)) {
        $parent = @(Get-FixtureProcessById $process.ParentProcessId | Select-Object -First 1)
        # A parent created after its child holds a reused PID and names nothing.
        $reused = $parent.Count -and $parent[0].CreationDate -gt $process.CreationDate
        [ordered]@{
            pid = [uint32]$process.ProcessId
            parentPid = [uint32]$process.ParentProcessId
            parentName = if ($parent.Count -and -not $reused) { [string]$parent[0].Name } else { $null }
            parentPidReused = [bool]$reused
            sessionId = [uint32]$process.SessionId
            executablePath = [string]$process.ExecutablePath
            commandLine = Protect-DiagnosticText ([string]$process.CommandLine)
            creationDate = if ($process.CreationDate) { ([DateTime]$process.CreationDate).ToUniversalTime().ToString('o') } else { $null }
        }
    }
}
function Get-RestartManagerView([string]$Folder) {
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder -PathType Container)) { return [ordered]@{ folder = $Folder; exists = $false } }
    $files = @(Get-ChildItem -LiteralPath $Folder -File -Recurse -Force -ErrorAction Stop | Select-Object -First 512 -ExpandProperty FullName)
    if (-not ('OaFixtureRestartManager' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class OaFixtureRestartManager {
    [StructLayout(LayoutKind.Sequential)]
    public struct UniqueProcess { public int ProcessId; public uint StartLow; public uint StartHigh; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ProcessInfo {
        public UniqueProcess Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string AppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string ServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint SessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool Restartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmStartSession(out uint session, int flags, StringBuilder key);
    [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint session);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmRegisterResources(uint session, uint fileCount, string[] files, uint processCount, UniqueProcess[] processes, uint serviceCount, string[] services);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmGetList(uint session, out uint needed, ref uint count, [In, Out] ProcessInfo[] info, out uint reasons);
    public static ProcessInfo[] Query(string[] files, out uint reasons) {
        uint session;
        int code = RmStartSession(out session, 0, new StringBuilder(64));
        if (code != 0) { throw new Win32Exception(code); }
        try {
            code = RmRegisterResources(session, (uint)files.Length, files, 0, null, 0, null);
            if (code != 0) { throw new Win32Exception(code); }
            for (int attempt = 0; attempt < 4; attempt++) {
                uint needed;
                uint count = 0;
                code = RmGetList(session, out needed, ref count, null, out reasons);
                if (code == 0) { return new ProcessInfo[0]; }
                if (code != 234) { throw new Win32Exception(code); }
                ProcessInfo[] info = new ProcessInfo[needed];
                count = needed;
                code = RmGetList(session, out needed, ref count, info, out reasons);
                if (code == 0) { Array.Resize(ref info, (int)count); return info; }
                if (code != 234) { throw new Win32Exception(code); }
            }
            throw new Win32Exception(234);
        } finally { RmEndSession(session); }
    }
}
'@
    }
    $types = @{ 0='RmUnknownApp'; 1='RmMainWindow'; 2='RmOtherWindow'; 3='RmService'; 4='RmExplorer'; 5='RmConsole'; 1000='RmCritical' }
    $reasons = [uint32]0
    $apps = if ($files.Count) { @([OaFixtureRestartManager]::Query([string[]]$files, [ref]$reasons)) } else { @() }
    $reasonNames = @(@{ 1='PermissionDenied'; 2='SessionMismatch'; 4='CriticalProcess'; 8='CriticalService'; 16='DetectedSelf' }.GetEnumerator() |
        Where-Object { $reasons -band $_.Key } | Sort-Object Key | ForEach-Object { $_.Value })
    [ordered]@{
        folder = $Folder
        exists = $true
        registeredFiles = $files.Count
        rebootReasons = $reasons
        rebootReasonNames = $reasonNames
        applications = @(foreach ($app in $apps) {
            $type = [int]$app.ApplicationType
            [ordered]@{
                pid = $app.Process.ProcessId
                startTimeUtc = [DateTime]::FromFileTimeUtc(([long]$app.Process.StartHigh -shl 32) -bor [long]$app.Process.StartLow).ToString('o')
                name = $app.AppName
                serviceShortName = $app.ServiceShortName
                type = if ($types.ContainsKey($type)) { $types[$type] } else { "$type" }
                status = $app.AppStatus
                sessionId = $app.SessionId
                restartable = $app.Restartable
            }
        })
    }
}
function Save-RuntimeSnapshot([string]$Path, [string]$Sid, [string]$Stage, [string]$Folder) {
    $snapshot = [ordered]@{ stage = $Stage; capturedUtc = [DateTime]::UtcNow.ToString('o'); sid = $Sid; observerPid = $PID; processes = @(); pipes = @() }
    try { $snapshot.processes = @(Get-AccountProcessDetails $Sid) } catch { $snapshot.processError = Protect-DiagnosticText $_.Exception.Message }
    try { $snapshot.pipes = @(Get-CapabilityPipes $Sid) } catch { $snapshot.pipeError = Protect-DiagnosticText $_.Exception.Message }
    if ($Folder) {
        try { $snapshot.restartManager = Get-RestartManagerView $Folder } catch { $snapshot.restartManagerError = Protect-DiagnosticText $_.Exception.Message }
    }
    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Assert-InstalledShortcut($Shortcut, [string]$Tools) {
    $expectedTarget = [IO.Path]::GetFullPath((Join-Path $Tools 'jobdw.exe'))
    $expectedDirectory = [IO.Path]::GetFullPath($Tools).TrimEnd([char[]]'\/')
    $actualTarget = if ($Shortcut.TargetPath) { [IO.Path]::GetFullPath($Shortcut.TargetPath) } else { '' }
    $actualDirectory = if ($Shortcut.WorkingDirectory) { [IO.Path]::GetFullPath($Shortcut.WorkingDirectory).TrimEnd([char[]]'\/') } else { '' }
    if ($actualTarget -ne $expectedTarget -or $Shortcut.Arguments -ne 'start --runtime' -or $actualDirectory -ne $expectedDirectory) {
        throw 'Installed shortcut target, runtime arguments or working directory differ'
    }
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
    foreach ($contract in @('abstraction.logging/sink@1','abstraction.config/reader@1','abstraction.config/editor@1','abstraction.job/acceptance@1','abstraction.job/operations@1')) {
        $capability = $contract.Split('/')[0]
        $matches = @($status.capabilities | Where-Object { $_.capability -eq $capability -and $_.contract -eq $contract })
        if ($matches.Count -ne 1 -or $matches[0].status -ne 'resolved') {
            throw "Expected exactly one ready contract: $contract"
        }
    }
}
function Protect-DiagnosticText([string]$Text) {
    $Text = $Text.Substring(0, [Math]::Min(8192, $Text.Length))
    $Text = $Text -replace '(?i)(password|token|secret|authorization|api[_-]?key)(\s*[:=]\s*)\S+', '$1$2[redacted]'
    $Text = $Text -replace '(?i)Bearer\s+\S+', 'Bearer [redacted]'
    return $Text -replace '(https?://)[^/\s@]+@', '$1[redacted]@'
}
function Save-ActivationFailure([string]$Tools) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $profile = Get-ProfileFolder UserProfile
    $context = [ordered]@{
        purpose='diagnostic retry only; original MSI failure remains failure'
        session=(Get-Process -Id $PID).SessionId
        expectedSidMatches=($identity.User.Value -eq $ExpectedSid)
        administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        workingDirectory=(Get-Location).Path
        userProfile=$profile
        environmentProfileMatches=($env:USERPROFILE -eq $profile)
        localApplicationData=(Get-ProfileFolder LocalApplicationData)
        defaultStoreExists=(Test-Path -LiteralPath (Join-Path $profile '.abstraction') -PathType Container)
        legacyStoreExists=(Test-Path -LiteralPath (Join-Path $profile '.modelget') -PathType Container)
        overridesPresent=@('ABSTRACTION_STORE','MODELGET_STORE','ABSTRACTION_RUNTIME_ENDPOINT','ABSTRACTION_NAS_STORE' | Where-Object { [Environment]::GetEnvironmentVariable($_) })
    }
    $context | ConvertTo-Json | Set-Content -Encoding UTF8 'activation-failure-context.json'
    $image = Join-Path $Tools 'jobdw.exe'
    if (-not (Test-Path -LiteralPath $image -PathType Leaf)) {
        'Installed jobdw unavailable for diagnostic retry' | Set-Content 'activation-diagnostic-retry.txt'
        return
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $image
    $info.Arguments = 'start --runtime --require-unelevated'
    # Retain the same fixture working directory and environment as its MSI call.
    $result = Invoke-FixtureProcess $info 30
    [ordered]@{
        purpose='diagnostic retry; never post-install activation evidence'
        exitCode=$result.ExitCode
        stdout=(Protect-DiagnosticText $result.Output)
        stderr=(Protect-DiagnosticText $result.Diagnostics)
    } | ConvertTo-Json | Set-Content -Encoding UTF8 'activation-diagnostic-retry.json'
}
function Invoke-InstallWithDiagnostics([scriptblock]$Install, [scriptblock]$Diagnose) {
    try { & $Install } catch {
        $original = $_
        try { & $Diagnose } catch { Write-Warning ('Activation diagnostics failed: ' + (Protect-DiagnosticText $_.Exception.Message)) }
        throw $original
    }
}
function Assert-PackageHash([string]$Path, [string]$Expected) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
    if ($Expected -notmatch '^[0-9a-f]{64}$' -or $actual -ne $Expected) {
        throw 'Predecessor package differs from the verified release checksum'
    }
}
function Get-PackageProperty([string]$Path, [ValidateSet('ProductVersion','ProductCode','UpgradeCode')][string]$Property) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Path, 0)
    $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$Property'")
    try {
        [void]$view.Execute()
        $record = $view.Fetch()
        if (-not $record) { throw "MSI property absent: $Property" }
        return $record.StringData(1)
    } finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}
function Get-UserProducts {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        # MSIINSTALLCONTEXT_USERUNMANAGED=2; query the invoking fresh user only.
        $products = $installer.ProductsEx('', $sid, 2)
        try {
            foreach ($product in $products) {
                try {
                    [pscustomobject]@{
                        ProductCode = [string]$product.GetType().InvokeMember('ProductCode', [Reflection.BindingFlags]::GetProperty, $null, $product, $null)
                        ProductName = [string]$product.InstallProperty('ProductName')
                        VersionString = [string]$product.InstallProperty('VersionString')
                        State = [string]$product.InstallProperty('State')
                        Context = [int]$product.GetType().InvokeMember('Context', [Reflection.BindingFlags]::GetProperty, $null, $product, $null)
                        UserSid = [string]$product.GetType().InvokeMember('UserSid', [Reflection.BindingFlags]::GetProperty, $null, $product, $null)
                    }
                } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($product) }
            }
        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($products) }
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) }
}
function Assert-InstalledVersion([string]$Version, [string]$ProductCode) {
    $observed = @(Get-UserProducts)
    $products = @($observed | Where-Object { $_.ProductName -eq 'Abstraction' -or $_.ProductCode -eq $ProductCode })
    if ($products.Count -ne 1 -or $products[0].VersionString -ne $Version -or $products[0].ProductCode -ne $ProductCode -or
        $products[0].ProductName -ne 'Abstraction' -or $products[0].State -ne '5' -or $products[0].Context -ne 2 -or
        $products[0].UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw "Expected installed per-user product $ProductCode version $Version; observed: $($observed | ConvertTo-Json -Depth 3 -Compress)"
    }
}
function Assert-RetainedSentinel([string]$Path, [string]$Value) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or [IO.File]::ReadAllText($Path) -ne $Value) { throw 'User-data sentinel changed or disappeared' }
}
function Assert-RemovedRegistration {
    $products = @(Get-UserProducts | Where-Object { $_.ProductName -eq 'Abstraction' })
    if ($products.Count) {
        throw "Per-user product registration survived removal: $($products | ConvertTo-Json -Depth 3 -Compress)"
    }
}
function Start-PredecessorSupervisor([string]$Tools) {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path (Get-ProfileFolder Startup) 'Abstraction supervisor.lnk'))
    try {
        $targets = @('jobd.exe','jobdw.exe' | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $Tools $_)) })
        if ($shortcut.TargetPath -notin $targets -or $shortcut.Arguments -notin @('start','start --runtime') -or
            $shortcut.WorkingDirectory.TrimEnd([char[]]'\/') -ne $Tools.TrimEnd([char[]]'\/')) {
            throw 'Predecessor shortcut does not select its installed supervisor'
        }
        Push-Location $Tools
        try { Invoke-Bounded $shortcut.TargetPath @($shortcut.Arguments) 30 } finally { Pop-Location }
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
}
function Get-RunningFixtureProcesses([string]$Tools, [string]$Sid) {
    $retained = @()
    try {
        foreach ($candidate in @(Get-FixtureProcessCandidates)) {
            $owner = Get-FixtureProcessOwner $candidate
            if ($null -eq $owner -or $owner -ne $Sid) { continue }
            try { $process = [Diagnostics.Process]::GetProcessById($candidate.ProcessId) }
            catch {
                # Exited after its owner was read; a gone process is not captured.
                if (Test-FixtureProcessGone $candidate $null) { continue }
                throw
            }
            try {
                # Force a retained process handle before replacement; a later PID lookup is insufficient.
                $null = $process.Handle
                if ($process.HasExited -or $process.MainModule.FileName -ne (Join-Path $Tools $candidate.Name) -or
                    [Math]::Abs(($process.StartTime.ToUniversalTime() - $candidate.CreationDate.ToUniversalTime()).TotalMilliseconds) -ge 1) {
                    throw 'Fixture process identity changed during capture'
                }
                $retained += $process
            } catch { $process.Dispose(); throw }
        }
        if (-not @($retained | Where-Object { $_.ProcessName -in @('jobd','jobdw') }).Count) {
            throw 'Upgrade requires a live installed predecessor supervisor'
        }
        return $retained
    } catch { foreach ($process in $retained) { $process.Dispose() }; throw }
}
function Assert-PreviousProcessesExited($Processes) {
    foreach ($process in $Processes) {
        if (-not $process.WaitForExit(0)) { throw 'Package replacement left a previous installed process running' }
    }
}
function Assert-SameVersionReinstall([string]$Package, [string]$Version, [string]$ProductCode, [string]$Central, [string]$Sentinel, [string]$Value) {
    Invoke-Bounded msiexec.exe @('/i',"`"$Package`"",'/qn','/norestart','ALLUSERS=2','MSIINSTALLPERUSER=1','REINSTALL=ALL','REINSTALLMODE=vomus','/l*v','user-reinstall.log')
    Assert-InstalledVersion $Version $ProductCode
    Assert-RuntimeReady $Central reinstall-status
    Assert-RetainedSentinel $Sentinel $Value
}
function Invoke-CheckedTool([string]$Image, [string[]]$Arguments) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Image; $info.Arguments=$Arguments -join ' '
    $result=Invoke-FixtureProcess $info 60
    $result.Diagnostics | Write-Host
    if ($result.ExitCode -ne 0) { throw "Tool exited $($result.ExitCode): $Image" }
    return ($result.Output -split '\r?\n')
}
function Assert-InstalledUserTools([string]$Tools) {
$dir = Split-Path -Parent $tools
if (-not (Test-Path $tools)) { throw "a per-user install did not land in $tools" }
foreach ($f in 'jobd.exe','jobdw.exe','dl.exe','jobctl.exe','openabstractions.exe','Abstraction Panel.exe') {
  if (-not (Test-Path (Join-Path $tools $f))) { throw "$f was not installed" }
}
$path = (Get-ItemProperty 'HKCU:\Environment' -Name Path -ErrorAction Stop).Path
if ($path -notlike "*$tools*") { throw "the user PATH does not carry $tools" }

# What this scope promises instead of a service, in the words the
# feature text uses: a Startup shortcut, and nothing that replaces the
# supervisor if it dies before the next sign-in.
$lnk = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\Abstraction supervisor.lnk'
if (-not (Test-Path $lnk)) { throw 'the Startup shortcut is what a per-user install gets instead of a service, and it is not there' }
if ((Get-ItemProperty 'HKCU:\Software\OpenAbstractions\Abstraction\Supervisor' -Name atLogon).atLogon -ne 1) {
  throw 'the per-user supervisor marker is not set'
}

# And what it must not have done. Every one of these is a machine-scope
# act, and an install that had no administrator token and did them
# anyway would have done them badly.
if (Test-Path 'HKLM:\Software\OpenAbstractions') { throw 'a per-user install wrote the machine registry key' }
if (Test-Path (Join-Path $env:ProgramData 'abstraction')) { throw 'a per-user install created the machine config folder it cannot protect' }
& sc.exe qc OpenAbstractionsSupervisor | Out-Null
if ($LASTEXITCODE -eq 0) { throw 'a per-user install registered a service. It has no administrator token, so whatever it registered, it registered wrong.' }
if ($LASTEXITCODE -ne 1060) { throw "sc qc could not establish service absence: exit $LASTEXITCODE" }
foreach ($t in 'jobd','jobd-logon') {
  if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
    throw "a scheduled task named $t exists. This package registered one until it was replaced by the service and the Startup shortcut; a task coming back is that mechanism returning unannounced."
  }
}
'ok    programs, a user PATH entry, a Startup shortcut — and no service, no machine key, no task'
}
function Assert-ToolStoreCompatibility([string]$Tools, [string]$PythonPath) {
$work = Join-Path (Get-Location) 'agree'
$oldStore=$env:ABSTRACTION_STORE; $oldJobStore=$env:JOB_STORE
New-Item -ItemType Directory -Force -Path "$work\serve","$work\out","$work\store" | Out-Null
$env:ABSTRACTION_STORE = "$work\store"
Set-Content "$work\serve\thing.bin" 'three modules, one store format'
$srv = Start-Process -FilePath $PythonPath -WindowStyle Hidden -PassThru -RedirectStandardOutput agree-server.log -RedirectStandardError agree-server.err -WorkingDirectory "$work\serve" -ArgumentList '-m','http.server','8099','--bind','127.0.0.1'
try {
    # Bound HTTP readiness independently of each tool's process deadline.
    $ready=$false
    $readyUntil=[DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $readyUntil) {
      try { Invoke-WebRequest 'http://127.0.0.1:8099/thing.bin' -UseBasicParsing -TimeoutSec 1 | Out-Null; $ready=$true; break }
      catch { Start-Sleep -Milliseconds 200 }
    }
    if (-not $ready) { throw 'Isolated HTTP source did not become ready' }
    $fetched = Invoke-CheckedTool "$tools\dl.exe" @('http://127.0.0.1:8099/thing.bin','-o',"`"$work\out`"")
    $fetched

    if (-not (Test-Path "$work\out\thing.bin")) { throw 'dl reported success and delivered nothing' }
    $named = $fetched | Select-String -Pattern '^\s*job\s+(\S+)'
    if (-not $named) { throw 'dl did not name the job it created' }
    $id = $named.Matches[0].Groups[1].Value

    $seen = Invoke-CheckedTool "$tools\jobd.exe" @('status')
    $seen
    if (-not ($seen | Select-String -SimpleMatch 'thing.bin')) {
      throw 'jobd could not see the download dl completed in the store they share'
    }

    $env:JOB_STORE = "$work\store"
    $shown = Invoke-CheckedTool "$tools\jobctl.exe" @('show',$id)

    if (-not ($shown | Select-String -SimpleMatch $id)) {
      throw 'jobctl read the store and did not find the record dl wrote there'
    }

    Remove-Item Env:JOB_STORE
    $without = Invoke-CheckedTool "$tools\jobctl.exe" @('show',$id)
    if (-not ($without | Select-String -SimpleMatch $id)) {
      throw 'jobctl exited 0 without JOB_STORE and did not find the record dl wrote'
    }
} finally {
    $env:ABSTRACTION_STORE=$oldStore; $env:JOB_STORE=$oldJobStore
    if (-not $srv.HasExited) { $srv.Kill() }
    if (-not $srv.WaitForExit(5000)) { throw 'HTTP fixture process termination was not observed' }
    $srv.Dispose()
}
    'Cross-tool store compatibility passed' | Set-Content tool-compatibility.txt
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
    $predecessorAttempted = $false
    $previousProcesses = @()
    $sentinel = $null
    try {
        if ($PredecessorMsiPath) {
            Assert-PackageHash $PredecessorMsiPath $PredecessorSHA256
            if ($ExpectedVersion -notmatch '^\d+\.\d+\.\d+$' -or [version]$ExpectedVersion -le [version]'0.1.5') { throw 'Upgrade requires an explicit candidate version newer than 0.1.5' }
            if ((Get-PackageProperty $PredecessorMsiPath ProductVersion) -ne '0.1.5' -or (Get-PackageProperty $MsiPath ProductVersion) -ne $ExpectedVersion) { throw 'Unexpected predecessor or candidate MSI version' }
            if ((Get-PackageProperty $PredecessorMsiPath UpgradeCode) -ne (Get-PackageProperty $MsiPath UpgradeCode)) { throw 'Packages do not share the product upgrade identity' }
            $productCode = Get-PackageProperty $MsiPath ProductCode
            $sentinel = Join-Path (Get-ProfileFolder LocalApplicationData) 'openabstractions\runtime-v1\qualification-sentinel.txt'
            $sentinelValue = [Guid]::NewGuid().ToString('N')
            New-Item -ItemType Directory -Force (Split-Path -Parent $sentinel) | Out-Null
            [IO.File]::WriteAllText($sentinel, $sentinelValue)
            $predecessorAttempted = $true
            Invoke-Bounded msiexec.exe @('/i',"`"$PredecessorMsiPath`"",'/qn','/norestart','ALLUSERS=2','MSIINSTALLPERUSER=1','/l*v','predecessor-install.log')
            Assert-InstalledVersion '0.1.5' (Get-PackageProperty $PredecessorMsiPath ProductCode)
            Assert-RetainedSentinel $sentinel $sentinelValue
            # 0.1.5 start opens its log before creating the store. Initialize through its own CLI.
            Invoke-Bounded (Join-Path $tools 'jobd.exe') @('status')
            Start-PredecessorSupervisor $tools
            $previousProcesses = @(Get-RunningFixtureProcesses $tools $ExpectedSid)
        }
        $installAttempted = $true
        Invoke-InstallWithDiagnostics {
            Invoke-Bounded msiexec.exe @('/i', "`"$MsiPath`"", '/qn', '/norestart', 'ALLUSERS=2', 'MSIINSTALLPERUSER=1', '/l*v', 'user-install.log')
        } { Save-ActivationFailure $tools }
        $installed = $true
        if ($PredecessorMsiPath) { Assert-PreviousProcessesExited $previousProcesses }
        if ($CheckTools) { Assert-InstalledUserTools $tools; Assert-ToolStoreCompatibility $tools $PythonPath }
        $central = Join-Path $tools 'openabstractions.exe'
        Assert-RuntimeReady $central post-install-status
        if ($PredecessorMsiPath) {
            Assert-InstalledVersion $ExpectedVersion $productCode
            Assert-RetainedSentinel $sentinel $sentinelValue
            Assert-SameVersionReinstall $MsiPath $ExpectedVersion $productCode $central $sentinel $sentinelValue
            'Predecessor upgrade and same-version reinstall passed' | Set-Content upgrade.txt
        }
        'ok: logging/config ready immediately after MSI completion' | Set-Content 'post-install-activation.txt'
        $shortcutPath = Join-Path (Get-ProfileFolder Startup) 'Abstraction supervisor.lnk'
        if (@(Get-Service | Where-Object { $_.Name -like 'OpenAbstractionsSupervisor*' }).Count) { throw 'Per-user install registered a service' }
        if (-not (Test-Path -LiteralPath $shortcutPath)) { throw 'Installed Startup shortcut missing' }
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        Assert-InstalledShortcut $shortcut $tools
        Push-Location $shortcut.WorkingDirectory
        try { Invoke-Bounded $shortcut.TargetPath @($shortcut.Arguments) 30 } finally { Pop-Location }
        Assert-RuntimeReady $central runtime-status
        'ok: installed shortcut invocation resolved logging/config as a non-admin account' | Set-Content 'activation.txt'
        # The state Restart Manager is about to see, for comparison with a removal failure.
        try { Save-RuntimeSnapshot 'pre-uninstall-snapshot.json' $ExpectedSid 'before-uninstall' (Split-Path -Parent $tools) }
        catch { Write-Warning ('Pre-uninstall diagnostics failed: ' + (Protect-DiagnosticText $_.Exception.Message)) }
        Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'user-uninstall.log')
        $installed = $false
        $installAttempted = $false
        # These assertions precede outer fixture cleanup and its process termination.
        Assert-NoRuntime $ExpectedSid 'removal-remaining.json' (Split-Path -Parent $tools)
        if ($sentinel) { Assert-RetainedSentinel $sentinel $sentinelValue; Assert-RemovedRegistration }
        if ($CheckTools) {
            if (Test-Path (Split-Path -Parent $tools)) { throw 'Install folder survived removal' }
            if (Test-Path 'HKCU:\Software\OpenAbstractions') { throw 'User registry key survived removal' }
            $userPath = (Get-ItemProperty 'HKCU:\Environment' -Name Path -ErrorAction SilentlyContinue).Path
            if ($userPath -like '*Programs\OpenAbstractions*') { throw 'User PATH entry survived removal' }
        }
        if (Test-Path -LiteralPath $shortcutPath) { throw 'Startup shortcut survived uninstall' }
        foreach ($name in @('jobdw.exe','openabstractions.exe')) {
            if (Test-Path -LiteralPath (Join-Path $tools $name)) { throw "Installed $name survived uninstall" }
        }
        'ok: uninstall removed processes, endpoints, shortcut and runtime binaries before fixture cleanup' | Set-Content 'removal.txt'
    } finally {
        foreach ($process in $previousProcesses) { $process.Dispose() }
        if ($installed -or $installAttempted) {
            # A post-InstallFinalize activation error can leave committed files.
            try { Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'user-cleanup-uninstall.log') } catch { Write-Warning $_ }
        }
        if ($predecessorAttempted) {
            $oldCode = Get-PackageProperty $PredecessorMsiPath ProductCode
            if (@(Get-UserProducts | Where-Object { $_.ProductCode -eq $oldCode }).Count) {
                try { Invoke-Bounded msiexec.exe @('/x',"`"$PredecessorMsiPath`"",'/qn','/norestart','/l*v','predecessor-cleanup.log') } catch { Write-Warning $_ }
            }
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
    if ($PredecessorMsiPath) {
        $PredecessorMsiPath = (Resolve-Path -LiteralPath $PredecessorMsiPath).Path
        Assert-PackageHash $PredecessorMsiPath $PredecessorSHA256
        Copy-Item -LiteralPath $PredecessorMsiPath -Destination (Join-Path $directory 'predecessor.msi')
    }
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
    if ($PredecessorMsiPath) { $arguments += @('-PredecessorMsiPath',"`"$directory\predecessor.msi`"",'-PredecessorSHA256',$PredecessorSHA256,'-ExpectedVersion',$ExpectedVersion) }
    if ($CheckTools) {
        if (-not $PythonPath -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw 'Release tools check requires an explicit existing Python executable' }
        $arguments += @('-CheckTools','-PythonPath',"`"$PythonPath`"")
    }
    $childInfo = New-Object Diagnostics.ProcessStartInfo
    $childInfo.FileName = 'powershell.exe'
    $childInfo.Arguments = $arguments -join ' '
    $childInfo.WorkingDirectory = $directory
    $childInfo.UserName = $user
    $childInfo.Domain = $env:COMPUTERNAME
    $childInfo.Password = $credential.Password
    $childInfo.LoadUserProfile = $true
    $child = Invoke-FixtureProcess $childInfo $(if ($PredecessorMsiPath) { 600 } else { 300 })
    $child.Output | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.log')
    $child.Diagnostics | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.err')
    if ($child.ExitCode -ne 0) { throw "Per-user fixture exited $($child.ExitCode); inspect diagnostics" }
    New-Item -ItemType Directory -Force -Path $ResultDirectory | Out-Null
    Assert-NoRuntime $account.SID.Value (Join-Path $ResultDirectory 'account-removal-remaining.json')
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
        foreach ($process in @(Get-FixtureProcessCandidates)) {
            $owner = Get-FixtureProcessOwner $process
            if ($null -ne $owner -and $owner -eq $account.SID.Value) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-LocalUser -Name $user
    }
    # Retain the fixture directory for runner disposal; never recursively delete
    # a path writable by the test account, which could contain reparse points.
}
