param(
    [ValidateSet('ValidateOnly','Verify','User','FailingCandidate','CheckLogs','LocalAccount')][string]$Mode = 'ValidateOnly',
    [switch]$Help,
    [string]$MsiPath,
    [string]$ExpectedSid,
    [switch]$CheckTools,
    [switch]$Unscoped,
    [switch]$PredecessorElsewhere,
    [switch]$FailUpgrade,
    [switch]$FailSameVersion,
    [switch]$NewProductCode,
    [string]$Output,
    [string]$PythonPath,
    [string]$PredecessorMsiPath,
    [string]$PredecessorSHA256,
    [string]$PredecessorVersion,
    [string]$ExpectedVersion,
    [string]$ResultDirectory = (Join-Path (Get-Location) 'user-runtime-diagnostics'),
    # CheckLogs: verbose MSI logs a finished run collected, separated by '|'.
    [string]$UpgradeLogs,
    [string]$RemovalLogs
)
$ErrorActionPreference = 'Stop'
if ($Help) {
    @'
test_user_runtime.ps1 -Mode MODE [options]

Per-user Windows installer qualification.

Modes
  ValidateOnly      parse the fixture and change nothing (default)
  CheckLogs         check collected MSI logs: -UpgradeLogs a|b -RemovalLogs c|d
  FailingCandidate  write a copy of -MsiPath that fails after its files: -Output PATH [-NewProductCode]
  Verify            hosted runner only: create a disposable standard account and run User in it
  User              the per-user cases inside that account (started by Verify or LocalAccount)
  LocalAccount      the User cases on the invoking account, for a local qualification. It refuses
                    an elevated token, refuses when any OpenAbstractions product, service, folder,
                    shortcut, registry key, runtime process or upgrade exclusion is present, never
                    elevates, and removes what it installed. Unscoped is refused because an
                    unscoped install may ask for elevation.

Case options (Verify and LocalAccount)
  -MsiPath PATH  -CheckTools -PythonPath PATH  -Unscoped (Verify only)
  -PredecessorMsiPath PATH -PredecessorSHA256 HEX -PredecessorVersion X.Y.Z -ExpectedVersion X.Y.Z
  -PredecessorElsewhere  -FailUpgrade  -FailSameVersion
  -ResultDirectory DIR   logs and evidence (default .\user-runtime-diagnostics)
'@
    exit 0
}
# Bounded processes, the disposable account, runtime process and pipe queries,
# product enumeration and diagnostic redaction. The parent copies the module
# beside the account's copy of this fixture.
Import-Module (Join-Path $PSScriptRoot 'OAFixture.psm1') -Force
if ($Mode -eq 'ValidateOnly') {
    'Per-user fixture parsed; no accounts, processes, installations or registrations changed.'
    exit 0
}
# CheckLogs only reads log files, so it runs anywhere. LocalAccount checks the
# invoking account itself and starts User with the account's SID as its marker.
$localAccountChild = $Mode -eq 'User' -and $env:OA_FIXTURE_LOCAL_ACCOUNT -and
    $env:OA_FIXTURE_LOCAL_ACCOUNT -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($Mode -notin @('CheckLogs','LocalAccount') -and -not $localAccountChild -and ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted')) {
    throw 'This mutating fixture requires a disposable GitHub-hosted runner.'
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
# Removal leaves no account runtime process and no runtime capability pipe. At
# the deadline a snapshot names what remained; its failure never changes the verdict.
function Assert-RuntimeRemoved([string]$Sid, [string]$DiagnosticPath, [string]$Folder, [int]$Seconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $remaining = @(Get-RuntimeProcesses $Sid)
        $pipes = @(Get-CapabilityPipes $Sid -Runtime)
        if ($remaining.Count -eq 0 -and $pipes.Count -eq 0) { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($DiagnosticPath) {
        try { Save-RuntimeSnapshot $DiagnosticPath $Sid 'removal-deadline' $Folder }
        catch { Write-Warning ('Removal diagnostics failed: ' + (Protect-DiagnosticText $_.Exception.Message)) }
    }
    throw 'Uninstall left account runtime processes or capability endpoints'
}
function Get-AccountProcessDetails([string]$Sid) {
    foreach ($process in @(Get-RuntimeProcesses $Sid)) {
        $parent = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([uint32]$process.ParentProcessId)" | Select-Object -First 1)
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
    try { $snapshot.pipes = @(Get-CapabilityPipes $Sid -Runtime) } catch { $snapshot.pipeError = Protect-DiagnosticText $_.Exception.Message }
    if ($Folder) {
        try { $snapshot.restartManager = Get-RestartManagerView $Folder } catch { $snapshot.restartManagerError = Protect-DiagnosticText $_.Exception.Message }
    }
    $snapshot | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Assert-InstalledShortcut($Shortcut, [string]$Tools) {
    $expectedTarget = [IO.Path]::GetFullPath((Join-Path $Tools 'openabstractionsw.exe'))
    $expectedDirectory = [IO.Path]::GetFullPath($Tools).TrimEnd([char[]]'\/')
    $actualTarget = if ($Shortcut.TargetPath) { [IO.Path]::GetFullPath($Shortcut.TargetPath) } else { '' }
    $actualDirectory = if ($Shortcut.WorkingDirectory) { [IO.Path]::GetFullPath($Shortcut.WorkingDirectory).TrimEnd([char[]]'\/') } else { '' }
    if ($actualTarget -ne $expectedTarget -or $Shortcut.Arguments -ne 'serve host' -or $actualDirectory -ne $expectedDirectory) {
        throw 'Installed shortcut target, host arguments or working directory differ'
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
    if ($null -eq $status -or $status -is [array] -or $status -isnot [Management.Automation.PSCustomObject]) {
        throw 'Runtime status report is malformed: expected an object'
    }
    foreach ($contract in @('abstraction.logging/sink@1','abstraction.config/reader@1','abstraction.config/editor@1','abstraction.job/acceptance@1','abstraction.job/operations@1')) {
        $capability = $contract.Split('/')[0]
        $matches = @($status.capabilities | Where-Object { $_.capability -eq $capability -and $_.contract -eq $contract })
        if ($matches.Count -ne 1 -or $matches[0].status -ne 'resolved') {
            throw "Expected exactly one ready contract: $contract"
        }
    }
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
    $image = Join-Path $Tools 'openabstractions.exe'
    if (-not (Test-Path -LiteralPath $image -PathType Leaf)) {
        'Installed openabstractions unavailable for diagnostic retry' | Set-Content 'activation-diagnostic-retry.txt'
        return
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    # The console link of the installer's activation, so its output is captured.
    $info.FileName = $image
    $info.Arguments = 'start --require-unelevated'
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
function Assert-InstalledVersion([string]$Version, [string]$ProductCode) {
    # MSIINSTALLCONTEXT_USERUNMANAGED for the invoking fresh user only.
    $observed = @(Get-InstalledProducts)
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
    $products = @(Get-InstalledProducts | Where-Object { $_.ProductName -eq 'Abstraction' })
    if ($products.Count) {
        throw "Per-user product registration survived removal: $($products | ConvertTo-Json -Depth 3 -Compress)"
    }
}
# The predecessor's Startup shortcut, as that version authored it, and the
# process that supervises its runtime. Through 0.1.5 jobd ran `start`; 0.1.6 and
# 0.1.7 run the windowless jobdw `start --runtime`; from 0.1.8 the shortcut runs
# the windowless host `openabstractionsw serve host`, which does not exit, so
# the fixture activates it with the idempotent `start`. The rule reads the
# version it was given, so moving the qualification's predecessor forward
# changes nothing here.
function Get-PredecessorActivation([string]$Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "A predecessor version is required to select its activation arguments: '$Version'" }
    if ([version]$Version -le [version]'0.1.5') {
        return [pscustomobject]@{ Images = @('jobd.exe','jobdw.exe'); Arguments = 'start'; Start = 'start'; Supervisor = @('jobd','jobdw') }
    }
    if ([version]$Version -le [version]'0.1.7') {
        return [pscustomobject]@{ Images = @('jobdw.exe'); Arguments = 'start --runtime'; Start = 'start --runtime'; Supervisor = @('jobdw') }
    }
    return [pscustomobject]@{ Images = @('openabstractionsw.exe'); Arguments = 'serve host'; Start = 'start'; Supervisor = @('openabstractionsw') }
}
function Start-PredecessorSupervisor([string]$Tools, [string]$Version) {
    $expected = Get-PredecessorActivation $Version
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path (Get-ProfileFolder Startup) 'Abstraction supervisor.lnk'))
    try {
        $targets = @($expected.Images | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $Tools $_)) })
        if ($shortcut.TargetPath -notin $targets -or $shortcut.Arguments -ne $expected.Arguments -or
            $shortcut.WorkingDirectory.TrimEnd([char[]]'\/') -ne $Tools.TrimEnd([char[]]'\/')) {
            throw "Predecessor $Version shortcut does not select its installed supervisor with '$($expected.Arguments)'"
        }
        Push-Location $Tools
        try { Invoke-Bounded $shortcut.TargetPath @($expected.Start) 30 } finally { Pop-Location }
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
}
function Get-RunningFixtureProcesses([string]$Tools, [string]$Sid, [string[]]$Supervisor = @('jobd','jobdw','openabstractionsw')) {
    $retained = @()
    try {
        foreach ($candidate in @(Get-RuntimeProcesses $Sid)) {
            try { $process = [Diagnostics.Process]::GetProcessById($candidate.ProcessId) }
            catch {
                # Exited after its owner was read; a gone process is not captured.
                if (Test-ProcessGone $candidate $null) { continue }
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
        if (-not @($retained | Where-Object { $_.ProcessName -in $Supervisor }).Count) {
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
# The hosted proof for an upgrade: the package stopped nothing, the upgrade
# exclusion (Begin) and its commit release (End) executed from the early script
# before any file was replaced, Begin carried a resolved absolute folder and the
# related ProductCodes, and the predecessor was removed only after this
# installation committed. Mirrors check() in installer/test_upgrade_log.py,
# which the redist fixture does not carry; test_user_runtime.py holds both to
# the same accepted and refused logs.
function Assert-UpgradeExclusionLog([string]$Text, [string]$Action = 'BeginUserUpgradeExclusion') {
    # The predecessor's own uninstall is logged after RemoveExistingProducts
    # starts; a 0.1.7 predecessor skips its own stop actions there.
    $own = [regex]::Match($Text, 'Action start [^\r\n]*: RemoveExistingProducts\.')
    $transaction = if ($own.Success) { $Text.Substring(0, $own.Index) } else { $Text }
    foreach ($stop in 'StopPreviousSupervisor','StopPreviousUserSupervisor') {
        if ([regex]::IsMatch($transaction, "\b$stop\b")) { throw "$stop appears in the log; the package stops nothing" }
    }
    $user = $Action -ceq 'BeginUserUpgradeExclusion'
    $scope = if ($user) { 'user' } else { 'machine' }
    $release = if ($user) { 'EndUserUpgradeExclusion' } else { 'EndMachineUpgradeExclusion' }
    $files = [regex]::Match($Text, 'Action start [^\r\n]*: InstallFiles\.')
    if (-not $files.Success) { throw "upgrade never replaced the predecessor's files" }
    $before = $Text.Substring(0, $files.Index)
    $begun = [regex]::Match($before, "Action ended [^\r\n]*: $([regex]::Escape($Action))\. Return value 1\.")
    if (-not $begun.Success) { throw "upgrade exclusion $Action was not scheduled successfully before the new files" }
    $after = $before.Substring($begun.Index + $begun.Length)
    $flush = [regex]::Match($after, 'Action ended [^\r\n]*: InstallExecute\. Return value 1\.')
    if (-not $flush.Success) { throw "the exclusion's execution script was not flushed before the new files" }
    $script = $after.Substring(0, $flush.Index)
    $op = [regex]::Match($script, "Executing op: CustomActionSchedule\(Action=$([regex]::Escape($Action)),ActionType=(\d+),Source=[^,\r\n]*,Target=([^\r\n]*),\)")
    if (-not $op.Success) { throw "$Action was not executed from the early script" }
    if ((([int64]$op.Groups[1].Value -band 2048) -eq 0) -ne $user) { throw "$Action executed with the wrong token" }
    $guid = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
    if (-not [regex]::IsMatch($op.Groups[2].Value, "^service begin-upgrade --$scope `"[A-Za-z]:\\[^`"\[\]]+\\\.`" --related `"$guid(?:;$guid)*`"\z")) {
        throw "$Action target was not a resolved install folder and related product list: $($op.Groups[2].Value)"
    }
    $end = [regex]::Match($script.Substring($op.Index + $op.Length), "Executing op: CustomActionSchedule\(Action=$release,ActionType=(\d+),Source=[^,\r\n]*,Target=([^\r\n]*),\)")
    if (-not $end.Success) { throw "$release was not registered for commit after $Action" }
    $kind = [int64]$end.Groups[1].Value
    if (-not ($kind -band 512) -or ((($kind -band 2048) -eq 0) -ne $user) -or $end.Groups[2].Value -cne "service end-upgrade --$scope") {
        throw "$release is not the commit release of the $Action record: $($end.Value)"
    }
    $removal = [regex]::Match($Text, 'Action start [^\r\n]*: RemoveExistingProducts\.')
    if (-not $removal.Success) { throw 'upgrade never removed the predecessor' }
    if (-not [regex]::IsMatch($Text.Substring(0, $removal.Index), 'Action ended [^\r\n]*: InstallFinalize\. Return value 1\.')) {
        throw 'the predecessor was removed before this installation committed'
    }
}
# A quiet removal with /norestart exits 0 even when Restart Manager found a
# critical application holding the product's files: Windows Installer moves the
# files aside, schedules their deletion for the next reboot and reports
# "Removal success or error status: 0" (hosted run 34906434707). Only the log
# records that state. Returns the Restart Manager verdict of a clean removal.
# Mirrors check() in installer/test_removal_log.py; test_user_runtime.py holds
# both to the same accepted and refused logs.
function Assert-RemovalLog([string]$Text) {
    $refusals = @(
        @('RESTART MANAGER: [^\r\n]*critical application[^\r\n]*', "Restart Manager found a critical application holding the product's files"),
        @('RESTART MANAGER: [^\r\n]*reboot will be (?:necessary|required)[^\r\n]*', 'Restart Manager decided a reboot is required'),
        @('Info 1903\.[^\r\n]*', 'Windows Installer scheduled a file operation for the next reboot'),
        @('RESTART MANAGER: Failed to shut down[^\r\n]*', 'Restart Manager could not shut down every application that held files in use'),
        @('Windows Installer requires a system restart[^\r\n]*', 'Windows Installer recorded that a system restart is required'),
        @('Property\([SC]\): ReplacedInUseFiles = [^\r\n]+', 'Windows Installer replaced files that were in use'),
        @('MainEngineThread is returning (?:3010|1641)\b[^\r\n]*', 'Windows Installer returned a reboot status')
    )
    foreach ($refusal in $refusals) {
        $found = [regex]::Match($Text, $refusal[0])
        if ($found.Success) { throw "$($refusal[1]): $($found.Value.Trim())" }
    }
    if (-not [regex]::IsMatch($Text, 'Removal success or error status: 0\.')) { throw 'the log does not record a completed removal' }
    if ([regex]::IsMatch($Text, 'RESTART MANAGER: Successfully shut down all applications')) {
        return 'Restart Manager shut down every application that held files in use'
    }
    return "no application held the product's files"
}
# The removal verdict reads the removal's own log before the process deadline,
# so a removal Windows Installer could not finish without a reboot fails with
# that cause. A snapshot records what still holds the files.
function Assert-HonestRemoval([string]$Log, [string]$Sid, [string]$Folder, [string]$Snapshot) {
    try { return Assert-RemovalLog ([IO.File]::ReadAllText((Join-Path (Get-Location) $Log))) }
    catch {
        $cause = $_.Exception.Message
        try { Save-RuntimeSnapshot $Snapshot $Sid 'removal-restart-manager' $Folder }
        catch { Write-Warning ('Removal diagnostics failed: ' + (Protect-DiagnosticText $_.Exception.Message)) }
        throw "msiexec reported a successful removal, but ${Log} shows it is incomplete until a reboot: $cause"
    }
}
# Negative controls for a real log: each copy breaks one property the check
# proves, and the check must refuse every copy. A mutation that matches nothing
# leaves the accepted text, which the check accepts, so it cannot pass silently.
function Get-UpgradeLogMutations([string]$Text) {
    [ordered]@{
        'unformatted install folder' = [regex]::Replace($Text, '(CustomActionSchedule\(Action=BeginUserUpgradeExclusion,[^\r\n]*? --user )"[^"\r\n]*"', '$1"[APPLICATIONFOLDER]."')
        'exclusion script not flushed' = [regex]::Replace($Text, '(Action ended [^\r\n]*: InstallExecute\. Return value )1\.', '${1}3.')
        'predecessor removed before the commit' = "Action start 00:00:00: RemoveExistingProducts.`r`n" + $Text
        'a stop ran' = "Action ended 00:00:00: StopPreviousUserSupervisor. Return value 1.`r`n" + $Text
    }
}
function Get-RemovalLogMutations([string]$Text) {
    $completed = [regex]'[^\r\n]*Removal success or error status: 0\.'
    [ordered]@{
        'critical application' = $completed.Replace($Text, "MSI (s) (00:00) [00:00:00:000]: RESTART MANAGER: Did detect that a critical application holds file[s] in use, so a reboot will be necessary.`r`n`$0", 1)
        'reboot operation scheduled' = $completed.Replace($Text, "Info 1903.Scheduling reboot operation: Deleting file C:\Config.Msi\0.rbf. Must reboot to complete operation.`r`n`$0", 1)
        'removal failed' = ([regex]'(Removal success or error status: )0\.').Replace($Text, '${1}1603.', 1)
    }
}
function Invoke-MsiSql($Database, [string]$Sql) {
    $view = $Database.OpenView($Sql)
    try { [void]$view.Execute() } finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
}
function Get-MsiSequence($Database, [string]$Condition) {
    $view = $Database.OpenView("SELECT ``Action``, ``Sequence`` FROM ``InstallExecuteSequence`` WHERE $Condition")
    try {
        [void]$view.Execute()
        $record = $view.Fetch()
        if (-not $record) { return $null }
        return [pscustomobject]@{ Action = $record.StringData(1); Sequence = $record.IntegerData(2) }
    } finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
}
# A copy of the candidate that fails after the new files are written and before
# the predecessor is removed. The refusal is a deferred EXE from the package's
# own openabstractions Binary, taking the first free sequence after
# InstallFiles, because only a deferred action runs inside the script
# InstallFinalize executes: an immediate action there refuses before a single
# file operation has been applied, and the rollback it provokes has nothing to
# restore. `openabstractions service` with no known subcommand prints its usage
# and exits 2, which Windows Installer reports as 1722 and turns into 1603.
# RemoveExistingProducts follows InstallFinalize, so the failure precedes it and
# the predecessor is never touched. The copy gets its own package code; the
# source package is unchanged. -NewProductCode also gives the copy its own
# ProductCode, so the candidate itself can be its same-version predecessor.
function New-FailingCandidate([string]$Source, [string]$Target, [switch]$NewProductCode) {
    if (Test-Path -LiteralPath $Target) { throw "Forced-failure candidate already exists: $Target" }
    Copy-Item -LiteralPath $Source -Destination $Target
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Target, 1)
    try {
        $removal = Get-MsiSequence $database "``Action``='RemoveExistingProducts'"
        $files = Get-MsiSequence $database "``Action``='InstallFiles'"
        $finalize = Get-MsiSequence $database "``Action``='InstallFinalize'"
        if ($null -eq $removal -or $null -eq $files -or $null -eq $finalize -or
            -not ($files.Sequence + 1 -lt $finalize.Sequence -and $finalize.Sequence -lt $removal.Sequence)) {
            throw 'Candidate sequence does not place InstallFiles, then InstallFinalize, then RemoveExistingProducts'
        }
        $at = $files.Sequence + 1
        while ($at -lt $finalize.Sequence -and $null -ne (Get-MsiSequence $database "``Sequence``=$at")) { $at++ }
        if ($at -ge $finalize.Sequence) { throw "Candidate has no free sequence between InstallFiles ($($files.Sequence)) and InstallFinalize ($($finalize.Sequence))" }
        Invoke-MsiSql $database "INSERT INTO ``CustomAction`` (``Action``, ``Type``, ``Source``, ``Target``) VALUES ('ForcedUpgradeFailure', 1026, 'UpgradeSupervisorCode', 'service forced-qualification-failure')"
        Invoke-MsiSql $database "INSERT INTO ``InstallExecuteSequence`` (``Action``, ``Condition``, ``Sequence``) VALUES ('ForcedUpgradeFailure', 'NOT REMOVE', $at)"
        if ($NewProductCode) {
            $product = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'
            Invoke-MsiSql $database "UPDATE ``Property`` SET ``Value``='$product' WHERE ``Property``='ProductCode'"
        }
        $summary = $database.SummaryInformation(4)
        try {
            $code = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'
            [void]$summary.GetType().InvokeMember('Property', [Reflection.BindingFlags]::SetProperty, $null, $summary, @(9, $code))
            [void]$summary.Persist()
        } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) }
        [void]$database.Commit()
    } finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}
# A failed upgrade left the predecessor installed, registered, runnable and
# running. The failure happens after the new files are written and before
# RemoveExistingProducts, so the predecessor's product registration is never
# removed and never has to be written back by an unelevated rollback. The
# package stops nothing: Restart Manager ends the predecessor at InstallValidate,
# and the rollback activation `service start --related` releases the exclusion
# and runs the predecessor's own activation from its recorded folder, so its
# supervisor is running again before msiexec returns.
function Assert-RolledBackUpgrade([string]$LogText, [string]$PredecessorTools, [string]$Sid, [DateTime]$FailedAt,
                                  [string]$PredecessorCode, [string]$PredecessorVersion, [string]$Sentinel,
                                  [string]$Value, [int]$Seconds = 30) {
    $files = [regex]::Match($LogText, 'Action start [^\r\n]*: InstallFiles\.')
    if (-not $files.Success) { throw 'The failed upgrade never reached the file replacement it is meant to fail after' }
    $failure = [regex]::Match($LogText, 'Action start [^\r\n]*: ForcedUpgradeFailure\.')
    if (-not $failure.Success -or $failure.Index -lt $files.Index) { throw 'The forced failure did not follow the new files' }
    $removal = [regex]::Match($LogText, 'Action start [^\r\n]*: RemoveExistingProducts\.')
    if ($removal.Success) { throw 'The failed upgrade removed the predecessor; the removal must follow the commit it never reached' }
    if (-not @([regex]::Matches($LogText, 'RestartPreviousUserSupervisor') | Where-Object { $_.Index -gt $failure.Index }).Count) {
        throw 'Rollback did not run the per-user activation'
    }
    # State 5 for this account's SID: installed and registered, not the files-only
    # remains an in-transaction removal left behind.
    Assert-InstalledVersion $PredecessorVersion $PredecessorCode
    Assert-RetainedSentinel $Sentinel $Value
    Assert-NoUpgradeExclusion
    $activation = Get-PredecessorActivation $PredecessorVersion
    $images = @($activation.Images | ForEach-Object { Join-Path $PredecessorTools $_ } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if (-not $images.Count) { throw 'Rollback did not leave the predecessor supervisor in its folder' }
    if (-not (Test-Path -LiteralPath (Join-Path (Get-ProfileFolder Startup) 'Abstraction supervisor.lnk') -PathType Leaf)) {
        throw 'Rollback did not leave the Startup activation that restarts the predecessor at sign-in'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $running = @(Get-RuntimeProcesses $Sid | Where-Object {
            [string]$_.ExecutablePath -in $images -and ([DateTime]$_.CreationDate) -ge $FailedAt })
        if ($running.Count) { return }
        if ($Seconds -gt 0) { Start-Sleep -Milliseconds 250 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Rollback did not start the predecessor's supervisor ($($activation.Images -join ' or ')) again"
}
# The candidate as its own same-version predecessor, failing after its new files:
# Restart Manager restarts the host it shut down, because the host registered
# for restart and ran for at least 60 seconds, and the rollback activation is
# idempotent with that restart. A live host with a new PID serves the runtime.
function Assert-RestartedSameVersionHost([string]$LogText, [string]$Tools, [string]$Sid, [int]$PreviousHostPid, [int]$Seconds = 30) {
    $failure = [regex]::Match($LogText, 'Action start [^\r\n]*: ForcedUpgradeFailure\.')
    if (-not $failure.Success) { throw 'The same-version failure never ran its forced failure' }
    if (-not [regex]::IsMatch($LogText, 'RESTART MANAGER: Previously shut down applications have been restarted\.')) {
        throw 'Restart Manager did not report restarting the applications it shut down'
    }
    if ([regex]::IsMatch($LogText, 'Action start [^\r\n]*: RemoveExistingProducts\.')) { throw 'The failed same-version upgrade removed the installed candidate' }
    $image = Join-Path $Tools 'openabstractionsw.exe'
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $hosts = @(Get-RuntimeProcesses $Sid | Where-Object { [string]$_.ExecutablePath -eq $image })
        if ($hosts.Count -eq 1 -and [int]$hosts[0].ProcessId -ne $PreviousHostPid) { return [int]$hosts[0].ProcessId }
        if ($Seconds -gt 0) { Start-Sleep -Milliseconds 250 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Expected one live host with a new PID after the failed same-version upgrade; observed $($hosts.Count) host(s)"
}
# No upgrade exclusion outlives the installer transaction that wrote it: commit
# and rollback both release it.
function Assert-NoUpgradeExclusion {
    $record = Join-Path (Get-ProfileFolder LocalApplicationData) 'openabstractions\upgrade-v1\exclusion.json'
    if (Test-Path -LiteralPath $record) { throw "An upgrade exclusion record survived its installation: $record" }
}
# Unscoped passes neither ALLUSERS nor MSIINSTALLPERUSER; the package's own
# defaults choose the scope, exactly as `msiexec /i package.msi /qn` does.
function Get-CandidateInstallArguments([string]$Package, [bool]$Unscoped, [string]$Log = 'user-install.log') {
    if ($Unscoped) { return @('/i', "`"$Package`"", '/qn', '/norestart', '/l*v', 'unscoped.log') }
    return @('/i', "`"$Package`"", '/qn', '/norestart', 'ALLUSERS=2', 'MSIINSTALLPERUSER=1', '/l*v', $Log)
}
# An unscoped install chose one scope and did all of it: one per-user product
# registration for this account and nothing of the machine arm.
function Assert-SingleUserScope([string]$MachineFolder = (Join-Path $env:ProgramFiles 'OpenAbstractions'), [string]$MachineKey = 'HKLM:\Software\OpenAbstractions') {
    if (Test-Path -LiteralPath $MachineFolder) { throw "an unscoped install also created the machine folder $MachineFolder" }
    if (Test-Path -LiteralPath $MachineKey) { throw 'an unscoped install also wrote the machine registry key' }
    if (@(Get-Service | Where-Object { $_.Name -like 'OpenAbstractionsSupervisor*' }).Count) { throw 'an unscoped install also registered the machine supervisor service' }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $products = @(Get-InstalledProducts | Where-Object { $_.ProductName -eq 'Abstraction' })
    if ($products.Count -ne 1 -or $products[0].Context -ne 2 -or $products[0].UserSid -ne $sid -or $products[0].State -ne '5') {
        throw "an unscoped install did not register exactly one per-user product for this account; observed: $($products | ConvertTo-Json -Depth 3 -Compress)"
    }
    'ok    an unscoped install chose the per-user scope and nothing of the machine scope'
}
function Assert-InstalledUserTools([string]$Tools) {
$dir = Split-Path -Parent $tools
if (-not (Test-Path $tools)) { throw "a per-user install did not land in $tools" }
foreach ($f in 'openabstractions.exe','openabstractionsw.exe','Abstraction Panel.exe') {
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
# A download through the installed runtime, with no store named anywhere: the
# runtime fetches and verifies, the command copies the result out, jobs show and
# jobs list observe the operation this program submitted, an equal submission
# returns the original receipt (JOB-A2), and jobs result writes the file it is
# given.
function Assert-ServiceDownload([string]$Central, [string]$PythonPath) {
$work = Join-Path (Get-Location) 'service-download'
New-Item -ItemType Directory -Force -Path "$work\serve","$work\out","$work\out2" | Out-Null
Set-Content "$work\serve\thing.bin" 'bytes the runtime fetched and the command delivered'
$srv = Start-Process -FilePath $PythonPath -WindowStyle Hidden -PassThru -RedirectStandardOutput service-download-server.log -RedirectStandardError service-download-server.err -WorkingDirectory "$work\serve" -ArgumentList '-m','http.server','8099','--bind','127.0.0.1'
try {
    # Bound HTTP readiness independently of each command's process deadline.
    $ready=$false
    $readyUntil=[DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $readyUntil) {
      try { Invoke-WebRequest 'http://127.0.0.1:8099/thing.bin' -UseBasicParsing -TimeoutSec 1 | Out-Null; $ready=$true; break }
      catch { Start-Sleep -Milliseconds 200 }
    }
    if (-not $ready) { throw 'Isolated HTTP source did not become ready' }
    $first = (Invoke-CheckedTool $Central @('download','http://127.0.0.1:8099/thing.bin','--out',"`"$work\out`"",'--json','--timeout','60s')) -join "`n" | ConvertFrom-Json
    if ($first.snapshot.state -ne 'complete') { throw "download did not complete: $($first.snapshot.state)" }
    if ((Get-Content "$work\out\thing.bin" -Raw) -ne (Get-Content "$work\serve\thing.bin" -Raw)) { throw 'download delivered different bytes' }
    $id = $first.receipt.operation_id
    if (-not $id) { throw 'download did not name the operation it created' }

    $shown = (Invoke-CheckedTool $Central @('jobs','show',$id,'--json')) -join "`n" | ConvertFrom-Json
    if ($shown.snapshot.receipt.operation_id -ne $id -or $shown.snapshot.state -ne 'complete') { throw 'jobs show did not observe the completed operation' }

    $listed = (Invoke-CheckedTool $Central @('jobs','list','--json')) -join "`n" | ConvertFrom-Json
    if (-not ($listed.snapshots | Where-Object { $_.receipt.operation_id -eq $id })) { throw 'jobs list did not include the operation this program submitted' }

    $again = (Invoke-CheckedTool $Central @('download','http://127.0.0.1:8099/thing.bin','--out',"`"$work\out`"",'--json','--timeout','60s')) -join "`n" | ConvertFrom-Json
    if ($again.receipt.operation_id -ne $id) { throw 'an equal submission did not return the original receipt (JOB-A2)' }

    $copied = (Invoke-CheckedTool $Central @('jobs','result',$id,'--out',"`"$work\out2\thing.bin`"",'--json')) -join "`n" | ConvertFrom-Json
    if ($copied.out -notlike '*\out2\thing.bin') { throw "jobs result wrote somewhere other than the file it was given: $($copied.out)" }
    if ((Get-Content "$work\out2\thing.bin" -Raw) -ne (Get-Content "$work\serve\thing.bin" -Raw)) { throw 'jobs result delivered different bytes' }
} finally {
    if (-not $srv.HasExited) { $srv.Kill() }
    if (-not $srv.WaitForExit(5000)) { throw 'HTTP fixture process termination was not observed' }
    $srv.Dispose()
}
    'Service download passed' | Set-Content service-download.txt
}
# The candidate is installed and its host runs long enough for Restart Manager
# to restart it (60 seconds); then a same-version copy with its own ProductCode
# fails after its new files. The candidate stays installed, Restart Manager
# restarts its host, and the runtime is ready again. Ends with the candidate
# removed.
function Invoke-SameVersionFailure([string]$MsiPath, [string]$Tools, [string]$Sid) {
    $failingPackage = Join-Path (Split-Path -Parent $MsiPath) 'failing-same-version.msi'
    if (-not (Test-Path -LiteralPath $failingPackage -PathType Leaf)) { throw 'Same-version forced-failure candidate was not prepared' }
    Invoke-InstallWithDiagnostics {
        Invoke-Bounded msiexec.exe (Get-CandidateInstallArguments $MsiPath $false 'same-version-install.log')
    } { Save-ActivationFailure $Tools }
    $central = Join-Path $Tools 'openabstractions.exe'
    Assert-RuntimeReady $central same-version-before-status
    $hostImage = Join-Path $Tools 'openabstractionsw.exe'
    $hosts = @(Get-RuntimeProcesses $Sid | Where-Object { [string]$_.ExecutablePath -eq $hostImage })
    if ($hosts.Count -ne 1) { throw "Expected one installed host before the same-version failure; observed $($hosts.Count)" }
    $previousHost = $hosts[0]
    $ranFor = ([DateTime]::Now - [DateTime]$previousHost.CreationDate).TotalSeconds
    if ($ranFor -lt 65) { Start-Sleep -Seconds ([int][Math]::Ceiling(65 - $ranFor)) }
    $failure = ''
    # The copy carries the installed files byte for byte, and Windows Installer
    # skips an unversioned file whose hash matches: nothing is replaced, Restart
    # Manager shuts nothing down and there is no restart to observe (measured on
    # the owner's account, 2026-09-17). REINSTALLMODE=amus replaces every file,
    # as a rebuilt same-version package with different bytes does.
    try { Invoke-Bounded msiexec.exe ((Get-CandidateInstallArguments $failingPackage $false 'failed-same-version.log') + 'REINSTALLMODE=amus') 300 }
    catch { $failure = $_.Exception.Message }
    if ($failure -notmatch 'msiexec\.exe exited 1603') { throw "The same-version forced failure did not end with 1603: $failure" }
    $log = [IO.File]::ReadAllText((Join-Path (Get-Location) 'failed-same-version.log'))
    $newHost = Assert-RestartedSameVersionHost $log $Tools $Sid ([int]$previousHost.ProcessId)
    Assert-InstalledVersion (Get-PackageProperty $MsiPath ProductVersion) (Get-PackageProperty $MsiPath ProductCode)
    Assert-NoUpgradeExclusion
    Assert-RuntimeReady $central same-version-after-status
    "ok: the failed same-version upgrade kept the candidate installed; Restart Manager restarted its host (pid $($previousHost.ProcessId) -> $newHost)" | Set-Content 'failed-same-version.txt'
    Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'same-version-uninstall.log')
    $null = Assert-HonestRemoval 'same-version-uninstall.log' $Sid (Split-Path -Parent $Tools) 'same-version-removal-restart-manager.json'
    Assert-RuntimeRemoved $Sid 'same-version-removal-remaining.json' (Split-Path -Parent $Tools)
}
# Everything of an OpenAbstractions installation a local-account run could
# disturb, one line per item present: product registrations in this account and
# the machine, supervisor services, install folders, the Startup shortcut, the
# user registry key, this account's runtime processes and an upgrade exclusion.
function Get-OpenAbstractionsFootprint([string]$Sid, [string]$LocalAppData, [string]$ProgramFiles, [string]$Startup,
                                       [string]$RegistryKey = 'HKCU:\Software\OpenAbstractions') {
    $items = @()
    foreach ($product in @(Get-InstalledProducts -UserSid $Sid -Context 2) + @(Get-InstalledProducts -Context 4)) {
        if ($product.ProductName -eq 'Abstraction') { $items += "installed product $($product.ProductCode) $($product.VersionString) (context $($product.Context))" }
    }
    foreach ($service in @(Get-Service -Name 'OpenAbstractionsSupervisor*' -ErrorAction SilentlyContinue)) { $items += "service $($service.Name)" }
    foreach ($path in @((Join-Path $LocalAppData 'Programs\OpenAbstractions'), (Join-Path $ProgramFiles 'OpenAbstractions'),
                        (Join-Path $Startup 'Abstraction supervisor.lnk'), (Join-Path $LocalAppData 'openabstractions\upgrade-v1\exclusion.json'), $RegistryKey)) {
        if ($path -and (Test-Path -LiteralPath $path)) { $items += "path $path" }
    }
    foreach ($process in @(Get-RuntimeProcesses $Sid)) { $items += "runtime process $($process.Name) $($process.ProcessId)" }
    return ,$items
}
# A local-account run touches no existing installation.
function Assert-NoOpenAbstractions($Footprint, [string]$When = 'before the local-account run') {
    if (@($Footprint).Count) {
        throw "OpenAbstractions is present $When; the local-account fixture refuses to touch an existing installation: $(@($Footprint) -join '; ')"
    }
}
# A local-account run never elevates and refuses an elevated token.
function Assert-UnelevatedToken([scriptblock]$IsAdministrator = {
    (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}) {
    if (& $IsAdministrator) { throw 'The local-account fixture refuses an elevated token; run it from an unelevated shell' }
}
# The logs a hosted run collected, checked again outside the account that wrote
# them: every per-user upgrade log proves the exclusion order and a resolved
# folder, every removal log proves no reboot is pending, and mutated copies of
# each real log are refused.
if ($Mode -eq 'CheckLogs') {
    $logs = @(
        foreach ($path in @($UpgradeLogs -split '\|' | Where-Object { $_ })) { [pscustomobject]@{ Kind = 'upgrade'; Path = $path } }
        foreach ($path in @($RemovalLogs -split '\|' | Where-Object { $_ })) { [pscustomobject]@{ Kind = 'removal'; Path = $path } }
    )
    if (-not $logs.Count) { throw 'CheckLogs needs -UpgradeLogs or -RemovalLogs' }
    foreach ($log in $logs) {
        if (-not (Test-Path -LiteralPath $log.Path -PathType Leaf)) { throw "The $($log.Kind) log was not collected: $($log.Path)" }
        $text = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $log.Path).Path)
        if ($log.Kind -eq 'upgrade') {
            Assert-UpgradeExclusionLog $text
            "ok    $($log.Path): the upgrade exclusion and its commit release preceded the new files with a resolved folder, nothing was stopped, and the predecessor went after the commit"
            $mutations = Get-UpgradeLogMutations $text
        } else {
            "ok    $($log.Path): the removal completed with no reboot pending; $(Assert-RemovalLog $text)"
            $mutations = Get-RemovalLogMutations $text
        }
        foreach ($name in $mutations.Keys) {
            $refused = $false
            try {
                if ($log.Kind -eq 'upgrade') { Assert-UpgradeExclusionLog $mutations[$name] } else { $null = Assert-RemovalLog $mutations[$name] }
            } catch { $refused = $true }
            if (-not $refused) { throw "The $($log.Kind) check accepted a copy of $($log.Path) with its negative control applied: $name" }
            "ok    $($log.Path): refused with $name"
        }
    }
    exit 0
}
if ($Mode -eq 'FailingCandidate') {
    if (-not $MsiPath -or -not $Output) { throw 'FailingCandidate needs -MsiPath and -Output' }
    New-FailingCandidate (Resolve-Path -LiteralPath $MsiPath).Path $Output -NewProductCode:$NewProductCode
    "Prepared forced-failure candidate $Output"
    exit 0
}
# The User cases on the invoking account. The refusals run before any package is
# copied or installed. The child runs User with this account's SID as its marker;
# its own cleanup uninstalls what it installed, and this parent then requires
# the footprint to be empty again and removes the data folder the run created.
if ($Mode -eq 'LocalAccount') {
    if (-not $MsiPath) { throw 'LocalAccount needs -MsiPath' }
    if ($Unscoped) { throw 'LocalAccount refuses -Unscoped: an unscoped install may ask for elevation' }
    if (($PredecessorElsewhere -or $FailUpgrade) -and -not $PredecessorMsiPath) { throw 'PredecessorElsewhere and FailUpgrade qualify an upgrade and need -PredecessorMsiPath' }
    if ($FailSameVersion -and ($PredecessorMsiPath -or $CheckTools)) { throw 'FailSameVersion installs the candidate as its own predecessor and takes no other variant' }
    if ($PredecessorMsiPath -and $PredecessorVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'An upgrade needs -PredecessorVersion naming the predecessor release' }
    Assert-UnelevatedToken
    # The installer and runtime started from here must see the real profile.
    Assert-RealProfileView
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $localAppData = Get-ProfileFolder LocalApplicationData
    $footprint = { Get-OpenAbstractionsFootprint $sid $localAppData $env:ProgramFiles (Get-ProfileFolder Startup) }
    Assert-NoOpenAbstractions (& $footprint)
    $MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
    if ([IO.Path]::GetExtension($MsiPath) -ne '.msi') { throw 'Expected an MSI package' }
    $data = Join-Path $localAppData 'openabstractions'
    $dataExisted = Test-Path -LiteralPath $data
    $sentinel = Join-Path $data 'runtime-v1\qualification-sentinel.txt'
    $directory = Join-Path ([IO.Path]::GetFullPath($ResultDirectory)) ('local-account-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $failure = $null
    try {
        Copy-Item -LiteralPath $MsiPath -Destination (Join-Path $directory 'package.msi')
        if ($FailUpgrade) { New-FailingCandidate $MsiPath (Join-Path $directory 'failing-upgrade.msi') }
        if ($FailSameVersion) { New-FailingCandidate $MsiPath (Join-Path $directory 'failing-same-version.msi') -NewProductCode }
        $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Mode','User','-MsiPath',"`"$directory\package.msi`"",'-ExpectedSid',$sid)
        if ($PredecessorMsiPath) {
            $PredecessorMsiPath = (Resolve-Path -LiteralPath $PredecessorMsiPath).Path
            Assert-PackageHash $PredecessorMsiPath $PredecessorSHA256
            Copy-Item -LiteralPath $PredecessorMsiPath -Destination (Join-Path $directory 'predecessor.msi')
            $arguments += @('-PredecessorMsiPath',"`"$directory\predecessor.msi`"",'-PredecessorSHA256',$PredecessorSHA256,'-PredecessorVersion',$PredecessorVersion,'-ExpectedVersion',$ExpectedVersion)
        }
        if ($PredecessorElsewhere) { $arguments += '-PredecessorElsewhere' }
        if ($FailUpgrade) { $arguments += '-FailUpgrade' }
        if ($FailSameVersion) { $arguments += '-FailSameVersion' }
        if ($CheckTools) {
            if (-not $PythonPath -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw 'Release tools check requires an explicit existing Python executable' }
            $arguments += @('-CheckTools','-PythonPath',"`"$PythonPath`"")
        }
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = 'powershell.exe'
        $info.Arguments = $arguments -join ' '
        $info.WorkingDirectory = $directory
        $info.EnvironmentVariables['OA_FIXTURE_LOCAL_ACCOUNT'] = $sid
        $child = Invoke-FixtureProcess $info $(if ($PredecessorMsiPath) { 600 } else { 300 })
        $child.Output | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.log')
        $child.Diagnostics | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.err')
        if ($child.ExitCode -ne 0) { throw "Local-account fixture exited $($child.ExitCode); inspect $directory" }
        Assert-RuntimeRemoved $sid (Join-Path $directory 'account-removal-remaining.json')
    } catch { $failure = $_ } finally {
        $cleanup = @()
        if (-not $dataExisted -and (Test-Path -LiteralPath $data)) {
            try { Remove-Item -LiteralPath $data -Recurse -Force } catch { $cleanup += "data folder $data`: $($_.Exception.Message)" }
        } elseif (Test-Path -LiteralPath $sentinel) {
            try { Remove-Item -LiteralPath $sentinel -Force } catch { $cleanup += "sentinel $sentinel`: $($_.Exception.Message)" }
        }
        foreach ($copy in 'package.msi','predecessor.msi','failing-upgrade.msi','failing-same-version.msi') {
            $path = Join-Path $directory $copy
            try { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } } catch { $cleanup += "package copy $path`: $($_.Exception.Message)" }
        }
        $left = @(try { & $footprint } catch { "footprint unreadable: $($_.Exception.Message)" })
        if ($left.Count) { $cleanup += "left installed: $($left -join '; ')" }
    }
    if ($failure) { throw $failure }
    if ($cleanup.Count) { throw "The local-account run did not remove what it installed: $($cleanup -join ' | ')" }
    "ok: local-account cases passed and removed what they installed; evidence in $directory"
    exit 0
}
if ($Mode -eq 'User') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($identity.User.Value -ne $ExpectedSid -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Fixture requires the exact private non-admin account'
    }
    if ($Unscoped -and $PredecessorMsiPath) { throw 'Unscoped verification installs a fresh package and takes no predecessor' }
    if (($PredecessorElsewhere -or $FailUpgrade) -and -not $PredecessorMsiPath) { throw 'PredecessorElsewhere and FailUpgrade qualify an upgrade and need -PredecessorMsiPath' }
    if ($FailSameVersion -and ($PredecessorMsiPath -or $Unscoped -or $CheckTools)) { throw 'FailSameVersion installs the candidate as its own predecessor and takes no other variant' }
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
            if ($PredecessorVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Upgrade requires an explicit predecessor version' }
            if ($ExpectedVersion -notmatch '^\d+\.\d+\.\d+$' -or [version]$ExpectedVersion -le [version]$PredecessorVersion) { throw "Upgrade requires an explicit candidate version newer than $PredecessorVersion" }
            if ((Get-PackageProperty $PredecessorMsiPath ProductVersion) -ne $PredecessorVersion -or (Get-PackageProperty $MsiPath ProductVersion) -ne $ExpectedVersion) { throw 'Unexpected predecessor or candidate MSI version' }
            if ((Get-PackageProperty $PredecessorMsiPath UpgradeCode) -ne (Get-PackageProperty $MsiPath UpgradeCode)) { throw 'Packages do not share the product upgrade identity' }
            $productCode = Get-PackageProperty $MsiPath ProductCode
            $sentinel = Join-Path (Get-ProfileFolder LocalApplicationData) 'openabstractions\runtime-v1\qualification-sentinel.txt'
            $sentinelValue = [Guid]::NewGuid().ToString('N')
            New-Item -ItemType Directory -Force (Split-Path -Parent $sentinel) | Out-Null
            [IO.File]::WriteAllText($sentinel, $sentinelValue)
            $predecessorTools = $tools
            $predecessorArguments = @('/i',"`"$PredecessorMsiPath`"",'/qn','/norestart','ALLUSERS=2','MSIINSTALLPERUSER=1','/l*v','predecessor-install.log')
            if ($PredecessorElsewhere) {
                # A folder chosen at install time. The candidate upgrades into its own default folder.
                $predecessorFolder = Join-Path (Get-ProfileFolder LocalApplicationData) 'OA-Predecessor-Elsewhere\OpenAbstractions'
                $predecessorTools = Join-Path $predecessorFolder 'tools'
                $predecessorArguments += "APPLICATIONFOLDER=`"$predecessorFolder`""
            }
            $predecessorAttempted = $true
            Invoke-Bounded msiexec.exe $predecessorArguments
            Assert-InstalledVersion $PredecessorVersion (Get-PackageProperty $PredecessorMsiPath ProductCode)
            Assert-RetainedSentinel $sentinel $sentinelValue
            $predecessorImage = (Get-PredecessorActivation $PredecessorVersion).Images[-1]
            if ($PredecessorElsewhere -and (Test-Path -LiteralPath (Join-Path $tools $predecessorImage))) { throw 'The predecessor did not install into its chosen folder' }
            # A predecessor start opens its log before creating the store. Initialize through its own CLI.
            Invoke-Bounded (Join-Path $predecessorTools 'jobd.exe') @('status')
            Start-PredecessorSupervisor $predecessorTools $PredecessorVersion
            $previousProcesses = @(Get-RunningFixtureProcesses $predecessorTools $ExpectedSid)
        }
        if ($FailUpgrade) {
            # The candidate copy fails after the new files are written and before the
            # predecessor is removed. Rollback must restore the files, release the
            # exclusion and activate the predecessor again, and the predecessor must
            # still be installed and registered because nothing removed it.
            $failingPackage = Join-Path (Split-Path -Parent $MsiPath) 'failing-upgrade.msi'
            if (-not (Test-Path -LiteralPath $failingPackage -PathType Leaf)) { throw 'Forced-failure candidate was not prepared' }
            $failedAt = Get-Date
            $failure = ''
            try { Invoke-Bounded msiexec.exe (Get-CandidateInstallArguments $failingPackage $false 'failed-upgrade.log') 300 }
            catch { $failure = $_.Exception.Message }
            if ($failure -notmatch 'msiexec\.exe exited 1603') { throw "The forced upgrade failure did not end with 1603: $failure" }
            Assert-PreviousProcessesExited $previousProcesses
            Assert-RolledBackUpgrade ([IO.File]::ReadAllText((Join-Path (Get-Location) 'failed-upgrade.log'))) $predecessorTools $ExpectedSid $failedAt (Get-PackageProperty $PredecessorMsiPath ProductCode) $PredecessorVersion $sentinel $sentinelValue
            "ok: failed upgrade left $PredecessorVersion installed, registered and running again, and released its exclusion" | Set-Content 'failed-upgrade.txt'
            # The restored predecessor's own removal is out of scope; end its restarted processes before cleanup removes it.
            foreach ($process in @(Get-RuntimeProcesses $ExpectedSid | Where-Object { [string]$_.ExecutablePath -like (Join-Path $predecessorTools '*') })) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
            }
        } elseif ($FailSameVersion) {
            $installAttempted = $true
            Invoke-SameVersionFailure $MsiPath $tools $ExpectedSid
            $installAttempted = $false
        } else {
            $installAttempted = $true
            Invoke-InstallWithDiagnostics {
                Invoke-Bounded msiexec.exe (Get-CandidateInstallArguments $MsiPath $Unscoped.IsPresent)
            } { Save-ActivationFailure $tools }
            $installed = $true
            Assert-NoUpgradeExclusion
            if ($PredecessorMsiPath) {
                Assert-PreviousProcessesExited $previousProcesses
                Assert-UpgradeExclusionLog ([IO.File]::ReadAllText((Join-Path (Get-Location) 'user-install.log')))
                'ok: the per-user upgrade exclusion and its commit release preceded the new files, nothing was stopped, and the predecessor went after the commit' | Set-Content 'upgrade-exclusion-log.txt'
                if ($PredecessorElsewhere) {
                    if (Test-Path -LiteralPath (Join-Path $predecessorTools $predecessorImage)) { throw 'The upgrade left the predecessor installed in its chosen folder' }
                    'ok: the upgrade replaced and removed the predecessor installed in a non-default folder' | Set-Content 'upgrade-elsewhere.txt'
                }
            }
            if ($CheckTools -or $Unscoped) { Assert-InstalledUserTools $tools }
            if ($Unscoped) { Assert-SingleUserScope }
            $central = Join-Path $tools 'openabstractions.exe'
            Assert-RuntimeReady $central post-install-status
            if ($CheckTools) { Assert-ServiceDownload $central $PythonPath }
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
            $restartManager = Assert-HonestRemoval 'user-uninstall.log' $ExpectedSid (Split-Path -Parent $tools) 'removal-restart-manager.json'
            Assert-RuntimeRemoved $ExpectedSid 'removal-remaining.json' (Split-Path -Parent $tools)
            if ($sentinel) { Assert-RetainedSentinel $sentinel $sentinelValue; Assert-RemovedRegistration }
            if ($Unscoped) { Assert-RemovedRegistration }
            if ($CheckTools -or $Unscoped) {
                if (Test-Path (Split-Path -Parent $tools)) { throw 'Install folder survived removal' }
                if (Test-Path 'HKCU:\Software\OpenAbstractions') { throw 'User registry key survived removal' }
                $userPath = (Get-ItemProperty 'HKCU:\Environment' -Name Path -ErrorAction SilentlyContinue).Path
                if ($userPath -like '*Programs\OpenAbstractions*') { throw 'User PATH entry survived removal' }
            }
            if (Test-Path -LiteralPath $shortcutPath) { throw 'Startup shortcut survived uninstall' }
            foreach ($name in @('openabstractionsw.exe','openabstractions.exe')) {
                if (Test-Path -LiteralPath (Join-Path $tools $name)) { throw "Installed $name survived uninstall" }
            }
            "ok: uninstall removed processes, endpoints, shortcut and runtime binaries before fixture cleanup, with no reboot pending; $restartManager" | Set-Content 'removal.txt'
        }
    } finally {
        foreach ($process in $previousProcesses) { $process.Dispose() }
        if ($installed -or $installAttempted) {
            # A post-InstallFinalize activation error can leave committed files.
            try { Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'user-cleanup-uninstall.log') } catch { Write-Warning $_ }
        }
        if ($predecessorAttempted) {
            $oldCode = Get-PackageProperty $PredecessorMsiPath ProductCode
            if (@(Get-InstalledProducts | Where-Object { $_.ProductCode -eq $oldCode }).Count) {
                try { Invoke-Bounded msiexec.exe @('/x',"`"$PredecessorMsiPath`"",'/qn','/norestart','/l*v','predecessor-cleanup.log') } catch { Write-Warning $_ }
            }
        }
        # openabstractions appends each failed installer-invoked command here; MSI discards its stderr.
        $installerActions = Join-Path (Get-ProfileFolder LocalApplicationData) 'openabstractions\upgrade-v1\installer-actions.txt'
        try { if (Test-Path -LiteralPath $installerActions) { Copy-Item -LiteralPath $installerActions -Destination 'installer-actions.txt' -Force } }
        catch { Write-Warning ('Installer action diagnostics failed: ' + (Protect-DiagnosticText $_.Exception.Message)) }
    }
    exit 0
}

$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
if ([IO.Path]::GetExtension($MsiPath) -ne '.msi') { throw 'Expected an MSI package' }
if ($Unscoped -and $PredecessorMsiPath) { throw 'Unscoped verification installs a fresh package and takes no predecessor' }
if (($PredecessorElsewhere -or $FailUpgrade) -and -not $PredecessorMsiPath) { throw 'PredecessorElsewhere and FailUpgrade qualify an upgrade and need -PredecessorMsiPath' }
if ($FailSameVersion -and ($PredecessorMsiPath -or $Unscoped -or $CheckTools)) { throw 'FailSameVersion installs the candidate as its own predecessor and takes no other variant' }
# The predecessor release is the caller's choice, not a constant of this fixture.
if ($PredecessorMsiPath -and $PredecessorVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'An upgrade needs -PredecessorVersion naming the predecessor release' }
if (@(Get-Service | Where-Object { $_.Name -like 'OpenAbstractionsSupervisor*' }).Count) { throw 'Run per-user verification on a separate clean runner' }
$directory = Join-Path $env:ProgramData ('OA-User-Test-' + [Guid]::NewGuid().ToString('N'))
$account = $null
try {
    # A standard Users-group account with a masked random password.
    $account = New-DisposableAccount -Prefix 'oa_ci'
    New-Item -ItemType Directory -Path $directory | Out-Null
    Grant-AccountAccess -Path $directory -Sid $account.Sid -Access Modify
    Copy-Item -LiteralPath $MsiPath -Destination (Join-Path $directory 'package.msi')
    if ($FailUpgrade) { New-FailingCandidate $MsiPath (Join-Path $directory 'failing-upgrade.msi') }
    if ($FailSameVersion) { New-FailingCandidate $MsiPath (Join-Path $directory 'failing-same-version.msi') -NewProductCode }
    if ($PredecessorMsiPath) {
        $PredecessorMsiPath = (Resolve-Path -LiteralPath $PredecessorMsiPath).Path
        Assert-PackageHash $PredecessorMsiPath $PredecessorSHA256
        Copy-Item -LiteralPath $PredecessorMsiPath -Destination (Join-Path $directory 'predecessor.msi')
    }
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $directory 'fixture.ps1')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'OAFixture.psm1') -Destination (Join-Path $directory 'OAFixture.psm1')
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
    $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$directory\launcher.ps1`"",'-Mode','User','-MsiPath',"`"$directory\package.msi`"",'-ExpectedSid',$account.Sid)
    if ($PredecessorMsiPath) { $arguments += @('-PredecessorMsiPath',"`"$directory\predecessor.msi`"",'-PredecessorSHA256',$PredecessorSHA256,'-PredecessorVersion',$PredecessorVersion,'-ExpectedVersion',$ExpectedVersion) }
    if ($Unscoped) { $arguments += '-Unscoped' }
    if ($PredecessorElsewhere) { $arguments += '-PredecessorElsewhere' }
    if ($FailUpgrade) { $arguments += '-FailUpgrade' }
    if ($FailSameVersion) { $arguments += '-FailSameVersion' }
    if ($CheckTools) {
        if (-not $PythonPath -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw 'Release tools check requires an explicit existing Python executable' }
        $arguments += @('-CheckTools','-PythonPath',"`"$PythonPath`"")
    }
    $child = Invoke-AccountProcess -Account $account -FileName 'powershell.exe' -Arguments $arguments -WorkingDirectory $directory -Seconds $(if ($PredecessorMsiPath) { 600 } else { 300 })
    $child.Output | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.log')
    $child.Diagnostics | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.err')
    if ($child.ExitCode -ne 0) { throw "Per-user fixture exited $($child.ExitCode); inspect diagnostics" }
    New-Item -ItemType Directory -Force -Path $ResultDirectory | Out-Null
    Assert-RuntimeRemoved $account.Sid (Join-Path $ResultDirectory 'account-removal-remaining.json')
} finally {
    try {
        if (Test-Path -LiteralPath $directory) {
            New-Item -ItemType Directory -Force -Path $ResultDirectory | Out-Null
            Get-ChildItem -LiteralPath $directory -File | Where-Object { $_.Extension -in @('.log','.err','.txt','.json') } | Copy-Item -Destination $ResultDirectory
        }
        $machineActions = Join-Path $env:ProgramData 'abstraction\upgrade-v1\installer-actions.txt'
        if (Test-Path -LiteralPath $machineActions) {
            New-Item -ItemType Directory -Force -Path $ResultDirectory | Out-Null
            Copy-Item -LiteralPath $machineActions -Destination (Join-Path $ResultDirectory 'machine-installer-actions.txt')
        }
    } catch { Write-Warning "Could not preserve all fixture diagnostics: $_" }
    # Account-owned runtime leftovers are cleanup only; no assertion becomes green here.
    if ($account) { Remove-DisposableAccount -Account $account -RuntimeProcessesOnly -RequirePresent }
    # Retain the fixture directory for runner disposal; never recursively delete
    # a path writable by the test account, which could contain reparse points.
}
