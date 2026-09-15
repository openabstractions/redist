param(
    [ValidateSet('ValidateOnly','Verify','User','FailingCandidate')][string]$Mode = 'ValidateOnly',
    [string]$MsiPath,
    [string]$ExpectedSid,
    [switch]$CheckTools,
    [switch]$Unscoped,
    [switch]$PredecessorElsewhere,
    [switch]$FailUpgrade,
    [string]$Output,
    [string]$PythonPath,
    [string]$PredecessorMsiPath,
    [string]$PredecessorSHA256,
    [string]$ExpectedVersion,
    [string]$ResultDirectory = (Join-Path (Get-Location) 'user-runtime-diagnostics')
)
$ErrorActionPreference = 'Stop'
# Bounded processes, the disposable account, runtime process and pipe queries,
# product enumeration and diagnostic redaction. The parent copies the module
# beside the account's copy of this fixture.
Import-Module (Join-Path $PSScriptRoot 'OAFixture.psm1') -Force
if ($Mode -eq 'ValidateOnly') {
    'Per-user fixture parsed; no accounts, processes, installations or registrations changed.'
    exit 0
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
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
# The hosted proof for a per-user upgrade: the incoming stop succeeded, its
# script flushed before RemoveExistingProducts, and the executed command carried
# a resolved folder and related ProductCodes. Mirrors check() in
# installer/test_upgrade_log.py, which the redist fixture does not carry;
# test_user_runtime.py holds both to the same accepted and refused logs.
function Assert-UpgradeStopLog([string]$Text, [string]$Action = 'StopPreviousUserSupervisor') {
    $removal = [regex]::Match($Text, 'Action start [^\r\n]*: RemoveExistingProducts\.')
    if (-not $removal.Success) { throw 'upgrade never reached RemoveExistingProducts' }
    $before = $Text.Substring(0, $removal.Index)
    $stop = [regex]::Match($before, "Action ended [^\r\n]*: $([regex]::Escape($Action))\. Return value 1\.")
    if (-not $stop.Success) { throw "checked incoming stop $Action did not succeed before removal" }
    $after = $before.Substring($stop.Index + $stop.Length)
    $flush = [regex]::Match($after, 'Action ended [^\r\n]*: InstallExecute\. Return value 1\.')
    if (-not $flush.Success) { throw 'checked stop execution script was not flushed before removal' }
    if ($Action -ceq 'StopPreviousUserSupervisor') {
        $op = [regex]::Match($after.Substring(0, $flush.Index), "Executing op: CustomActionSchedule\(Action=$([regex]::Escape($Action)),ActionType=(\d+),Source=[^,\r\n]*,Target=([^\r\n]*),\)")
        if (-not $op.Success) { throw 'per-user stop was not executed from the early script' }
        if ([int64]$op.Groups[1].Value -band 2048) { throw 'per-user stop executed without impersonation' }
        $guid = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
        if (-not [regex]::IsMatch($op.Groups[2].Value, "^service stop --user `"[A-Za-z]:\\[^`"\[\]]+\\\.`" --related `"$guid(?:;$guid)*`"\z")) {
            throw "per-user stop target was not a resolved install folder and related product list: $($op.Groups[2].Value)"
        }
        # The upgrade exclusion was held by the same script before the stop ran.
        if (-not [regex]::IsMatch($before.Substring(0, $stop.Index), 'Action ended [^\r\n]*: BeginUserUpgradeExclusion\. Return value 1\.')) {
            throw 'the upgrade exclusion was not scheduled before the per-user stop'
        }
        $exclusion = [regex]::Match($after.Substring(0, $op.Index), 'Executing op: CustomActionSchedule\(Action=BeginUserUpgradeExclusion,ActionType=(\d+),Source=[^,\r\n]*,Target=([^\r\n]*),\)')
        if (-not $exclusion.Success) { throw 'the upgrade exclusion was not executed before the per-user stop' }
        if (([int64]$exclusion.Groups[1].Value -band 2048) -or -not [regex]::IsMatch($exclusion.Groups[2].Value, "^service begin-upgrade --user `"[A-Za-z]:\\[^`"\[\]]+\\\.`" --related `"$guid(?:;$guid)*`"\z")) {
            throw "the upgrade exclusion did not hold the resolved folder and related products: $($exclusion.Groups[2].Value)"
        }
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
# A copy of the candidate that fails after its predecessor was removed. An error
# custom action (type 19) follows InstallFiles, so the early script, the
# predecessor stop and RemoveExistingProducts have run before it refuses. The
# copy gets its own package code; the source package is unchanged.
function New-FailingCandidate([string]$Source, [string]$Target) {
    if (Test-Path -LiteralPath $Target) { throw "Forced-failure candidate already exists: $Target" }
    Copy-Item -LiteralPath $Source -Destination $Target
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Target, 1)
    try {
        $removal = Get-MsiSequence $database "``Action``='RemoveExistingProducts'"
        $files = Get-MsiSequence $database "``Action``='InstallFiles'"
        $finalize = Get-MsiSequence $database "``Action``='InstallFinalize'"
        if ($null -eq $removal -or $null -eq $files -or $null -eq $finalize -or
            -not ($removal.Sequence -lt $files.Sequence -and $files.Sequence + 1 -lt $finalize.Sequence)) {
            throw 'Candidate sequence does not place InstallFiles between RemoveExistingProducts and InstallFinalize'
        }
        $at = $files.Sequence + 1
        if ($null -ne (Get-MsiSequence $database "``Sequence``=$at")) { throw "Candidate sequence $at is already used" }
        Invoke-MsiSql $database "INSERT INTO ``CustomAction`` (``Action``, ``Type``, ``Target``) VALUES ('ForcedUpgradeFailure', 19, 'Forced upgrade failure after the predecessor was removed')"
        Invoke-MsiSql $database "INSERT INTO ``InstallExecuteSequence`` (``Action``, ``Condition``, ``Sequence``) VALUES ('ForcedUpgradeFailure', 'NOT REMOVE', $at)"
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
# A failed upgrade restored the predecessor's registration and data, released
# its exclusion, and restarted the supervisor its stop ended, from its folder.
function Assert-RolledBackUpgrade([string]$LogText, [string]$PredecessorTools, [string]$Sid, [DateTime]$FailedAt,
                                  [string]$PredecessorCode, [string]$Sentinel, [string]$Value, [int]$Seconds = 30) {
    $removal = [regex]::Match($LogText, 'Action start [^\r\n]*: RemoveExistingProducts\.')
    if (-not $removal.Success) { throw 'The failed upgrade never removed the predecessor' }
    $failure = [regex]::Match($LogText, 'Action start [^\r\n]*: ForcedUpgradeFailure\.')
    if (-not $failure.Success -or $failure.Index -lt $removal.Index) { throw 'The forced failure did not follow the predecessor removal' }
    if (-not @([regex]::Matches($LogText, 'RestartPreviousUserSupervisor') | Where-Object { $_.Index -gt $failure.Index }).Count) {
        throw 'Rollback did not run the per-user restart'
    }
    Assert-InstalledVersion '0.1.5' $PredecessorCode
    Assert-RetainedSentinel $Sentinel $Value
    Assert-NoUpgradeExclusion
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $restarted = @(Get-RuntimeProcesses $Sid | Where-Object {
            $_.Name -in @('jobd.exe','jobdw.exe') -and [string]$_.ExecutablePath -ieq (Join-Path $PredecessorTools $_.Name) -and ([DateTime]$_.CreationDate) -gt $FailedAt
        })
        if ($restarted.Count) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Rollback did not restart the stopped predecessor supervisor from its folder'
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
if ($Mode -eq 'FailingCandidate') {
    if (-not $MsiPath -or -not $Output) { throw 'FailingCandidate needs -MsiPath and -Output' }
    New-FailingCandidate (Resolve-Path -LiteralPath $MsiPath).Path $Output
    "Prepared forced-failure candidate $Output"
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
            Assert-InstalledVersion '0.1.5' (Get-PackageProperty $PredecessorMsiPath ProductCode)
            Assert-RetainedSentinel $sentinel $sentinelValue
            if ($PredecessorElsewhere -and (Test-Path -LiteralPath (Join-Path $tools 'jobdw.exe'))) { throw 'The predecessor did not install into its chosen folder' }
            # 0.1.5 start opens its log before creating the store. Initialize through its own CLI.
            Invoke-Bounded (Join-Path $predecessorTools 'jobd.exe') @('status')
            Start-PredecessorSupervisor $predecessorTools
            $previousProcesses = @(Get-RunningFixtureProcesses $predecessorTools $ExpectedSid)
        }
        if ($FailUpgrade) {
            # The candidate copy fails after the predecessor was removed. Rollback must
            # restore it, release the exclusion and restart what the stop ended.
            $failingPackage = Join-Path (Split-Path -Parent $MsiPath) 'failing-upgrade.msi'
            if (-not (Test-Path -LiteralPath $failingPackage -PathType Leaf)) { throw 'Forced-failure candidate was not prepared' }
            $failedAt = Get-Date
            $failure = ''
            try { Invoke-Bounded msiexec.exe (Get-CandidateInstallArguments $failingPackage $false 'failed-upgrade.log') 300 }
            catch { $failure = $_.Exception.Message }
            if ($failure -notmatch 'msiexec\.exe exited 1603') { throw "The forced upgrade failure did not end with 1603: $failure" }
            Assert-PreviousProcessesExited $previousProcesses
            Assert-RolledBackUpgrade ([IO.File]::ReadAllText((Join-Path (Get-Location) 'failed-upgrade.log'))) $predecessorTools $ExpectedSid $failedAt (Get-PackageProperty $PredecessorMsiPath ProductCode) $sentinel $sentinelValue
            'ok: failed upgrade restored the predecessor, released its exclusion and restarted the stopped supervisor' | Set-Content 'failed-upgrade.txt'
            # The restored predecessor's own removal is out of scope; end its restarted processes before cleanup removes it.
            foreach ($process in @(Get-RuntimeProcesses $ExpectedSid | Where-Object { [string]$_.ExecutablePath -like (Join-Path $predecessorTools '*') })) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
            }
        } else {
            $installAttempted = $true
            Invoke-InstallWithDiagnostics {
                Invoke-Bounded msiexec.exe (Get-CandidateInstallArguments $MsiPath $Unscoped.IsPresent)
            } { Save-ActivationFailure $tools }
            $installed = $true
            Assert-NoUpgradeExclusion
            if ($PredecessorMsiPath) {
                Assert-PreviousProcessesExited $previousProcesses
                Assert-UpgradeStopLog ([IO.File]::ReadAllText((Join-Path (Get-Location) 'user-install.log')))
                'ok: incoming per-user stop and its flush preceded RemoveExistingProducts' | Set-Content 'upgrade-stop-log.txt'
                if ($PredecessorElsewhere) {
                    if (Test-Path -LiteralPath (Join-Path $predecessorTools 'jobdw.exe')) { throw 'The upgrade left the predecessor installed in its chosen folder' }
                    'ok: the upgrade stopped and removed the predecessor installed in a non-default folder' | Set-Content 'upgrade-elsewhere.txt'
                }
            }
            if ($CheckTools -or $Unscoped) { Assert-InstalledUserTools $tools }
            if ($Unscoped) { Assert-SingleUserScope }
            if ($CheckTools) { Assert-ToolStoreCompatibility $tools $PythonPath }
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
            foreach ($name in @('jobdw.exe','openabstractions.exe')) {
                if (Test-Path -LiteralPath (Join-Path $tools $name)) { throw "Installed $name survived uninstall" }
            }
            'ok: uninstall removed processes, endpoints, shortcut and runtime binaries before fixture cleanup' | Set-Content 'removal.txt'
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
    }
    exit 0
}

$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
if ([IO.Path]::GetExtension($MsiPath) -ne '.msi') { throw 'Expected an MSI package' }
if ($Unscoped -and $PredecessorMsiPath) { throw 'Unscoped verification installs a fresh package and takes no predecessor' }
if (($PredecessorElsewhere -or $FailUpgrade) -and -not $PredecessorMsiPath) { throw 'PredecessorElsewhere and FailUpgrade qualify an upgrade and need -PredecessorMsiPath' }
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
    if ($PredecessorMsiPath) { $arguments += @('-PredecessorMsiPath',"`"$directory\predecessor.msi`"",'-PredecessorSHA256',$PredecessorSHA256,'-ExpectedVersion',$ExpectedVersion) }
    if ($Unscoped) { $arguments += '-Unscoped' }
    if ($PredecessorElsewhere) { $arguments += '-PredecessorElsewhere' }
    if ($FailUpgrade) { $arguments += '-FailUpgrade' }
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
    } catch { Write-Warning "Could not preserve all fixture diagnostics: $_" }
    # Account-owned runtime leftovers are cleanup only; no assertion becomes green here.
    if ($account) { Remove-DisposableAccount -Account $account -RuntimeProcessesOnly -RequirePresent }
    # Retain the fixture directory for runner disposal; never recursively delete
    # a path writable by the test account, which could contain reparse points.
}
