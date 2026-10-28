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
    [string]$NodePath,
    [string]$SdkSmokes,
    [string]$NativeCoreRequest,
    [ValidateSet(0,3600)][int]$SoakSeconds = 0,
    [string]$ExpectedRuntimeSha256,
    [string]$ExpectedSupervisorSha256,
    [string]$SoakRequestPath,
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
  -MsiPath PATH  -CheckTools -PythonPath PATH  -SdkSmokes DIR -NodePath PATH  -Unscoped (Verify only)
  -PredecessorMsiPath PATH -PredecessorSHA256 HEX -PredecessorVersion X.Y.Z -ExpectedVersion X.Y.Z
  -PredecessorElsewhere  -FailUpgrade  -FailSameVersion
  -ResultDirectory DIR   logs and evidence (default .\user-runtime-diagnostics)
  -SoakSeconds 3600 -ExpectedRuntimeSha256 HEX -ExpectedSupervisorSha256 HEX -SoakRequestPath PATH
                    rehearsal-only installed hour; default0 preserves ordinary lifetime
'@
    exit 0
}
# Bounded processes, the disposable account, runtime process and pipe queries,
# product enumeration and diagnostic redaction. The parent copies the module
# beside the account's copy of this fixture.
Import-Module (Join-Path $PSScriptRoot 'OAFixture.psm1') -Force
if ($SoakSeconds -and ($Mode -notin @('User','Verify','LocalAccount') -or $FailUpgrade -or $FailSameVersion -or
    $ExpectedRuntimeSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedSupervisorSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    -not [IO.Path]::IsPathRooted($SoakRequestPath) -or -not (Test-Path -LiteralPath $SoakRequestPath -PathType Leaf))) {
    throw 'Rehearsal soak requires the ordinary lifecycle and exact runtime/supervisor/request inputs'
}
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
# Keep the executor, Administrators and SYSTEM able to traverse every copied
# SDK input before removing inherited grants. The parent diagnostics folder
# grants the disposable account Modify; replace that grant with RX on each item.
function Protect-SdkSmokeInputs {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][ValidatePattern('^S-1-5-(?:\d+-)*\d+$')][string]$Sid)
    Assert-DisposableRunner
    $executor = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($Sid -in @($executor, 'S-1-5-32-544', 'S-1-5-18')) {
        throw 'SDK smoke account must differ from executor, Administrators and SYSTEM'
    }
    $account = [Security.Principal.SecurityIdentifier]::new($Sid)
    $privileged = @($executor, 'S-1-5-32-544', 'S-1-5-18') |
        ForEach-Object { [Security.Principal.SecurityIdentifier]::new($_) }
    $root = Get-Item -LiteralPath $Path -Force
    if (-not $root.PSIsContainer) { throw 'SDK smoke inputs must be a directory' }
    if ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "SDK smoke input is a reparse point: $($root.FullName)"
    }
    $items = New-Object Collections.ArrayList
    $pending = New-Object Collections.Queue
    $null = $items.Add($root)
    $pending.Enqueue($root)
    while ($pending.Count) {
        $directory = $pending.Dequeue()
        foreach ($child in @(Get-ChildItem -LiteralPath $directory.FullName -Force)) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "SDK smoke input is a reparse point: $($child.FullName)"
            }
            $null = $items.Add($child)
            if ($child.PSIsContainer) { $pending.Enqueue($child) }
        }
    }
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "SDK smoke input is a reparse point: $($item.FullName)"
        }
        $flags = if ($item.PSIsContainer) {
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        } else { [Security.AccessControl.InheritanceFlags]::None }
        $security = if ($item.PSIsContainer) {
            [IO.Directory]::GetAccessControl($item.FullName)
        } else { [IO.File]::GetAccessControl($item.FullName) }
        # Complete one object's protected ACL before writing it to disk.
        $security.SetAccessRuleProtection($true, $false)
        foreach ($old in @($security.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
            $security.RemoveAccessRuleSpecific($old)
        }
        foreach ($principal in $privileged) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $principal, [Security.AccessControl.FileSystemRights]::FullControl, $flags,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            $security.SetAccessRule($rule)
        }
        $readOnly = [Security.AccessControl.FileSystemAccessRule]::new(
            $account, [Security.AccessControl.FileSystemRights]::ReadAndExecute, $flags,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($readOnly)
        if ($item.PSIsContainer) {
            [IO.Directory]::SetAccessControl($item.FullName, $security)
        } else { [IO.File]::SetAccessControl($item.FullName, $security) }
    }
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
    if ($actualTarget -ne $expectedTarget -or $Shortcut.Arguments -ne 'serve supervisor' -or $actualDirectory -ne $expectedDirectory) {
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
    $health = [ordered]@{ status_exit=$probe.ExitCode; describes=@() }
    if ($probe.ExitCode -ne 0) { throw "Runtime status exited $($probe.ExitCode)" }
    $status = Get-Content "$Evidence.json" -Raw | ConvertFrom-Json
    if ($null -eq $status -or $status -is [array] -or $status -isnot [Management.Automation.PSCustomObject]) {
        throw 'Runtime status report is malformed: expected an object'
    }
    $endpoints = @{}
    foreach ($contract in @('abstraction.logging/sink@1','abstraction.config/reader@1','abstraction.config/editor@1','abstraction.job/acceptance@1','abstraction.job/operations@1')) {
        $capability = $contract.Split('/')[0]
        $matches = @($status.capabilities | Where-Object { $_.capability -eq $capability -and $_.contract -eq $contract })
        if ($matches.Count -ne 1 -or $matches[0].status -ne 'resolved') {
            throw "Expected exactly one ready contract: $contract"
        }
        $endpoint = $matches[0].result.reference.endpoint
        if ($endpoint -isnot [string] -or -not $endpoint -or $endpoint.Contains('"') -or $endpoint.Contains("`r") -or $endpoint.Contains("`n")) {
            throw "Resolved contract lacks a usable endpoint: $contract"
        }
        if (-not $endpoints.ContainsKey($endpoint)) { $endpoints[$endpoint] = @() }
        $endpoints[$endpoint] += $contract
    }
    # Resolve proves the binding; Describe supplies the endpoint's current
    # readiness facts. Its self-reported metadata grants no authority.
    foreach ($endpoint in @($endpoints.Keys | Sort-Object)) {
        $describeInfo = New-Object Diagnostics.ProcessStartInfo
        $describeInfo.FileName = $central
        $describeInfo.Arguments = 'status describe "' + $endpoint + '" --json --timeout 5s'
        $described = Invoke-FixtureProcess $describeInfo 10
        $prefix = $Evidence + '.describe-' + $health.describes.Count
        $described.Output | Set-Content -Encoding UTF8 ($prefix + '.json')
        $described.Diagnostics | Set-Content -Encoding UTF8 ($prefix + '.err')
        $health.describes += [ordered]@{ endpoint=$endpoint; exit_code=$described.ExitCode; output=($prefix+'.json'); diagnostics=($prefix+'.err') }
        if ($described.ExitCode -ne 0) { throw "Endpoint Describe failed for $endpoint" }
        try { $description = ConvertFrom-Json -InputObject $described.Output -ErrorAction Stop }
        catch { throw "Endpoint Describe returned invalid JSON for $endpoint" }
        if ($null -eq $description -or $description -is [array] -or $description.outcome -cne 'described') {
            throw "Endpoint Describe did not describe $endpoint"
        }
        foreach ($contract in $endpoints[$endpoint]) {
            $matches = @($description.services | Where-Object { $_.contract -ceq $contract })
            if ($matches.Count -ne 1 -or $matches[0].readiness -cne 'ready' -or $matches[0].why -cne '') {
                throw "Endpoint Describe did not list ready $contract"
            }
        }
    }
    [IO.File]::WriteAllText(($Evidence+'.checks.json'),($health | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
}
function Get-InstalledSoakClock {
    # Microsoft realtimeapiset.h: VOID QueryInterruptTime(PULONGLONG), BOOL
    # QueryUnbiasedInterruptTime(PULONGLONG), Kernel32.dll, 100ns units.
    # https://learn.microsoft.com/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttime
    # https://learn.microsoft.com/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime
    # QueryInterruptTime's API-set binding is documented at:
    # https://learn.microsoft.com/uwp/win32-and-com/win32-apis#apis-from-api-ms-win-core-realtime-l1-1-1dll
    # Biased time includes suspend; unbiased time counts the working state.
    if (-not ('OAInstalledSoakClock' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class OAInstalledSoakClock {
    [DllImport("api-ms-win-core-realtime-l1-1-1.dll")] static extern void QueryInterruptTime(out ulong value);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)] static extern bool QueryUnbiasedInterruptTime(out ulong value);
    public static ulong[] Sample() {
        ulong before, awake, after;
        QueryInterruptTime(out before);
        if (!QueryUnbiasedInterruptTime(out awake)) throw new InvalidOperationException("Unbiased clock unavailable");
        QueryInterruptTime(out after);
        return new ulong[] { before, awake, after };
    }
}
'@
    }
    $ticks = [OAInstalledSoakClock]::Sample()
    return [pscustomobject]@{ before=[decimal]$ticks[0]; awake=[decimal]$ticks[1]; after=[decimal]$ticks[2] }
}
function Assert-InstalledSoakClock($Sample, $Previous) {
    foreach ($name in @('before','awake','after')) {
        if ($null -eq $Sample -or -not $Sample.PSObject.Properties[$name] -or $Sample.$name -isnot [decimal]) { throw 'Soak clock fields are unavailable' }
    }
    if ($null -eq $Sample -or $Sample.before -lt 0 -or $Sample.awake -lt 0 -or
        $Sample.after -lt $Sample.before -or ($Sample.after-$Sample.before) -gt 500000) {
        throw 'Soak clock sample unknown or wider than 50ms'
    }
    $low = $Sample.before-$Sample.awake
    $high = $Sample.after-$Sample.awake
    if ($Previous) {
        if ($Sample.awake -lt $Previous.awake -or $Sample.before -lt $Previous.before -or
            ($Sample.after-$Previous.before) -gt 1850000000) { throw 'Soak monotonic clock reversal or observation gap exceeded 185s' }
        $low = [Math]::Max([decimal]$low,[decimal]$Previous.low)
        $high = [Math]::Min([decimal]$high,[decimal]$Previous.high)
        if ($low -gt $high) { throw 'Soak suspend bias changed or clock continuity is unknown' }
    }
    return [pscustomobject]@{ before=$Sample.before; awake=$Sample.awake; after=$Sample.after; low=$low; high=$high }
}
function Get-InstalledSoakInputs([string[]]$Paths) {
    $result = @()
    foreach ($path in $Paths) {
        $item=Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Soak input is not a regular file' }
        $result += [ordered]@{ path=$item.FullName; bytes=$item.Length; sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    return ,$result
}
function Get-InstalledSoakProcesses([string]$Central,[string]$RuntimeHash,[string]$SupervisorHash,[string]$Sid) {
    $held=@()
    try {
        $supervisor=Join-Path (Split-Path -Parent $Central) 'openabstractionsw.exe'
        $processes=@(Get-RuntimeProcesses $Sid)
        foreach ($role in @(@('runtime',$Central,$RuntimeHash,'serve runtime --supervised'),
                            @('supervisor',$supervisor,$SupervisorHash,'serve supervisor(?: --service)?'))) {
            $matches=@($processes | Where-Object { $_.ExecutablePath -ceq $role[1] -and
                $_.CommandLine -cmatch ('^"?' + [regex]::Escape($role[1]) + '"?\s+' + $role[3] + '$') })
            if ($matches.Count -ne 1) { throw "Exact installed soak $($role[0]) process missing or ambiguous" }
            $row=$matches[0]
            $handle=Get-Process -Id $row.ProcessId
            try {
                $null=$handle.Handle # retain the native process handle, including after exit/PID reuse
                $entry=[pscustomobject]@{ role=$role[0]; pid=[int]$row.ProcessId; parent=[int]$row.ParentProcessId;
                    birth=$row.CreationDate.ToUniversalTime().ToString('o'); handle_birth=$handle.StartTime.ToUniversalTime().ToString('o');
                    session=[int]$row.SessionId; sid=$Sid; path=$role[1]; command=[string]$row.CommandLine; sha256=$role[2]; handle=$handle }
            } catch { $handle.Dispose(); throw }
            $held += $entry
        }
        if ($held[0].parent -ne $held[1].pid -or $held[0].session -ne $held[1].session -or
            $held[1].handle.StartTime -gt $held[0].handle.StartTime) { throw 'Soak runtime is not the exact supervisor child; parent PID may be reused' }
        Assert-InstalledSoakProcesses $held $Sid
        return ,$held
    } catch { foreach ($entry in $held) { $entry.handle.Dispose() }; throw }
}
function Assert-InstalledSoakProcesses($Held,[string]$Sid) {
    $current=@(Get-RuntimeProcesses $Sid)
    foreach ($entry in $Held) {
        if ($entry.handle.HasExited -or $entry.handle.StartTime.ToUniversalTime().ToString('o') -cne $entry.handle_birth) { throw 'Soak retained process exited or birth changed' }
        $rows=@($current | Where-Object { $_.ProcessId -eq $entry.pid })
        if ($rows.Count -ne 1 -or $rows[0].CreationDate.ToUniversalTime().ToString('o') -cne $entry.birth -or
            $rows[0].ExecutablePath -cne $entry.path -or $rows[0].CommandLine -cne $entry.command -or
            [int]$rows[0].ParentProcessId -ne $entry.parent -or [int]$rows[0].SessionId -ne $entry.session) { throw 'Soak process identity changed' }
        if ((Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) { throw 'Soak installed image bytes changed' }
        if ($entry.handle.HasExited) { throw 'Soak process exited during observation' }
    }
}
function Get-InstalledRuntimeIntervalRows($Held) {
    return ,@(foreach ($entry in $Held) {
        [ordered]@{ role=$entry.role;pid=$entry.pid;parent=$entry.parent;birth=$entry.birth;
            handle_birth=$entry.handle_birth;session=$entry.session;sid=$entry.sid;path=$entry.path;
            command=$entry.command;sha256=$entry.sha256 }
    })
}
function Assert-InstalledJ1Runtime([string]$Central,[string]$Tools,[string]$PythonPath,
    [string]$RequestPath,[string]$Evidence,[string]$Sid) {
    $native=Get-Content -LiteralPath $RequestPath -Raw|ConvertFrom-Json
    if (-not $native.core.adopter_journey -or $native.runtime_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $native.supervisor_sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'J1 runtime interval requires original selected runtime and supervisor pins' }
    $journal=Get-Content -LiteralPath $Evidence -Raw|ConvertFrom-Json
    if ($journal.runtime_interval -or $journal.state -cne 'installed' -or
        $journal.source_sha -cne $native.source_sha -or $journal.tool_source -cne $native.tool_source -or $journal.runtime_sha256 -cne $native.runtime_sha256 -or
        $journal.native_request.path -cne $RequestPath -or
        $journal.native_request.bytes -ne (Get-Item -LiteralPath $RequestPath).Length -or
        $journal.native_request.sha256 -cne (Get-FileHash -LiteralPath $RequestPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'J1 runtime interval differs from the original installed lifecycle'
    }
    $report=[ordered]@{state='running';sid=$Sid;started_at=[DateTime]::UtcNow.ToString('o');ended_at=$null;
        runtime_sha256=$native.runtime_sha256;supervisor_sha256=$native.supervisor_sha256;before=@();after=@();failure=$null}
    $journal|Add-Member NoteProperty runtime_interval $report
    $held=@();$failure=$null
    try {
        $held=Get-InstalledSoakProcesses $Central $native.runtime_sha256 $native.supervisor_sha256 $Sid
        Assert-InstalledSoakProcesses $held $Sid
        $report.before=Get-InstalledRuntimeIntervalRows $held
        $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
        Assert-NativeCore $Central $Tools $PythonPath $RequestPath
        Assert-InstalledSoakProcesses $held $Sid
        $report.after=Get-InstalledRuntimeIntervalRows $held
        $report.state='stable'
    } catch {
        $failure=$_;$report.state='failed';$report.failure=[string]$_.Exception.Message
    } finally {
        $report.ended_at=[DateTime]::UtcNow.ToString('o')
        try { $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8 }
        finally { foreach ($entry in $held) { $entry.handle.Dispose() } }
    }
    if ($failure) { throw $failure }
}
function Assert-InstalledRuntimeSoak([string]$Central,[string]$RuntimeHash,[string]$SupervisorHash,
    [string]$Sid,[int]$Seconds,[string]$Evidence,[string[]]$InputPaths) {
    if ($Seconds -eq 0) { return }
    if ($Seconds -ne 3600 -or $RuntimeHash -cnotmatch '^[0-9a-f]{64}$' -or $SupervisorHash -cnotmatch '^[0-9a-f]{64}$' -or -not $InputPaths.Count) { throw 'Soak needs exactly 3600s and exact payload/input pins' }
    if (Test-Path -LiteralPath $Evidence) { throw 'Soak attempt already exists; partial evidence cannot resume' }
    if (Test-Path -LiteralPath ($Evidence+'.health-0.json')) { throw 'Soak partial health evidence already exists; cannot resume' }
    $report=[ordered]@{ result='fail'; required_seconds=3600; cadence_seconds=60; cycle_budget_seconds=125;
        max_gap_seconds=185; samples=@(); processes=@(); inputs=$null; observed_awake_seconds=0 }
    $held=@(); $failure=$null
    try {
        # One status plus <=5 Describe processes. Each existing process bound is
        # 10s plus two 5s output-drain bounds: <=120s, with 5s observation allowance.
        # Aim for one cycle per60s; a slow cycle gets no additional pause.
        # Retained handles witness lifetime during the bounded wait between cycles.
        $inputs=Get-InstalledSoakInputs $InputPaths
        $report.inputs=$inputs
        $held=Get-InstalledSoakProcesses $Central $RuntimeHash $SupervisorHash $Sid
        $report.processes=@($held | Select-Object role,pid,parent,birth,handle_birth,session,sid,path,command,sha256)
        $previous=Assert-InstalledSoakClock (Get-InstalledSoakClock) $null
        $report.start_clock=$previous
        $start=$previous.awake
        for ($sample=0; $sample -lt 64; $sample++) {
            $before=Assert-InstalledSoakClock (Get-InstalledSoakClock) $previous
            Assert-InstalledSoakProcesses $held $Sid
            Assert-RuntimeReady $Central ($Evidence + '.health-' + $sample)
            Assert-InstalledSoakProcesses $held $Sid
            if ((ConvertTo-Json -InputObject (Get-InstalledSoakInputs $InputPaths) -Depth 5 -Compress) -cne
                (ConvertTo-Json -InputObject $inputs -Depth 5 -Compress)) { throw 'Soak candidate or declared input bytes changed' }
            $after=Assert-InstalledSoakClock (Get-InstalledSoakClock) $before
            Assert-InstalledSoakProcesses $held $Sid
            if (($after.after-$before.before) -gt 1250000000) { throw 'Soak readiness cycle exceeded 125s' }
            $report.samples += [ordered]@{ index=$sample; begin=$before; end=$after; health=($Evidence+'.health-'+$sample+'.json') }
            $report.observed_awake_seconds=($after.awake-$start)/10000000
            if ($report.observed_awake_seconds -ge 3600) { $report.result='pass'; break }
            $previous=$after
            $pause=[Math]::Max([decimal]0,[decimal]60000-($after.awake-$before.awake)/10000)
            if ($pause -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Ceiling($pause)) }
        }
        if ($report.result -cne 'pass') { throw 'Soak sample bound exhausted without a full observed hour' }
    } catch { $failure=$_; $report.failure=$_.Exception.Message } finally {
        foreach ($entry in $held) { $entry.handle.Dispose() }
        [IO.File]::WriteAllText($Evidence,($report | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    }
    if ($failure) { throw $failure }
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
    $products = @($observed | Where-Object { $_.ProductName -in @('OpenAbstractions', 'Abstraction') -or $_.ProductCode -eq $ProductCode })
    if ($products.Count -ne 1 -or $products[0].VersionString -ne $Version -or $products[0].ProductCode -ne $ProductCode -or
        $products[0].ProductName -notin @('OpenAbstractions', 'Abstraction') -or $products[0].State -ne '5' -or $products[0].Context -ne 2 -or
        $products[0].UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw "Expected installed per-user product $ProductCode version $Version; observed: $($observed | ConvertTo-Json -Depth 3 -Compress)"
    }
}
function Assert-RetainedSentinel([string]$Path, [string]$Value) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or [IO.File]::ReadAllText($Path) -ne $Value) { throw 'User-data sentinel changed or disappeared' }
}
function Assert-RemovedRegistration {
    $products = @(Get-InstalledProducts | Where-Object { $_.ProductName -in @('OpenAbstractions', 'Abstraction') })
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
        return [pscustomobject]@{ Images = @('jobd.exe','jobdw.exe'); Arguments = 'start'; Start = 'start'; Supervisor = @('jobd','jobdw'); Initializer = 'jobd.exe' }
    }
    if ([version]$Version -le [version]'0.1.7') {
        return [pscustomobject]@{ Images = @('jobdw.exe'); Arguments = 'start --runtime'; Start = 'start --runtime'; Supervisor = @('jobdw'); Initializer = 'jobd.exe' }
    }
    return [pscustomobject]@{ Images = @('openabstractionsw.exe'); Arguments = 'serve host'; Start = 'start'; Supervisor = @('openabstractionsw'); Initializer = '' }
}
function Initialize-PredecessorStore([string]$Tools, [string]$Version) {
    $initializer = (Get-PredecessorActivation $Version).Initializer
    # Legacy jobd status creates its store before start opens its log. From
    # 0.1.8, openabstractions start activates and readies the runtime itself;
    # status before start would correctly report that no runtime is listening.
    if ($initializer) { Invoke-Bounded (Join-Path $Tools $initializer) @('status') }
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
    $products = @(Get-InstalledProducts | Where-Object { $_.ProductName -in @('OpenAbstractions', 'Abstraction') })
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
'ok    programs, a user PATH entry, a Startup shortcut â€” and no service, no machine key, no task'
}
function Assert-InstalledPanelWebView2([string]$Tools, [string]$EvidencePath = 'webview2-availability.txt') {
    $panel = Join-Path $Tools 'Abstraction Panel.exe'
    if (-not (Test-Path -LiteralPath $panel)) { throw "Installed Panel missing: $panel" }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $panel
    $info.Arguments = '-check-webview2'
    $result = Invoke-FixtureProcess $info 15
    $answer = $result.Output.Trim()
    if ($result.ExitCode -eq 0 -and $answer -eq 'WebView2: available (native rendering untested)') {
        $answer | Set-Content -LiteralPath $EvidencePath
        return 'ok: installed Panel resolved the WebView2 runtime export; native rendering remains a separate check'
    }
    if ($result.ExitCode -eq 3 -and $answer -eq 'WebView2: unavailable (no Panel window)') {
        $answer | Set-Content -LiteralPath $EvidencePath
        return 'ok: installed Panel reported WebView2 unavailable; its window says so and opens no listener'
    }
    throw "Installed Panel WebView2 diagnostic returned exit $($result.ExitCode): $(Protect-DiagnosticText ($result.Output + $result.Diagnostics))"
}
function Assert-InstalledPanelShortcuts([string]$Tools, [string]$Package) {
    $target = [IO.Path]::GetFullPath((Join-Path $Tools 'Abstraction Panel.exe'))
    $shell = New-Object -ComObject WScript.Shell
    # The exact candidate package declares entry names and routes. Keep the
    # legacy --page setup route testable while product naming evolves.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Package, 0)
    $directoryView = $database.OpenView('SELECT `DefaultDir` FROM `Directory` WHERE `Directory`=''AbstractionMenuFolder''')
    $directoryView.Execute()
    $directoryRow = $directoryView.Fetch()
    if (-not $directoryRow) { throw 'Package Panel menu directory is absent' }
    $directoryName = $directoryRow.StringData(1).Split('|')[-1]
    [void]$directoryView.Close()
    if ($directoryName -notin @('OpenAbstractions', 'Abstraction')) { throw 'Unknown package Panel menu directory' }
    $menu = Join-Path (Get-ProfileFolder Programs) $directoryName
    $view = $database.OpenView('SELECT `Name`, `Arguments` FROM `Shortcut` WHERE `Target`=''[#panel.exe]'' AND `Directory`=''AbstractionMenuFolder''')
    $view.Execute()
    $cases = @()
    while ($row = $view.Fetch()) {
        $name = $row.StringData(1).Split('|')[-1]
        $arguments = $row.StringData(2)
        $page = if ($arguments -ceq '') { 'apps' } elseif ($arguments -ceq '--page setup') { 'setup' } else { throw 'Unknown package-declared Panel entry route' }
        $cases += @{name=$name; args=$arguments; page=$page}
    }
    $view.Close()
    if (-not @($cases | Where-Object { $_.page -eq 'apps' }).Count) { throw 'Package lacks ordinary Panel entry' }
    $proofs = @()
    foreach ($case in $cases) {
        $path = Join-Path $menu ($case.name + '.lnk')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Installed Panel/Setup Start-menu shortcut missing' }
        $shortcut = $shell.CreateShortcut($path)
        if ([IO.Path]::GetFullPath($shortcut.TargetPath) -ne $target -or
            $shortcut.Arguments -cne $case.args -or
            [IO.Path]::GetFullPath($shortcut.WorkingDirectory).TrimEnd([char[]]'\/') -ne [IO.Path]::GetFullPath($Tools).TrimEnd([char[]]'\/')) {
            throw 'Installed Panel/Setup shortcut target, arguments or working directory differ'
        }
        # Use actual installed shortcut values. The native launch owner invalidates
        # standard handles regardless of the fixture's own console/capture mode.
        $proofs += Invoke-InstalledPanelShortcutSmoke $shortcut.TargetPath $shortcut.Arguments $shortcut.WorkingDirectory $case.page
    }
    $proofs | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath 'installed-panel-shortcuts.json' -Encoding UTF8
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
# Observe the installer-started presenter before the short action window opens.
# This check never starts it: a missing presenter is an installation failure.
function Assert-InstalledNativePresenter([string]$Panel, [int]$Seconds = 10) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $session = (Get-Process -Id $PID).SessionId
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $observed = @()
    do {
        $observed = @(Get-CimInstance Win32_Process -Filter "Name='Abstraction Panel.exe'" | Where-Object {
            $_.ExecutablePath -eq $Panel -and $_.SessionId -eq $session -and
            $_.CommandLine -match '(?:^|\s)--?background(?:\s|$)' -and
            (Get-ProcessOwnerSid $_) -eq $sid
        })
        if ($observed.Count -eq 1) {
            $first = $observed[0]
            Start-Sleep -Milliseconds 3000
            $survivor = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([uint32]$first.ProcessId)" | Where-Object {
                $_.ExecutablePath -eq $Panel -and $_.SessionId -eq $session -and
                $_.CreationDate -eq $first.CreationDate -and
                $_.CommandLine -match '(?:^|\s)--?background(?:\s|$)' -and
                (Get-ProcessOwnerSid $_) -eq $sid
            })
            if ($survivor.Count -eq 1) {
                [ordered]@{ path=$Panel; pid=[uint32]$first.ProcessId; sessionId=$session;
                    account=$sid; observedAt=[DateTime]::UtcNow.ToString('o'); survivedMilliseconds=3000 } |
                    ConvertTo-Json | Set-Content -LiteralPath 'native-presenter-preflight.json' -Encoding UTF8
                return
            }
        }
        if ([DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Installed background native presenter missing or exited before the action window; preserve installation evidence'
}
function Assert-SelectedAppFile($Binding, [switch]$AllowEmpty) {
    $path = if ($Binding.file) { $Binding.file } else { $Binding.path }
    if (-not [IO.Path]::IsPathRooted($path) -or $Binding.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        ($Binding.bytes -isnot [int] -and $Binding.bytes -isnot [long]) -or $Binding.bytes -lt 0 -or
        ($Binding.bytes -eq 0 -and -not $AllowEmpty)) {
        throw 'Selected application file needs an absolute path and exact bytes'
    }
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Selected application file is not plain' }
    $parent = $item.Directory
    while ($parent) {
        if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Selected application ancestor is redirected' }
        $parent = $parent.Parent
    }
    if ($item.Length -ne $Binding.bytes -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Binding.sha256) {
        throw 'Selected application bytes changed'
    }
    return $item.FullName
}
function Get-SelectedAppPlan($Native) {
    if (-not $Native.core.adopter_journey) { return @() }
    $script:SelectedFileIdentityProbe=Get-SelectedIdentityProbe $Native
    $chain = $Native.selected_app_chain
    $readback = $Native.selected_app_readback
    if (-not $chain -or $chain.version -cne $Native.version -or -not $readback) {
        throw 'Automated adopter execution needs the authenticated selected application chain and compiled readback'
    }
    $required = @($Native.core.adopter_journey.scope.adopters | Where-Object { 'windows-x64' -in $_.targets } | ForEach-Object { $_.id } | Sort-Object)
    if ($Native.adopter_case -ceq 'opencode') { $required = @($required | Where-Object { $_ -ceq 'opencode' }) }
    $ids = @($chain.apps | ForEach-Object { $_.id } | Sort-Object)
    if (-not $required.Count -or ($required -join ',') -cne ($ids -join ',') -or @($ids | Select-Object -Unique).Count -ne $ids.Count -or
        (@($readback.PSObject.Properties.Name | Sort-Object) -join ',') -cne ($ids -join ',')) { throw 'Selected application chain differs from accepted adopter membership' }
    $plans = @()
    foreach ($app in $chain.apps) {
        $package = Assert-SelectedAppFile $app
        if ([IO.Path]::GetExtension($package) -ine '.msi') { throw 'Selected application integration is not an MSI' }
        $compiled = $readback.PSObject.Properties[$app.id].Value
        if ($compiled.scope -cne 'perUser' -or $compiled.expected_payload.schema -ne 1 -or
            $compiled.expected_payload.msi.sha256 -cne $app.sha256 -or $compiled.expected_payload.msi.bytes -ne $app.bytes -or
            -not @($compiled.expected_payload.files).Count) { throw 'Selected application compiled identity/payload missing' }
        $productCode=Get-PackageProperty $package ProductCode
        $upgradeCode=Get-PackageProperty $package UpgradeCode
        if ($productCode -cnotmatch '^\{[0-9A-Fa-f-]{36}\}$' -or
            ($compiled.product_code -and $compiled.product_code -cne $productCode) -or
            ($compiled.upgrade_code -and $compiled.upgrade_code -cne $upgradeCode)) { throw 'Selected MSI compiled product identity changed' }
        $compiled|Add-Member -NotePropertyName product_code -NotePropertyValue $productCode -Force
        $compiled|Add-Member -NotePropertyName upgrade_code -NotePropertyValue $upgradeCode -Force
        $files = @(Get-SelectedAppComponents $package $compiled.expected_payload)
        if ($app.host) {
            foreach ($binding in @($app.host,$app.host.preflight,$app.host.preparation) | Where-Object { $_ }) { $null = Assert-SelectedAppFile $binding }
            if (-not $compiled.host) { throw 'Selected official host lifecycle readback missing' }
            if($app.id -ceq 'opencode' -and -not $app.host.preflight){throw 'OpenCode needs its selected canonical-destination preflight before the official host'}
            $hostReadback=$compiled.host
            if (($hostReadback.executable.basename -and ($hostReadback.executable.basename -match '[/\\:]' -or [IO.Path]::GetExtension($hostReadback.executable.basename) -ine '.exe')) -or
                $hostReadback.executable.sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Selected official host source executable identity missing' }
            $null=Get-SelectedHostRemoval @{app=$app;compiled=$compiled}
        }
        $related=@($upgradeCode)
        $installer=New-Object -ComObject WindowsInstaller.Installer
        $database=$installer.OpenDatabase($package,0)
        $view=$database.OpenView('SELECT `Name` FROM `_Tables` WHERE `Name`=''Upgrade''');$view.Execute()
        $hasUpgrade=$null -ne $view.Fetch();$view.Close()
        if($hasUpgrade){
            $view=$database.OpenView('SELECT `UpgradeCode` FROM `Upgrade`');$view.Execute()
            while($row=$view.Fetch()){$related+= $row.StringData(1)};$view.Close()
        }
        $related=@($related|Where-Object{$_}|Sort-Object -Unique)
        if(@($related|Where-Object{$_ -cnotmatch '^\{[0-9A-Fa-f-]{36}\}$'}).Count){throw 'Selected MSI related-product identity malformed'}
        $plans += @{app=$app;compiled=$compiled;package=$package;files=$files;related_upgrade_codes=$related}
    }
    Assert-SelectedAppProductsAbsent $plans
    return $plans
}
function Assert-SelectedAppProductsAbsent($Plans) {
    $installer=New-Object -ComObject WindowsInstaller.Installer
    foreach($plan in $Plans){
        if(@($installer.ProductsEx($plan.compiled.product_code,'',7)).Count){throw 'Preexisting application integration is protected'}
        foreach($code in @($plan.related_upgrade_codes)){
            # RelatedProducts includes installed/advertised current-user and
            # machine products, the contexts this ordinary per-user MSI can affect.
            if(@($installer.RelatedProducts($code)).Count){throw 'Preexisting related application integration is protected'}
        }
    }
}
function Get-SelectedAppComponents([string]$Package, $Expected) {
    # Measure File/Component from the same authenticated MSI. Dynamic HostFolder
    # destinations are resolved by Windows Installer after installation.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($Package,0)
    $components = @{}
    $view = $database.OpenView('SELECT `Component`, `ComponentId`, `KeyPath`, `Attributes` FROM `Component`');$view.Execute()
    while ($row = $view.Fetch()) {
        $components[$row.StringData(1)] = @{guid=$row.StringData(2);key=$row.StringData(3);attributes=[int]$row.StringData(4)}
    }
    $view.Close()
    $found = @{}
    $view = $database.OpenView('SELECT `File`, `Component_`, `FileName` FROM `File`');$view.Execute()
    while ($row = $view.Fetch()) {
        $id=$row.StringData(1);$name=($row.StringData(3) -split '\|')[-1]
        if ($found.ContainsKey($id) -or $name -match '[/\\:]' -or $name -in @('','..','.')) { throw 'Ambiguous selected MSI File identity' }
        $found[$id]=@{id=$id;component=$row.StringData(2);name=$name}
    }
    $view.Close()
    if ((@($found.Keys|Sort-Object)-join ',') -cne (@($Expected.files|ForEach-Object{$_.id}|Sort-Object)-join ',')) { throw 'Selected MSI File table differs from original compiled readback' }
    foreach ($file in $Expected.files) {
        $measured=$found[$file.id];$component=$components[$measured.component]
        if (-not $component -or $component.guid -notmatch '^\{[0-9A-Fa-f-]{36}\}$' -or ($component.attributes -band 4) -or
            -not $found.ContainsKey($component.key) -or $found[$component.key].component -cne $measured.component) {
            throw 'Selected MSI component has no unambiguous file key path'
        }
        @{id=$file.id;component=$component.guid;key_name=$found[$component.key].name;name=$measured.name;sha256=$file.sha256;bytes=$file.bytes;declared_path=$file.path}
    }
}
function Get-SelectedAppInstalledFiles($Plan) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $actual = @()
    foreach ($file in $Plan.files) {
        $key = $installer.ComponentPath($Plan.compiled.product_code,$file.component)
        if (-not [IO.Path]::IsPathRooted($key) -or [IO.Path]::GetFileName($key) -cne $file.key_name) { throw 'Installed MSI component path differs from its measured File key' }
        $binding=@{path=(Join-Path ([IO.Path]::GetDirectoryName($key)) $file.name);sha256=$file.sha256;bytes=$file.bytes}
        $null=Assert-SelectedAppFile $binding -AllowEmpty
        $actual += @{id=$file.id;component=$file.component;component_path=$key;path=$binding.path;sha256=$binding.sha256;bytes=$binding.bytes;identity=(Get-SelectedFileIdentity $binding.path)}
    }
    if (@($actual.path|Select-Object -Unique).Count -ne $actual.Count) { throw 'Installed selected MSI files overlap' }
    return $actual
}
function Get-SelectedHostRegistry($Plan) {
    $rows=@()
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)) {
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            try {
                $key=$base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall\'+$Plan.app.host.arp_id)
                if ($key) {
                    try { $rows+=@{hive=$hive.ToString();view=$view.ToString();version=$key.GetValue('DisplayVersion');icon=$key.GetValue('DisplayIcon')} }
                    finally { $key.Dispose() }
                }
            } finally { $base.Dispose() }
        }
    }
    return $rows
}
function Get-SelectedAppRegistryBaseline {
    $rows=@()
    foreach($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryHive]::LocalMachine)) {
        foreach($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)) {
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            try {
                $root=$base.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall')
                if($root) {
                    try {
                        $names=@($root.GetSubKeyNames()|Sort-Object)
                        if($names.Count -gt 4096){throw 'Installed product baseline exceeds fixture bound'}
                        foreach($name in $names) {
                            $key=$root.OpenSubKey($name)
                            if(-not $key){throw 'Installed product baseline changed during read'}
                            try {
                                $row=[ordered]@{hive=$hive.ToString();view=$view.ToString();key=$name}
                                foreach($field in @('DisplayName','DisplayVersion','Publisher','InstallLocation','DisplayIcon','UninstallString','QuietUninstallString')){$row[$field]=$key.GetValue($field)}
                                $rows+=$row
                            } finally {$key.Dispose()}
                        }
                    } finally {$root.Dispose()}
                }
            } finally {$base.Dispose()}
        }
    }
    return ,$rows
}
function Assert-SelectedHost($Plan) {
    $expected=$Plan.host_observed
    if(-not $expected){$expected=$Plan.compiled.host.prior}
    if(-not $expected){throw 'Preexisting official host needs independently authenticated prior installed readback'}
    $rows=@(Get-SelectedHostRegistry $Plan)
    $view=if($Plan.app.host.arp_win64){'Registry64'}else{'Registry32'}
    if (-not @($rows|Where-Object{$_.view -ceq $view}).Count -or
        @($rows|Where-Object{$_.hive -cne 'CurrentUser' -or $_.version -cne $Plan.app.host.arp_version -or $_.icon -cne $expected.display_icon}).Count) { throw 'Official host registration differs or is ambiguous' }
    if (-not [IO.Path]::IsPathRooted($expected.root) -or -not @($expected.files).Count) { throw 'Official host installed closure missing' }
    $root=[IO.Path]::GetFullPath($expected.root).TrimEnd('\')
    foreach($file in $expected.files) {
        $path=Assert-SelectedAppFile $file
        if(-not $path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Official host file escaped its selected root'}
    }
    $inventory=@(Get-SelectedHostInventory $root)
    if((@($inventory.path|Sort-Object)-join '|') -cne (@($expected.files.path|Sort-Object)-join '|')){throw 'Official host has unexplained added or missing content'}
    foreach($file in $expected.files) {
        $actual=@($inventory|Where-Object{$_.path -ieq $file.path})
        if($actual.Count -ne 1 -or ($file.identity -and $actual[0].identity -cne $file.identity)){throw 'Official host file identity changed'}
    }
    $program=Assert-SelectedAppFile $expected.executable
    if([IO.Path]::GetDirectoryName($program) -ine $root){throw 'Official host executable outside selected root'}
    $signature=Get-AuthenticodeSignature -LiteralPath $program
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $expected.signer_thumbprint){throw 'Official host publisher differs'}
    return @{root=$root;registry=$rows;executable=$expected.executable;files=$expected.files}
}
function Get-SelectedHostInventory([string]$Root) {
    $files=@();$pending=New-Object 'Collections.Generic.Queue[string]';$pending.Enqueue($Root);$count=0
    while($pending.Count) {
        foreach($item in @(Get-ChildItem -LiteralPath $pending.Dequeue() -Force)) {
            if(++$count -gt 20000 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Official host installed tree exceeds bound or contains redirection'}
            if($item.PSIsContainer){$pending.Enqueue($item.FullName)}else{
                $files+=@{path=$item.FullName;sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$item.Length;identity=(Get-SelectedFileIdentity $item.FullName)}
            }
        }
    }
    return $files
}
function Assert-SelectedHostStopped([string]$Root) {
    $prefix=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    foreach($process in @(Get-CimInstance Win32_Process)) {
        if($process.ExecutablePath -and $process.ExecutablePath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Selected official host still has a process; retain it without termination'
        }
    }
}
function Get-SelectedHostRemoval($Plan) {
    $policy=$Plan.compiled.host.fixture_removal
    $names=@{opencode='Uninstall OpenCode.exe';comfyui='Uninstall Comfy Desktop.exe'}
    if(-not $policy -or (@($policy.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'basename,profile' -or
        $policy.profile -cne 'nsis-current-user' -or -not $names.ContainsKey($Plan.app.id) -or $policy.basename -cne $names[$Plan.app.id]) {
        throw 'Unknown source-owned official host fixture removal policy'
    }
    # The arguments are source-owned. Registry command text is never evaluated.
    $root=if($Plan.host_observed){$Plan.host_observed.root}elseif($Plan.compiled.host.prior){$Plan.compiled.host.prior.root}else{$null}
    return @{path=$(if($root){Join-Path $root $policy.basename}else{$null});basename=$policy.basename;arguments=@('/currentuser','/S')}
}
function Get-NewSelectedHost($Plan,$BeforeRoots,[DateTime]$Started,[string]$SupplierThumbprint) {
    $rows=@(Get-SelectedHostRegistry $Plan)
    $view=if($Plan.app.host.arp_win64){'Registry64'}else{'Registry32'}
    if(-not $rows.Count -or @($rows|Where-Object{$_.hive -cne 'CurrentUser' -or $_.version -cne $Plan.app.host.arp_version}).Count -or
        -not @($rows|Where-Object{$_.view -ceq $view}).Count -or @($rows.icon|Select-Object -Unique).Count -ne 1){throw 'New official host registration is absent or conflicting'}
    $icon=[string]$rows[0].icon
    if($icon.EndsWith(',0')){$icon=$icon.Substring(0,$icon.Length-2)}
    $icon=$icon.Trim('"')
    if(-not[IO.Path]::IsPathRooted($icon) -or [IO.Path]::GetExtension($icon) -ine '.exe' -or
        ($Plan.compiled.host.executable.basename -and [IO.Path]::GetFileName($icon) -cne $Plan.compiled.host.executable.basename)){throw 'Official host DisplayIcon differs from source executable'}
    $root=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($icon))
    if($Plan.requested_host_root) {
        if($root -ine $Plan.requested_host_root){throw 'Official host ignored or truncated the controlled fixture destination'}
    } else {
        $parent=Join-Path (Get-ProfileFolder LocalApplicationData) 'Programs'
        if([IO.Path]::GetDirectoryName($root) -ine [IO.Path]::GetFullPath($parent) -or $root -iin $BeforeRoots){throw 'Official host root was not absent in the native Programs baseline'}
    }
    $directory=Get-Item -LiteralPath $root
    if($directory.CreationTimeUtc -lt $Started.ToUniversalTime() -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Official host root predates install or is redirected'}
    $files=@(Get-SelectedHostInventory $root)
    $program=@($files|Where-Object{$_.path -ieq $icon})
    $removal=Get-SelectedHostRemoval $Plan
    $remover=@($files|Where-Object{$_.path -ieq (Join-Path $root $removal.basename)})
    if($program.Count -ne 1 -or $remover.Count -ne 1){throw 'New official host executable/remover missing'}
    $signatures=@()
    foreach($binding in @($program[0],$remover[0])) {
        $signature=Get-AuthenticodeSignature -LiteralPath $binding.path
        if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $SupplierThumbprint){throw 'Installed host/remover publisher differs from selected supplier installer'}
        $signatures+=@{path=$binding.path;status=[string]$signature.Status;thumbprint=$signature.SignerCertificate.Thumbprint;subject=$signature.SignerCertificate.Subject;observed_at=[DateTime]::UtcNow.ToString('o')}
    }
    $pin=$Plan.compiled.host.executable
    if(($pin.sha256 -and $pin.sha256 -cne $program[0].sha256) -or ($pin.bytes -and $pin.bytes -ne $program[0].bytes)){throw 'Installed host differs from declared source executable pin'}
    return @{root=$root;display_icon=$rows[0].icon;files=$files;executable=$program[0];remover=$remover[0];signer_thumbprint=$SupplierThumbprint;signatures=$signatures;registry=$rows;root_identity=(Get-SelectedFileIdentity $root);observed_at=[DateTime]::UtcNow.ToString('o')}
}
function Get-SelectedIdentityProbe($Native) {
    $sdk=$Native.sdk_smokes
    if(-not $sdk -or -not [IO.Path]::IsPathRooted($sdk.directory) -or -not $sdk.manifest -or -not $sdk.sources){throw 'Authenticated current SDK manifest and selected source graph required before mutation'}
    $manifestPath=Assert-SelectedAppFile $sdk.manifest
    if($manifestPath -ine (Join-Path ([IO.Path]::GetFullPath($sdk.directory)) 'manifest.json')){throw 'SDK manifest differs from the selected preparation root'}
    $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
    if($manifest.schema -ne 1 -or -not $manifest.files -or -not $manifest.sources -or
        (@($manifest.sources.PSObject.Properties.Name|Sort-Object)-join ',') -cne (@($sdk.sources.PSObject.Properties.Name|Sort-Object)-join ',') -or
        -not $sdk.sources.PSObject.Properties['abstraction-identity']){throw 'SDK selected identity graph missing or changed'}
    foreach($name in $sdk.sources.PSObject.Properties.Name){
        $actual=$manifest.sources.PSObject.Properties[$name].Value;$expected=$sdk.sources.PSObject.Properties[$name].Value
        if((@($actual.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'commit,module,version' -or
            $actual.module -cne $expected.module -or $actual.version -cne $expected.version -or $actual.commit -cne $expected.commit -or
            $expected.commit -cnotmatch '^[0-9a-f]{40}$'){throw 'SDK manifest differs from independently selected source graph'}
    }
    $pin=$manifest.files.PSObject.Properties['go_probe.exe']
    if(-not $pin -or $pin.Value -cnotmatch '^[0-9a-f]{64}$'){throw 'Selected SDK has no canonical identity probe pin'}
    $path=Join-Path ([IO.Path]::GetFullPath($sdk.directory)) 'go_probe.exe'
    $helper=@{path=$path;sha256=$pin.Value;bytes=(Get-Item -LiteralPath $path -ErrorAction Stop).Length}
    $null=Assert-SelectedAppFile $helper
    return @{helper=$helper;manifest=$sdk.manifest;sources=$sdk.sources}
}
function Assert-J1SelectionInputs($Native) {
    if(-not $Native.core.adopter_journey){return}
    $spec=$Native.j1_selection
    if(-not $spec -or $spec.schema -ne 1 -or $spec.source_sha -cne $Native.core.source_sha -or
        (@($spec.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'node,schema,sdk,source_sha') {throw 'J1 explicit current SDK and pinned Node test tool required before installation'}
    $null=Assert-SelectedAppFile $spec.node
    $sdk=$spec.sdk
    $null=Get-SelectedIdentityProbe ([pscustomobject]@{sdk_smokes=$sdk})
    $manifest=Get-Content -LiteralPath $sdk.manifest.path -Raw|ConvertFrom-Json
    $root=[IO.Path]::GetFullPath($sdk.directory).TrimEnd('\')
    $pending=[Collections.Generic.Stack[string]]::new();$pending.Push($root)
    $seen=@{};$total=0L
    while($pending.Count){
        foreach($item in @(Get-ChildItem -LiteralPath $pending.Pop() -Force)){
            if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'J1 SDK redirected member'}
            if($item.PSIsContainer){$pending.Push($item.FullName);continue}
            if($item.FullName -ieq $sdk.manifest.path){continue}
            $name=$item.FullName.Substring($root.Length+1).Replace('\','/')
            $total+=$item.Length
            $pin=$manifest.files.PSObject.Properties[$name]
            if($total -gt 536870912 -or $seen.Count -ge 40000 -or -not $pin -or $pin.Value -cnotmatch '^[0-9a-f]{64}$'){throw 'J1 SDK closure missing or exceeds bound'}
            $null=Assert-SelectedAppFile @{path=$item.FullName;sha256=$pin.Value;bytes=$item.Length} -AllowEmpty
            $seen[$name]=$true
        }
    }
    if($seen.Count -ne @($manifest.files.PSObject.Properties).Count -or -not $seen.ContainsKey('j1_selection_probe.mjs')){throw 'J1 SDK closure differs'}
    return $spec
}
function Invoke-J1SelectionCollection($Native,$Program,$Runtime,[string]$Account,[string]$Directory) {
    $spec=Assert-J1SelectionInputs $Native
    $request=Join-Path $Directory 'j1-selection-request.json';$result=Join-Path $Directory 'j1-selection-result.json';$process=Join-Path $Directory 'j1-selection-process.json'
    foreach($path in @($request,$result,$process)){if(Test-Path -LiteralPath $path){throw 'J1 selection observation already exists'}}
    [IO.File]::WriteAllText($request,(@{schema=1;account=$Account;program=$Program;runtime=$Runtime}|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
    $probe=Join-Path $spec.sdk.directory 'j1_selection_probe.mjs'
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$spec.node.path
    $info.Arguments='"'+$probe+'" "'+$request+'" "'+$result+'"';$info.WorkingDirectory=$Directory
    # Explicit test-tool environment, with no endpoint/addon override or Node preload.
    $keep=@{};foreach($key in @('SystemRoot','WINDIR','COMSPEC','PATHEXT','PROCESSOR_ARCHITECTURE','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA')){if($info.EnvironmentVariables[$key]){$keep[$key]=$info.EnvironmentVariables[$key]}}
    $info.EnvironmentVariables.Clear();foreach($key in $keep.Keys){$info.EnvironmentVariables[$key]=$keep[$key]}
    $held=Invoke-FixtureProcess $info 45 -ObservationPath $process
    if($held.ExitCode -ne 0){throw 'J1 current SDK selection collector failed; inspect retained process observation'}
    $null=Assert-J1SelectionInputs $Native
    return @{request=@{path=$request;sha256=(Get-FileHash -LiteralPath $request -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $request).Length}
        result=@{path=$result;sha256=(Get-FileHash -LiteralPath $result -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $result).Length}
        process=@{path=$process;sha256=(Get-FileHash -LiteralPath $process -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $process).Length}}
}
function Get-SelectedFileIdentity([string]$Path) {
    if(-not $script:SelectedFileIdentityProbe -or -not [IO.Path]::IsPathRooted($Path) -or $Path.Contains('"') -or $Path -match '[\r\n]'){throw 'Selected canonical SDK identity probe and absolute safe path required'}
    $probe=$script:SelectedFileIdentityProbe
    $null=Assert-SelectedAppFile $probe.helper;$null=Assert-SelectedAppFile $probe.manifest
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$probe.helper.path;$info.Arguments='--file-identity "'+$Path+'"'
    $result=Invoke-FixtureProcess $info 10
    $null=Assert-SelectedAppFile $probe.helper;$null=Assert-SelectedAppFile $probe.manifest
    if($result.ExitCode -ne 0 -or $result.Output.Length -gt 4096 -or $result.Diagnostics){throw 'Canonical SDK file identity probe refused or exceeded its output bound'}
    $value=$result.Output|ConvertFrom-Json
    if((@($value.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'key,schema' -or
        ($value.schema -isnot [int] -and $value.schema -isnot [long]) -or $value.schema -ne 1 -or
        $value.key -isnot [string] -or [string]::IsNullOrWhiteSpace($value.key) -or $value.key.Length -gt 256 -or
        [regex]::Matches($result.Output,'"(?:schema|key)"\s*:').Count -ne 2){throw 'Canonical SDK file identity reply shape differs'}
    # Opaque canonical owner key. This path observation does not make later deletion atomic.
    return $value.key
}
function Assert-SelectedAppMutationSafe([string]$Evidence) {
    Assert-FixtureMutationSafe
    if($Evidence -and (Test-Path -LiteralPath $Evidence -PathType Leaf)){
        $journal=Get-Content -LiteralPath $Evidence -Raw|ConvertFrom-Json
        if($journal.process_closure -cne 'known' -or @($journal.apps|ForEach-Object{$_.steps}|Where-Object{$_.closure -cne 'known'}).Count){throw 'Selected installer transaction closure unknown; retain all installed state'}
    }
}
function Write-NativeFixtureClosure([string]$Directory) {
    $value=Get-FixtureProcessClosure
    foreach($path in @((Join-Path $Directory 'selected-app-chain.json'),(Join-Path $Directory 'native-core\adopter-process.json'))){
        if(Test-Path -LiteralPath $path -PathType Leaf){
            try{
                $proof=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
                if(($proof.PSObject.Properties['process_closure'] -and $proof.process_closure -cne 'known') -or
                    ($proof.PSObject.Properties['Closure'] -and $proof.Closure -cne 'known')){$value.closure='unknown'}
            }catch{$value.closure='unknown'}
        }
    }
    [IO.File]::WriteAllText((Join-Path $Directory 'fixture-process-closure.json'),($value|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
}
function Assert-NativeFixtureMutationSafe([string]$Directory,[switch]$RequireTerminal) {
    Assert-FixtureMutationSafe
    $path=Join-Path $Directory 'fixture-process-closure.json'
    if($RequireTerminal -and -not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'Native child transaction closure terminal missing; retain installed state'}
    if(Test-Path -LiteralPath $path -PathType Leaf){
        $value=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
        if($value.closure -cne 'known'){throw 'Native child transaction closure unknown; retain installed state'}
    }
    Assert-SelectedAppMutationSafe (Join-Path $Directory 'selected-app-chain.json')
    $path=Join-Path $Directory 'native-core\adopter-process.json'
    if(Test-Path -LiteralPath $path -PathType Leaf){
        $value=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
        if($value.Closure -cne 'known'){throw 'Native scene process closure unknown; retain installed state'}
    }
}
function Invoke-SelectedAppStep($Row,[string]$Program,[string[]]$Arguments,[int]$Seconds,$Journal,[string]$Evidence) {
    Assert-SelectedAppMutationSafe $Evidence
    $path=$Evidence+'.process-'+[Guid]::NewGuid().ToString('N')+'.json'
    $step=@{state='intent';closure='unknown';observation_path=$path;requested_file_name=$Program;requested_arguments=($Arguments -join ' ')}
    $Row.steps+=$step;$Journal.process_closure='unknown'
    $Journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
    $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$Program;$info.Arguments=$Arguments -join ' '
    $held=$null;$failure=$null
    try {$held=Invoke-FixtureProcess $info $Seconds -ObservationPath $path}
    catch {$failure=$_}
    finally {
        if(Test-Path -LiteralPath $path -PathType Leaf){
            try {
                $held=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
                $step.observation=@{path=$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $path).Length}
            }catch{$held=$null}
        }
        if($held){
            $step.state=$held.State;$step.process_id=$held.ProcessId;$step.creation_utc=$held.CreationUtc
            $step.started_at=$held.StartedUtc;$step.ended_at=$held.FinishedUtc;$step.exit_code=$held.ExitCode
            $step.use_shell_execute=$held.UseShellExecute;$step.actual_image=$held.ActualImage;$step.actual_image_status=$held.ActualImageStatus
            $step.direct_exited=$held.DirectExited;$step.output_closed=$held.OutputClosed;$step.failure=$held.Failure
            if($held.State -ceq 'completed' -and $held.Closure -ceq 'known' -and $held.DirectExited -and $held.OutputClosed -and
                $held.ProcessId -gt 0 -and $held.CreationUtc -and -not $held.CreationError -and $held.UseShellExecute -eq $false -and
                $held.RequestedFileName -ceq $Program -and $held.RequestedArguments -ceq ($Arguments -join ' ')){$step.closure='known'}
        }
        $Journal.process_closure=if(@($Journal.apps|ForEach-Object{$_.steps}|Where-Object{$_.closure -cne 'known'}).Count){'unknown'}else{'known'}
        if($Journal.process_closure -cne 'known'){$global:OAFixtureProcessClosureUnknown=$true}
        $Journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
    }
    if($failure){throw $failure}
    Assert-SelectedAppMutationSafe $Evidence
    if($held.ExitCode -ne 0){throw ('Selected process completed with failure '+$held.ExitCode)}
}
function Install-SelectedAppChain($Plans,[string]$Evidence,[string]$RequestPath) {
    if(Test-Path -LiteralPath $Evidence){throw 'Selected app attempt already exists; reconcile its exact ownership journal'}
    Assert-SelectedAppProductsAbsent $Plans
    if(-not[IO.Path]::IsPathRooted($RequestPath)){throw 'Original canonical native request required for selected installation'}
    $native=Get-Content -LiteralPath $RequestPath -Raw|ConvertFrom-Json
    $journal=@{state='installing';process_closure='known';apps=@();private_evidence=$true;registry_baseline=(Get-SelectedAppRegistryBaseline);fixture_owner=$script:fixtureOwner
        source_sha=$native.source_sha;tool_source=$native.tool_source;runtime_sha256=$native.runtime_sha256
        native_request=@{path=$RequestPath;sha256=(Get-FileHash -LiteralPath $RequestPath -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $RequestPath).Length}}
    foreach($plan in $Plans) {
        $installer=New-Object -ComObject WindowsInstaller.Installer
        if(@($installer.ProductsEx($plan.compiled.product_code,'',7)).Count){throw 'Preexisting application integration is protected'}
        $row=@{id=$plan.app.id;product_code=$plan.compiled.product_code;upgrade_code=$plan.compiled.upgrade_code;package=$plan.app;measured_components=$plan.files;install_attempted=$false;installed=$false;host_owned=$false;steps=@()}
        $journal.apps+= $row
        $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
        if($plan.app.host) {
            $null=Get-SelectedHostRemoval $plan
            $before=@(Get-SelectedHostRegistry $plan)
            if($before.Count) {
                $row.host=Assert-SelectedHost $plan;$row.host_reused=$true
            } else {
                $parent=Join-Path (Get-ProfileFolder LocalApplicationData) 'Programs'
                $beforeRoots=if(Test-Path -LiteralPath $parent){@(Get-ChildItem -LiteralPath $parent -Directory -Force -ErrorAction Stop|ForEach-Object{$_.FullName})}else{@()}
                $beforeRootIdentities=@(foreach($path in $beforeRoots){@{path=$path;identity=(Get-SelectedFileIdentity $path)}})
                $signature=Get-AuthenticodeSignature -LiteralPath $plan.app.host.file
                if($signature.Status -ne 'Valid'){throw 'Selected supplier installer has no valid publisher signature'}
                $supplierThumbprint=$signature.SignerCertificate.Thumbprint
                $row.supplier_signature=@{status=[string]$signature.Status;thumbprint=$supplierThumbprint;subject=$signature.SignerCertificate.Subject;sha256=$plan.app.host.sha256;observed_at=[DateTime]::UtcNow.ToString('o')}
                if($plan.compiled.host.signer_thumbprint -and $plan.compiled.host.signer_thumbprint -cne $supplierThumbprint){throw 'Selected supplier installer publisher differs from source policy'}
                # Record attempted ownership before starting the selected host.
                $row.host_owned=$true;$row.host_install_attempted=$true;$row.host_before_roots=$beforeRoots;$row.host_parent_baseline=$beforeRootIdentities;$row.host_started=[DateTime]::UtcNow
                if($plan.app.id -ceq 'comfyui') {
                    $temporary=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
                    if($temporary -match '\s'){throw 'Controlled NSIS destination needs the existing native no-space temporary path'}
                    $ancestor=Get-Item -LiteralPath $temporary -ErrorAction Stop
                    while($ancestor){
                        if(-not ($ancestor.Attributes -band [IO.FileAttributes]::Directory) -or ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Controlled fixture temporary parent is redirected'}
                        $ancestor=$ancestor.Parent
                    }
                    $fixtureParent=Join-Path $temporary ('oa-host-'+[Guid]::NewGuid().ToString('N'))
                    if(Test-Path -LiteralPath $fixtureParent){throw 'Fixture host parent already exists'}
                    New-Item -ItemType Directory -Path $fixtureParent|Out-Null
                    if((Get-Acl -LiteralPath $fixtureParent).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne
                        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'Controlled fixture parent is not owned by this user'}
                    $plan.requested_host_root=Join-Path $fixtureParent 'host'
                    $row.fixture_parent=$fixtureParent;$row.fixture_parent_identity=Get-SelectedFileIdentity $fixtureParent
                    $row.requested_host_root=$plan.requested_host_root
                    if(Test-Path -LiteralPath $plan.requested_host_root){throw 'Controlled fixture host destination already exists'}
                }
                $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
                if($plan.app.host.preflight){$null=Assert-SelectedAppFile $plan.app.host.preflight;Invoke-SelectedAppStep $row $plan.app.host.preflight.file @() 60 $journal $Evidence;$null=Assert-SelectedAppFile $plan.app.host.preflight}
                $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
                $null=Assert-SelectedAppFile $plan.app.host
                $hostArguments=@('/S','/currentuser')
                if($plan.requested_host_root){$hostArguments+=('/D='+$plan.requested_host_root)} # NSIS override LAST, with no spaces.
                Invoke-SelectedAppStep $row $plan.app.host.file $hostArguments 300 $journal $Evidence
                $null=Assert-SelectedAppFile $plan.app.host
                $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
                $row.host=Get-NewSelectedHost $plan $beforeRoots $row.host_started $supplierThumbprint
                $row.host.installation_mode=if($plan.requested_host_root){'controlled-nsis-destination'}else{'source-preflight-standard-destination'}
                $row.host.requested_root=$plan.requested_host_root
                $plan.host_observed=$row.host
                Assert-SelectedHostStopped $row.host.root
                $row.remover=$row.host.remover;$row.remover_identity=$row.host.remover.identity;$row.root_identity=$row.host.root_identity
                $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
            }
            if($plan.app.host.preparation){$null=Assert-SelectedAppFile $plan.app.host.preparation;Invoke-SelectedAppStep $row $plan.app.host.preparation.file @('--verify-only') 60 $journal $Evidence;$null=Assert-SelectedAppFile $plan.app.host.preparation}
        }
        $row.install_attempted=$true
        $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
        $null=Assert-SelectedAppFile $plan.app
        Invoke-SelectedAppStep $row msiexec.exe (Get-CandidateInstallArguments $plan.package $false ('selected-'+$plan.app.id+'-install.log')) 300 $journal $Evidence
        $null=Assert-SelectedAppFile $plan.app
        $row.installed=$true;$row.files=@(Get-SelectedAppInstalledFiles $plan)
        $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
    }
    $journal.state='installed';$journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
    return $journal
}
function Remove-SelectedAppChain($Plans,[string]$Evidence) {
    Assert-SelectedAppMutationSafe $Evidence
    if(-not(Test-Path -LiteralPath $Evidence -PathType Leaf)){throw 'Selected application ownership journal missing'}
    $journal=Get-Content -LiteralPath $Evidence -Raw|ConvertFrom-Json
    $failures=@()
    $rows=@($journal.apps)
    [array]::Reverse($rows)
    foreach($row in $rows) {
        try {
            $plan=@($Plans|Where-Object{$_.app.id -ceq $row.id})
            if($plan.Count -ne 1 -or $plan[0].compiled.product_code -cne $row.product_code){throw 'Selected application cleanup identity differs'}
            $plan=$plan[0]
            if($row.install_attempted) {
                $null=Assert-SelectedAppFile $plan.app
                $installer=New-Object -ComObject WindowsInstaller.Installer
                if(@($installer.ProductsEx($row.product_code,'',7)).Count) {
                    Invoke-SelectedAppStep $row msiexec.exe @('/x',"`"$($plan.package)`"",'/qn','/norestart','/l*v',('selected-'+$row.id+'-remove.log')) 300 $journal $Evidence
                }
                if(@($installer.ProductsEx($row.product_code,'',7)).Count){throw 'Selected application product survived removal'}
                foreach($file in @($row.files)){if(Test-Path -LiteralPath $file.path){throw 'Selected integration file survived removal'}}
            }
            if($row.host_owned) {
                if(-not $row.remover -or -not $row.remover_identity -or -not $row.root_identity){throw 'Host installation did not reach verified ownership; retain for reconciliation'}
                $plan.host_observed=$row.host
                $null=Assert-SelectedHost $plan
                Assert-SelectedHostStopped $row.host.root
                $removal=Get-SelectedHostRemoval $plan
                $null=Assert-SelectedAppFile $row.remover
                if($row.remover.path -ine $removal.path -or (Get-SelectedFileIdentity $removal.path) -cne $row.remover_identity -or
                    (Get-SelectedFileIdentity $row.host.root) -cne $row.root_identity){throw 'Newly owned host/remover identity changed'}
                $signature=Get-AuthenticodeSignature -LiteralPath $removal.path
                if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $row.host.signer_thumbprint){throw 'Newly owned remover publisher changed'}
                Invoke-SelectedAppStep $row $removal.path $removal.arguments 300 $journal $Evidence
                if(@(Get-SelectedHostRegistry $plan).Count){throw 'Official host registration survived fixture removal'}
                $root=$row.host.root
                if(Test-Path -LiteralPath $root) {
                    if((Get-SelectedFileIdentity $root) -cne $row.root_identity -or @(Get-ChildItem -LiteralPath $root -Force).Count){throw 'Official host left nonempty or replaced root; retain without retry'}
                    Remove-Item -LiteralPath $root # Verified empty original root, never recursive.
                }
                if(Test-Path -LiteralPath $root){throw 'Official host root survived fixture restoration'}
                if($row.fixture_parent) {
                    if((Get-SelectedFileIdentity $row.fixture_parent) -cne $row.fixture_parent_identity -or @(Get-ChildItem -LiteralPath $row.fixture_parent -Force).Count){throw 'Controlled fixture parent changed or is not empty'}
                    Remove-Item -LiteralPath $row.fixture_parent
                }
                $parent=Join-Path (Get-ProfileFolder LocalApplicationData) 'Programs'
                $afterRoots=if(Test-Path -LiteralPath $parent){@(Get-ChildItem -LiteralPath $parent -Directory -Force|ForEach-Object{$_.FullName})}else{@()}
                if((@($afterRoots|Sort-Object)-join '|') -cne (@($row.host_before_roots|Sort-Object)-join '|')){throw 'Original Programs directory baseline changed'}
                foreach($before in @($row.host_parent_baseline)){if((Get-SelectedFileIdentity $before.path) -cne $before.identity){throw 'Protected Programs directory identity changed'}}
            } elseif($row.host_reused) { $null=Assert-SelectedHost $plan }
            $row|Add-Member -NotePropertyName restored -NotePropertyValue $true -Force
        } catch { $failures+=$_.Exception.Message;try{Assert-SelectedAppMutationSafe $Evidence}catch{break} }
    }
    if((ConvertTo-Json -InputObject (Get-SelectedAppRegistryBaseline) -Depth 12 -Compress) -cne
       (ConvertTo-Json -InputObject $journal.registry_baseline -Depth 12 -Compress)){$failures+='Original installed product baseline changed'}
    $journal.state=if($failures.Count){'restoration_failed'}else{'restored'}
    $journal|Add-Member -NotePropertyName failures -NotePropertyValue $failures -Force
    $journal|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $Evidence -Encoding UTF8
    if($failures.Count){throw ('Selected app restoration incomplete: '+($failures -join ' | '))}
}
function Assert-NativeCore([string]$Central, [string]$Tools, [string]$PythonPath, [string]$RequestPath) {
    $native = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    if ($native.kind -ne 'local_msi' -or -not $native.core -or $native.core.source_sha -ne $native.source_sha) {
        throw 'Fixed native core request/source required'
    }
    $panel = Join-Path $Tools 'Abstraction Panel.exe'
    if ((Get-FileHash -LiteralPath $Central -Algorithm SHA256).Hash.ToLowerInvariant() -ne $native.runtime_sha256) {
        throw 'Native core runtime differs from exact MSI payload'
    }
    if ((Get-FileHash -LiteralPath $panel -Algorithm SHA256).Hash.ToLowerInvariant() -ne $native.core.panel_sha256) {
        throw 'Native core presenter differs from exact MSI payload'
    }
    Assert-InstalledNativePresenter $panel
    foreach ($row in @($native.core.go,$native.core.journey,$native.core.helper,$native.core.native_library,$native.core.python) + @($native.core.python_files)) {
        if ((Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $row.sha256 -or
            (Get-Item -LiteralPath $row.path).Length -ne $row.bytes) { throw 'Native core input changed' }
    }
    if ((Get-FileHash -LiteralPath $PythonPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $native.core.python.sha256) {
        throw 'Native core interpreter differs'
    }
    $directory = Join-Path (Get-Location) 'native-core'
    New-Item -ItemType Directory -Path $directory | Out-Null
    $env:PYTHONPATH = $native.core.pythonpath
    $env:PYTHONDONTWRITEBYTECODE = '1'
    $request = Join-Path $directory 'core-request.json'
    $session = @{ schema=1; platform='win32'; core=$native.core; evidence_directory=$directory
        native_request=@{path=$RequestPath;sha256=(Get-FileHash -LiteralPath $RequestPath -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $RequestPath).Length}
        runtime=@{path=$Central;sha256=$native.runtime_sha256;bytes=(Get-Item -LiteralPath $Central).Length}
        panel=@{path=$panel;sha256=$native.core.panel_sha256;bytes=(Get-Item -LiteralPath $panel).Length} }
    if ($native.core.adopter_journey) {
        $chain=Get-Content -LiteralPath (Join-Path (Get-Location) 'selected-app-chain.json') -Raw|ConvertFrom-Json
        if (-not $chain.fixture_owner) { throw 'J1 owner input missing: actual fixture account and KnownFolder observation' }
        # Raw installation and owner observations stay beside immutable core.
        # The shared helper constructs the context; a supplied context is not authority.
        $session.installed_chain=$chain
        $session.observations=@{fixture_owner=$chain.fixture_owner;runtime=$session.runtime;panel=$session.panel}
        if ($native.adopter_case -ceq 'opencode') {
            $session.observations.profile=Get-ProfileFolder UserProfile
        }
        $roles=$native.selected_app_readback.opencode.journey_payload_roles
        $cli=@($chain.apps|Where-Object{$_.id -ceq 'opencode'}|ForEach-Object{$_.files}|Where-Object{$_.id -ceq $roles.official_cli.id})
        if($cli.Count -ne 1){throw 'J1 exact installed official CLI member required'}
        $program=@{path=$cli[0].path;sha256=$cli[0].sha256;bytes=$cli[0].bytes}
        $session.observations.j1_selection=Invoke-J1SelectionCollection $native $program $session.runtime $chain.fixture_owner.sid $directory
    }
    $session | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $request -Encoding UTF8
    if ($native.core.adopter_journey) {
        if ($native.core.ordinary -or $native.acceptance.profile -cne 'automated' -or
            $native.core.adopter_journey.probe_source_sha256 -cne $native.core.helper.sha256) {
            throw 'Automated adopter journey requires its separate source-bound selection'
        }
        $result = Join-Path $directory 'adopter-journey-result.json'
        try {
            Invoke-Bounded $PythonPath @('-B',"`"$($native.core.helper.path)`"",'--adopter-journey-request',"`"$request`"") 600 -ObservationPath (Join-Path $directory 'adopter-process.json')
        } finally {
            # Retain failed/partial bytes before the ordinary lifecycle cleanup.
            if (Test-Path -LiteralPath $result -PathType Leaf) {
                Copy-Item -LiteralPath $result -Destination (Join-Path (Split-Path -Parent $RequestPath) 'adopter-journey-result.json')
            }
        }
        Assert-OrdinaryNativeClosure $RequestPath
        $proof = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        if ($proof.result -cne 'partial') { throw 'Automated adopter journey did not retain its partial disposition' }
        return
    }
    Invoke-Bounded $PythonPath @('-B',"`"$($native.core.journey.path)`"",'--native-request',"`"$request`"") 390
    $result = Join-Path $directory 'core-result.json'
    $proof = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
    if ($proof.result -ne 'pass' -or -not $proof.owned_children_exited) { throw 'Native core outcome incomplete' }
    Copy-Item -LiteralPath $result -Destination (Join-Path (Split-Path -Parent $RequestPath) 'core-result.json')
    if ($native.core.ordinary) {
        # The new scene has its own bound and receipt after the original short core.
        Invoke-Bounded $PythonPath @('-B',"`"$($native.core.helper.path)`"",'--ordinary-request',"`"$request`"") 600
        $ordinaryResult = Join-Path $native.core.ordinary.directory 'scene\ordinary-result.json'
        $ordinaryProof = Get-Content -LiteralPath $ordinaryResult -Raw | ConvertFrom-Json
        if ($ordinaryProof.result -ne 'pass' -or -not $ordinaryProof.owned_children_exited -or
            -not $ordinaryProof.native_owner_closed) { throw 'Actual ordinary native scene incomplete' }
        Assert-OrdinaryNativeClosure $RequestPath
        Copy-Item -LiteralPath $ordinaryResult -Destination (Join-Path (Split-Path -Parent $RequestPath) 'ordinary-result.json')
    }
}
function Get-UserFixtureSeconds([bool]$HasPredecessor, [bool]$HasOrdinary, [int]$Soak = 0) {
    if ($Soak -notin @(0,3600)) { throw 'Soak duration must be zero or 3600' }
    $seconds = if ($HasPredecessor) { 600 } else { 300 }
    if ($HasOrdinary) { $seconds += 600 }
    if ($Soak) { $seconds += $Soak + 185 }
    return $seconds
}
function Assert-OrdinaryNativeClosure([string]$RequestPath) {
    if (-not $RequestPath) { return }
    $native = Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    if ($native.core.adopter_journey) {
        $result = Join-Path (Split-Path -Parent $RequestPath) 'adopter-journey-result.json'
        if (-not (Test-Path -LiteralPath $result -PathType Leaf)) { throw 'Adopter journey closure unknown; retain installed recovery state' }
        $proof = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        $requestHash = (Get-FileHash -LiteralPath $RequestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($proof.native_request.path -cne $RequestPath -or $proof.native_request.sha256 -cne $requestHash -or
            $proof.core.source_sha -cne $native.source_sha -or $proof.runtime.sha256 -cne $native.runtime_sha256 -or
            $proof.core.helper.sha256 -cne $native.core.helper.sha256 -or -not $proof.owned_children_exited -or
            $proof.result -notin @('partial','failed')) { throw 'Adopter journey closure differs from selected native request' }
        foreach ($child in @($proof.commands | Where-Object { $_.pid })) {
            if (-not $child.exited -or (Get-CimInstance Win32_Process -Filter "ProcessId=$($child.pid)")) {
                throw 'Adopter journey child lifetime unknown; retain installed recovery state'
            }
        }
        return
    }
    if (-not $native.core.ordinary) { return }
    $result = Join-Path $native.core.ordinary.directory 'scene\ordinary-result.json'
    if (-not (Test-Path -LiteralPath $result -PathType Leaf)) {
        throw 'Ordinary native closure unknown; retain installed runtime/data and its protected recovery state for the operator'
    }
    $proof = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
    $requestHash = (Get-FileHash -LiteralPath $RequestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($proof.native_request.path -ne $RequestPath -or $proof.native_request.sha256 -ne $requestHash -or
        $proof.core.source_sha -ne $native.source_sha -or $proof.core.tool_source -ne $native.core.tool_source -or
        $proof.runtime.sha256 -ne $native.runtime_sha256 -or $proof.panel.sha256 -ne $native.core.panel_sha256) {
        throw 'Ordinary native closure receipt differs from this request/source/install; retain recovery state'
    }
    $launches = @($proof.commands | Where-Object { $_.operation -eq 'opencode-native' })
    $control = Join-Path (Get-ProfileFolder LocalApplicationData) 'openabstractions\runtime-v1\apps\opencode\session.json'
    if ($launches.Count -eq 0 -and -not (Test-Path -LiteralPath $control)) {
        if (-not $proof.native_owner_closed -or -not $proof.ordinary.cleanup_completed) {
            throw 'Ordinary scene interrupted before observed cleanup; retain install/data for the operator'
        }
        return
    }
    if ($launches.Count -ne 1 -or -not (Test-Path -LiteralPath $control -PathType Leaf)) {
        throw 'Actual native launch/control binding missing; retain install/data for the operator'
    }
    $record = Get-Content -LiteralPath $control -Raw | ConvertFrom-Json
    $launch = $launches[0]
    $closed = $proof.ordinary.native_closed
    if ($record.format -ne 1 -or -not $record.closed_job -or $record.phase -ne 'closed' -or
        $record.owner_pid -ne $launch.pid -or $record.owner_program -ne $proof.runtime.path -or
        $record.account -ne $native.core.ordinary.comfy.invoking_account -or
        -not $record.child_pid -or -not $record.child_start -or -not $record.owner_start -or
        -not $record.guest_program_id -or -not $record.package_root_id -or
        $record.id -ne $closed.id -or $record.owner_start -ne $closed.owner_start -or
        $record.child_start -ne $closed.child_start -or $record.guest_program_id -ne $closed.guest_program_id -or
        $launch.argv[0] -ne $proof.runtime.path -or $launch.argv[1] -ne 'opencode' -or $launch.argv[2] -ne 'open' -or
        $launch.argv[4] -ne $native.core.ordinary.roots.project -or
        $launch.argv[6] -ne $native.core.ordinary.opencode.program.path -or
        -not $launch.exited -or -not $proof.native_owner_closed) {
        throw 'Actual native owner closure is unbound or unknown; retain installed runtime/data for the operator'
    }
    # A reused PID is uncertain too. No live process at either recorded PID
    # can authorize removal of this launch's protected recovery state.
    foreach ($processId in @($record.owner_pid,$record.child_pid)) {
        if (Get-CimInstance Win32_Process -Filter "ProcessId=$processId") {
            throw 'A recorded native PID remains live or was reused; retain install/data for the operator'
        }
    }
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
        if ($product.ProductName -in @('OpenAbstractions', 'Abstraction')) { $items += "installed product $($product.ProductCode) $($product.VersionString) (context $($product.Context))" }
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
    if ($SdkSmokes -and (-not $CheckTools -or -not $NodePath)) { throw 'SDK smokes require -CheckTools and -NodePath' }
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
    $nativeRequest=Join-Path $ResultDirectory 'native-request.json'
    if(Test-Path -LiteralPath $nativeRequest -PathType Leaf){$preflight=Get-Content -LiteralPath $nativeRequest -Raw|ConvertFrom-Json;$null=Get-SelectedAppPlan $preflight;$null=Assert-J1SelectionInputs $preflight}
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
        if ($SoakSeconds) { $arguments += @('-SoakSeconds',$SoakSeconds,'-ExpectedRuntimeSha256',$ExpectedRuntimeSha256,'-ExpectedSupervisorSha256',$ExpectedSupervisorSha256,'-SoakRequestPath',"`"$SoakRequestPath`"") }
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
        $nativeRequest = Join-Path $ResultDirectory 'native-request.json'
        $hasOrdinary = $false
        if (Test-Path -LiteralPath $nativeRequest -PathType Leaf) {
            $request = Get-Content -LiteralPath $nativeRequest -Raw | ConvertFrom-Json
            if ($request.core) { $arguments += @('-NativeCoreRequest',"`"$nativeRequest`"") }
            $hasOrdinary = [bool]($request.core.ordinary -or $request.core.adopter_journey)
        }
    if ($SdkSmokes) {
        Copy-Item -LiteralPath (Resolve-Path -LiteralPath $SdkSmokes).Path -Destination (Join-Path $directory 'sdk-smokes') -Recurse
        # The invoking local account owns this copy; hosted Verify uses a separate
        # disposable SID and protects that copy before it starts the child.
        $arguments += @('-SdkSmokes',"`"$directory\sdk-smokes`"",'-NodePath',"`"$NodePath`"")
        }
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = 'powershell.exe'
        $info.Arguments = $arguments -join ' '
        $info.WorkingDirectory = $directory
        $info.EnvironmentVariables['OA_FIXTURE_LOCAL_ACCOUNT'] = $sid
        $child = Invoke-FixtureProcess $info (Get-UserFixtureSeconds ([bool]$PredecessorMsiPath) $hasOrdinary $SoakSeconds) -ObservationPath (Join-Path $directory 'local-account-process.json')
        $child.Output | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.log')
        $child.Diagnostics | Set-Content -Encoding UTF8 (Join-Path $directory 'fixture.err')
        if ($child.ExitCode -ne 0) { throw "Local-account fixture exited $($child.ExitCode); inspect $directory" }
        Assert-RuntimeRemoved $sid (Join-Path $directory 'account-removal-remaining.json')
    } catch { $failure = $_ } finally {
        $cleanup = @()
        $canRemoveFixtureData = $true
        if((Get-FixtureProcessClosure).closure -cne 'known'){Write-NativeFixtureClosure $directory}
        try { Assert-NativeFixtureMutationSafe $directory -RequireTerminal }
        catch {$canRemoveFixtureData=$false;$cleanup+=$_.Exception.Message}
        if (Test-Path -LiteralPath $nativeRequest -PathType Leaf) {
            try { Assert-OrdinaryNativeClosure $nativeRequest }
            catch {
                $canRemoveFixtureData = $false; $cleanup += $_.Exception.Message
                Write-Warning ('Ordinary native closure UNKNOWN; retain installed runtime/data: ' + (Protect-DiagnosticText $_.Exception.Message)) -WarningAction Continue
            }
        }
        if ($canRemoveFixtureData -and -not $dataExisted -and (Test-Path -LiteralPath $data)) {
            try { Remove-Item -LiteralPath $data -Recurse -Force } catch { $cleanup += "data folder $data`: $($_.Exception.Message)" }
        } elseif ($canRemoveFixtureData -and (Test-Path -LiteralPath $sentinel)) {
            try { Remove-Item -LiteralPath $sentinel -Force } catch { $cleanup += "sentinel $sentinel`: $($_.Exception.Message)" }
        }
        foreach ($copy in 'package.msi','predecessor.msi','failing-upgrade.msi','failing-same-version.msi') {
            $path = Join-Path $directory $copy
            try { if ($canRemoveFixtureData -and (Test-Path -LiteralPath $path)) { Remove-Item -LiteralPath $path -Force } } catch { $cleanup += "package copy $path`: $($_.Exception.Message)" }
        }
        try { $left = & $footprint } catch { $left = @("footprint unreadable: $($_.Exception.Message)") }
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
    if($NativeCoreRequest){$preflight=Get-Content -LiteralPath $NativeCoreRequest -Raw|ConvertFrom-Json;$null=Get-SelectedAppPlan $preflight;$null=Assert-J1SelectionInputs $preflight}
    if ($Unscoped -and $PredecessorMsiPath) { throw 'Unscoped verification installs a fresh package and takes no predecessor' }
    if (($PredecessorElsewhere -or $FailUpgrade) -and -not $PredecessorMsiPath) { throw 'PredecessorElsewhere and FailUpgrade qualify an upgrade and need -PredecessorMsiPath' }
    if ($FailSameVersion -and ($PredecessorMsiPath -or $Unscoped -or $CheckTools)) { throw 'FailSameVersion installs the candidate as its own predecessor and takes no other variant' }
    $env:ABSTRACTION_RUNTIME_ENDPOINT = $null
    $env:ABSTRACTION_STORE = $null
    $env:MODELGET_STORE = $null
    $localAppData = Get-ProfileFolder LocalApplicationData
    $tools = Join-Path $localAppData 'Programs\OpenAbstractions\tools'
    $script:fixtureOwner=@{sid=$identity.User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;
        nonadmin=(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator));
        local_app_data=$localAppData;tools=$tools}
    $installed = $false
    $installAttempted = $false
    $predecessorAttempted = $false
    $previousProcesses = @()
    $sentinel = $null
    $failure = $null
    $closureFailure = $null
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
            Initialize-PredecessorStore $predecessorTools $PredecessorVersion
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
            $expectedUpgradeFailure = ''
            try { Invoke-Bounded msiexec.exe (Get-CandidateInstallArguments $failingPackage $false 'failed-upgrade.log') 300 }
            catch { $expectedUpgradeFailure = $_.Exception.Message }
            if ($expectedUpgradeFailure -notmatch 'msiexec\.exe exited 1603') { throw "The forced upgrade failure did not end with 1603: $expectedUpgradeFailure" }
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
            if ($CheckTools -or $Unscoped) {
                Assert-InstalledUserTools $tools
                Assert-InstalledPanelWebView2 $tools
                Assert-InstalledPanelShortcuts $tools $MsiPath
            }
            if ($Unscoped) { Assert-SingleUserScope }
            $central = Join-Path $tools 'openabstractions.exe'
            Assert-RuntimeReady $central post-install-status
            if ($CheckTools) { Assert-ServiceDownload $central $PythonPath }
            if ($NativeCoreRequest) {
                $native=Get-Content -LiteralPath $NativeCoreRequest -Raw|ConvertFrom-Json
                $selectedPlans=@(Get-SelectedAppPlan $native)
                if($selectedPlans.Count) {
                    $selectedEvidence=Join-Path (Get-Location) 'selected-app-chain.json'
                    if(Test-Path -LiteralPath $selectedEvidence){throw 'Selected app attempt already exists; reconcile it before another install'}
                    $selectedSceneAttempted=$false
                    try {
                        $null=Install-SelectedAppChain $selectedPlans $selectedEvidence $NativeCoreRequest
                        $selectedSceneAttempted=$true
                        if($native.core.adopter_journey) {
                            Assert-InstalledJ1Runtime $central $tools $PythonPath $NativeCoreRequest $selectedEvidence $ExpectedSid
                        } else { Assert-NativeCore $central $tools $PythonPath $NativeCoreRequest }
                    } finally {
                        # Unknown child closure retains installed state and its journal.
                        if($selectedSceneAttempted){Assert-OrdinaryNativeClosure $NativeCoreRequest}
                        if(Test-Path -LiteralPath $selectedEvidence){Remove-SelectedAppChain $selectedPlans $selectedEvidence}
                    }
                } else { Assert-NativeCore $central $tools $PythonPath $NativeCoreRequest }
            }
            if ($SdkSmokes) {
                & (Join-Path $SdkSmokes 'run.ps1') -Directory $SdkSmokes -ExpectedSid $ExpectedSid -ExpectedProgram $central -PythonPath $PythonPath -NodePath $NodePath |
                    Set-Content -LiteralPath 'installed-sdk-smokes.txt' -Encoding UTF8
            }
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
            if ($SoakSeconds) {
                Assert-InstalledRuntimeSoak $central $ExpectedRuntimeSha256 $ExpectedSupervisorSha256 $ExpectedSid $SoakSeconds (Join-Path (Get-Location) 'installed-soak.json') @($MsiPath,$PSCommandPath,(Join-Path $PSScriptRoot 'OAFixture.psm1'),$SoakRequestPath)
            }
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
    } catch { $failure = $_ } finally {
        foreach ($process in $previousProcesses) { $process.Dispose() }
        Write-NativeFixtureClosure (Get-Location).Path
        try { Assert-NativeFixtureMutationSafe (Get-Location).Path;Assert-OrdinaryNativeClosure $NativeCoreRequest }
        catch {
            $closureFailure = $_
            Write-Warning ('Ordinary native closure UNKNOWN; retain installed runtime/data: ' + (Protect-DiagnosticText $_.Exception.Message)) -WarningAction Continue
        }
        if (-not $closureFailure -and ($installed -or $installAttempted)) {
            # A post-InstallFinalize activation error can leave committed files.
            try { Invoke-Bounded msiexec.exe @('/x', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', 'user-cleanup-uninstall.log') } catch { Write-Warning $_ }
        }
        if (-not $closureFailure -and $predecessorAttempted) {
            $oldCode = Get-PackageProperty $PredecessorMsiPath ProductCode
            if (@(Get-InstalledProducts | Where-Object { $_.ProductCode -eq $oldCode }).Count) {
                try { Invoke-Bounded msiexec.exe @('/x',"`"$PredecessorMsiPath`"",'/qn','/norestart','/l*v','predecessor-cleanup.log') } catch { Write-Warning $_ }
            }
        }
        # openabstractions appends each failed installer-invoked command here; MSI discards its stderr.
        $installerActions = Join-Path (Get-ProfileFolder LocalApplicationData) 'openabstractions\upgrade-v1\installer-actions.txt'
        try { if (Test-Path -LiteralPath $installerActions) { Copy-Item -LiteralPath $installerActions -Destination 'installer-actions.txt' -Force } }
        catch { Write-Warning ('Installer action diagnostics failed: ' + (Protect-DiagnosticText $_.Exception.Message)) }
        Write-NativeFixtureClosure (Get-Location).Path
    }
    if ($failure) { throw $failure }
    if ($closureFailure) { throw $closureFailure }
    exit 0
}

$MsiPath = (Resolve-Path -LiteralPath $MsiPath).Path
if ([IO.Path]::GetExtension($MsiPath) -ne '.msi') { throw 'Expected an MSI package' }
if ($Unscoped -and $PredecessorMsiPath) { throw 'Unscoped verification installs a fresh package and takes no predecessor' }
if (($PredecessorElsewhere -or $FailUpgrade) -and -not $PredecessorMsiPath) { throw 'PredecessorElsewhere and FailUpgrade qualify an upgrade and need -PredecessorMsiPath' }
if ($FailSameVersion -and ($PredecessorMsiPath -or $Unscoped -or $CheckTools)) { throw 'FailSameVersion installs the candidate as its own predecessor and takes no other variant' }
if ($SdkSmokes -and (-not $CheckTools -or -not $NodePath)) { throw 'SDK smokes require -CheckTools and -NodePath' }
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
    if ($SoakSeconds) { $arguments += @('-SoakSeconds',$SoakSeconds,'-ExpectedRuntimeSha256',$ExpectedRuntimeSha256,'-ExpectedSupervisorSha256',$ExpectedSupervisorSha256,'-SoakRequestPath',"`"$SoakRequestPath`"") }
    if ($PredecessorMsiPath) { $arguments += @('-PredecessorMsiPath',"`"$directory\predecessor.msi`"",'-PredecessorSHA256',$PredecessorSHA256,'-PredecessorVersion',$PredecessorVersion,'-ExpectedVersion',$ExpectedVersion) }
    if ($Unscoped) { $arguments += '-Unscoped' }
    if ($PredecessorElsewhere) { $arguments += '-PredecessorElsewhere' }
    if ($FailUpgrade) { $arguments += '-FailUpgrade' }
    if ($FailSameVersion) { $arguments += '-FailSameVersion' }
    if ($CheckTools) {
        if (-not $PythonPath -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw 'Release tools check requires an explicit existing Python executable' }
        $arguments += @('-CheckTools','-PythonPath',"`"$PythonPath`"")
    }
    if ($SdkSmokes) {
        $smokes = Join-Path $directory 'sdk-smokes'
        Copy-Item -LiteralPath (Resolve-Path -LiteralPath $SdkSmokes).Path -Destination $smokes -Recurse
        Protect-SdkSmokeInputs -Path $smokes -Sid $account.Sid
        $probeAcl = (Get-Acl -LiteralPath (Join-Path $smokes 'python_probe.py')).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])
        $accountRules = @($probeAcl | Where-Object { $_.IdentityReference.Value -eq $account.Sid })
        if ($accountRules.Count -ne 1 -or $accountRules[0].AccessControlType -ne 'Allow' -or
            ($accountRules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)) {
            throw 'Disposable account can alter installed SDK smoke inputs'
        }
        $arguments += @('-SdkSmokes',"`"$directory\sdk-smokes`"",'-NodePath',"`"$NodePath`"")
    }
    $child = Invoke-AccountProcess -Account $account -FileName 'powershell.exe' -Arguments $arguments -WorkingDirectory $directory -Seconds (Get-UserFixtureSeconds ([bool]$PredecessorMsiPath) $false $SoakSeconds)
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
