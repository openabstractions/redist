param(
    [ValidateSet('Verify','VerifyRemoved','Cleanup','ValidateOnly')][string]$Mode = 'ValidateOnly',
    [string]$StatePath = (Join-Path $env:TEMP 'oa-service-session.json'),
    # Verify only: once the SCM-created instance serves a ready runtime, run this
    # application as the session's account from CommandDirectory, which must lie
    # under RUNNER_TEMP or GITHUB_WORKSPACE. Its exit decides the fixture.
    [string]$CommandPath,
    [string[]]$CommandArguments = @(),
    [string]$CommandDirectory,
    [ValidateRange(1, 7200)][int]$CommandSeconds = 1800,
    # Verify only: the image the SCM-created instance runs. 0.1.8 and later run
    # the windowless host; a 0.1.7 predecessor installed for a rollback test runs jobdw.
    [ValidateSet('openabstractionsw.exe','jobdw.exe')][string]$ExpectedImage = 'openabstractionsw.exe',
    # Current demand-start packages activate through their installed CLI in the
    # actual RDP token. Historical predecessors retain their sign-in behavior.
    [switch]$ActivateRuntime,
    [ValidateRange(1, 600)][int]$ActivationSeconds = 300
)
$ErrorActionPreference = 'Stop'
# No mutation in the default mode. Only disposable GitHub-hosted runners may run this fixture.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Windows.Forms;
public class OARdpHost : AxHost {
  public OARdpHost() : base("8B918B82-7985-4C24-89DF-C33AD2BBFBCD") {} // MsRdpClient9NotSafeForScripting
  public object Client { get { return GetOcx(); } }
  public bool LoginComplete;
  public int DisconnectReason;
  public bool Disconnected;
  public void HookEvents() {
    var iid = new Guid("336d5562-efa8-482e-8cb3-c5c0fc7a7db6");
    ComEventsHelper.Combine(Client,iid,3,new Action(() => { LoginComplete=true; }));
    ComEventsHelper.Combine(Client,iid,4,new Action<int>(n => { DisconnectReason=n; Disconnected=true; }));
  }
}
public static class OASessions {
  [StructLayout(LayoutKind.Sequential)] struct Info { public int Id; public IntPtr Station; public int State; }
  [DllImport("wtsapi32.dll", SetLastError=true)] static extern bool WTSEnumerateSessions(IntPtr h, int reserved, int version, out IntPtr data, out int count);
  [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool WTSQuerySessionInformation(IntPtr h, int id, int field, out IntPtr data, out int bytes);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
  public static string InitialProgram(int session) {
    IntPtr data; int bytes;
    if (!WTSQuerySessionInformation(IntPtr.Zero,session,0,out data,out bytes)) throw new System.ComponentModel.Win32Exception(); // WTSInitialProgram
    try { return Marshal.PtrToStringUni(data) ?? ""; }
    finally { WTSFreeMemory(data); }
  }
  [DllImport("wtsapi32.dll", SetLastError=true)] public static extern bool WTSLogoffSession(IntPtr h, int id, bool wait);
  public static int[] ForUser(string user) {
    IntPtr data; int count;
    var timer=System.Diagnostics.Stopwatch.StartNew();
    Console.WriteLine("WTS enumerate start");
    if (!WTSEnumerateSessions(IntPtr.Zero,0,1,out data,out count)) throw new System.ComponentModel.Win32Exception();
    Console.WriteLine("WTS enumerate done: {0}ms",timer.ElapsedMilliseconds);
    var result = new List<int>();
    try { for (int n=0;n<count;n++) {
      var s=(Info)Marshal.PtrToStructure(IntPtr.Add(data,n*Marshal.SizeOf(typeof(Info))),typeof(Info));
      IntPtr name; int bytes;
      timer.Restart();
      Console.WriteLine("WTS username query start: session {0}",s.Id);
      if (!WTSQuerySessionInformation(IntPtr.Zero,s.Id,5,out name,out bytes)) throw new System.ComponentModel.Win32Exception();
      Console.WriteLine("WTS username query done: session {0}, {1}ms",s.Id,timer.ElapsedMilliseconds);
      try { if (String.Equals(Marshal.PtrToStringUni(name),user,StringComparison.OrdinalIgnoreCase)) result.Add(s.Id); }
      finally { WTSFreeMemory(name); }
    }} finally { WTSFreeMemory(data); }
    return result.ToArray();
  }
}
"@ -ReferencedAssemblies System.Windows.Forms
# Bounded processes, the disposable account and account processes, process
# owners and runtime pipes come from the module published beside this fixture.
Import-Module (Join-Path $PSScriptRoot 'OAFixture.psm1') -Force
if ($Mode -eq 'ValidateOnly') { 'Harness compiled; no account, session, firewall or service changes.'; exit 0 }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This mutating fixture is restricted to disposable GitHub-hosted runners.'
}
function Write-Diagnostic([string]$Text) {
    $Text | Write-Output
    $Text | Add-Content -Encoding UTF8 'service-session.log'
}
# One status probe: a bounded process that keeps its creation handle, so an
# already-exited child still reports its exit code.
function Invoke-StatusProcess([Diagnostics.ProcessStartInfo]$StartInfo, [string]$ObservationPath) {
    return Invoke-FixtureProcess $StartInfo 10 -ObservationPath $ObservationPath
}
# Only fixed vocabulary reaches the artifact; captured CLI text may contain paths or secrets.
function Format-StatusFailure([Nullable[int]]$ExitCode, [string]$Json, [string]$Diagnostics) {
    $Json = $Json.Substring(0, [Math]::Min(4096, $Json.Length))
    $Diagnostics = $Diagnostics.Substring(0, [Math]::Min(4096, $Diagnostics.Length))
    $exitText = if ($null -eq $ExitCode) { 'unobserved' } else { [string]$ExitCode }
    $fields = @("exit=$exitText")
    $errorText = $Diagnostics
    try {
        $report = ConvertFrom-Json -InputObject $Json -ErrorAction Stop
        # JSON numbers, booleans, strings and arrays are not a status object.
        if ($null -eq $report -or $report -is [array] -or $report -isnot [Management.Automation.PSCustomObject]) { throw 'Expected status object' }
        $fields += 'json=parsed'
        foreach ($name in @('abstraction.logging','abstraction.config')) {
            $items = @($report.capabilities | Where-Object { $_.capability -ceq $name })
            if ($items.Count -eq 1 -and $items[0].status -cin @('resolved','unavailable','forbidden','incompatible','unmet_requirements','not_ready','invalid_request')) {
                $fields += "$name=$($items[0].status)"
            } else { $fields += "$name=missing-or-invalid" }
        }
        if ($report.error -is [string]) { $errorText += ' ' + $report.error.Substring(0, [Math]::Min(4096, $report.error.Length)) }
    } catch { $fields += 'json=invalid' }
    $fields += 'error-classes=' + (@(Get-ErrorClasses $errorText) -join ',')
    $fields += "stderr-present=$([bool]$Diagnostics.Length)"
    $line = 'runtime status failed: ' + ($fields -join ' ')
    return $line.Substring(0, [Math]::Min(768, $line.Length))
}
function Get-ErrorClasses([string]$Text) {
    $classes = @()
    foreach ($entry in @(
        @('timeout','(?i)timeout|timed out|deadline exceeded'),
        @('access-denied','(?i)access.*denied|permission denied'),
        @('refused','(?i)refused|refusal'),
        @('unavailable','(?i)unavailable|cannot find|not found|no such file'),
        @('disconnected','(?i)broken pipe|disconnected|end of file|\bEOF\b'),
        @('invalid','(?i)invalid|malformed'),
        @('identity','(?i)identity|principal|impersonat')
    )) { if ($Text -match $entry[1]) { $classes += $entry[0] } }
    if ($classes.Count -eq 0) { $classes = @('unclassified') }
    return $classes
}
# The same required set as test_user_runtime.ps1 Assert-RuntimeReady. A report
# that is malformed, duplicates or omits a required contract fails at once; a
# parsed report whose required contracts are not all resolved is not yet ready.
function Get-RuntimeReadiness([string]$Json) {
    try { $report = ConvertFrom-Json -InputObject $Json -ErrorAction Stop } catch { throw 'Runtime status report is malformed: invalid JSON' }
    # [pscustomobject] is PSObject here and matches any wrapped value; test the real type.
    $object = [Management.Automation.PSCustomObject]
    if ($null -eq $report -or $report -is [array] -or $report -isnot $object) { throw 'Runtime status report is malformed: expected an object' }
    if ($null -eq $report.PSObject.Properties['capabilities'] -or $null -eq $report.capabilities) { throw 'Runtime status report is malformed: no capabilities' }
    $entries = @($report.capabilities)
    foreach ($entry in $entries) {
        if ($entry -is [array] -or $entry -isnot $object -or $entry.capability -isnot [string] -or $entry.contract -isnot [string] -or $entry.status -isnot [string]) {
            throw 'Runtime status report is malformed: a capability entry lacks capability, contract or status'
        }
    }
    $known = @('resolved','unavailable','forbidden','incompatible','unmet_requirements','not_ready','invalid_request')
    $fields = @()
    $ready = $true
    $bindings = @{}
    foreach ($contract in @('abstraction.logging/sink@1','abstraction.config/reader@1','abstraction.config/editor@1','abstraction.job/acceptance@1','abstraction.job/operations@1')) {
        $found = @($entries | Where-Object { $_.contract -ceq $contract })
        if ($found.Count -eq 0) { throw "Runtime status report omits required $contract" }
        if ($found.Count -gt 1) { throw "Runtime status report lists $contract more than once" }
        $entry = $found[0]
        if ($entry.capability -cne $contract.Split('/')[0]) { throw "Runtime status report lists $contract under another capability" }
        if ($entry.status -ceq 'resolved') {
            $endpoint = $entry.result.reference.endpoint
            if ($endpoint -isnot [string] -or -not $endpoint -or $endpoint.Contains('"') -or $endpoint.Contains("`r") -or $endpoint.Contains("`n")) {
                throw "Resolved contract lacks a usable endpoint: $contract"
            }
            if (-not $bindings.ContainsKey($endpoint)) { $bindings[$endpoint] = @() }
            $bindings[$endpoint] += $contract
            $fields += "$contract=resolved"
            continue
        }
        $ready = $false
        $status = if ($entry.status -cin $known) { $entry.status } else { 'unrecognized' }
        # Only fixed vocabulary reaches this line: error text becomes classes.
        $text = @()
        foreach ($source in @($entry, $entry.result)) {
            if ($source -is [array] -or $source -isnot $object) { continue }
            foreach ($name in @('error','reason','detail','message')) {
                $value = $source.$name
                if ($value -is [string]) { $text += $value }
                elseif ($value -isnot [array] -and $value -is $object) { $text += @($value.PSObject.Properties | Where-Object { $_.Value -is [string] } | ForEach-Object { $_.Value }) }
            }
        }
        $classes = if ($text.Count) { @(Get-ErrorClasses ($text -join ' ')) -join ',' } else { 'none' }
        $fields += "$contract=$status error-classes=$classes"
    }
    return [pscustomobject]@{ Ready = $ready; Summary = ($fields -join '; '); Bindings = $bindings }
}
function Protect-StatusText([string]$Text) {
    $Text = $Text.Substring(0, [Math]::Min(16384, $Text.Length)) -replace '\r?\n', ' '
    $Text = $Text -replace '(?i)("(?:password|token|secret|authorization|api[_-]?key)"\s*:\s*")[^"]*', '$1[redacted]'
    $Text = $Text -replace '(?i)(password|token|secret|authorization|api[_-]?key)(\s*[:=]\s*)[^\s",}]+', '$1$2[redacted]'
    $Text = $Text -replace '(?i)Bearer\s+[^\s",}]+', 'Bearer [redacted]'
    return $Text -replace '(https?://)[^/\s@"]+@', '$1[redacted]@'
}
function Write-ServerDiagnostics {
    foreach ($log in @('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
        'Microsoft-Windows-Winlogon/Operational',
        'Microsoft-Windows-User Profile Service/Operational',
        'Microsoft-Windows-AppReadiness/Admin','Microsoft-Windows-AppReadiness/Operational',
        'Application','System','Security')) {
        try {
            $filter = @{ LogName=$log; StartTime=$started }
            if ($log -eq 'Security') { $filter.Id=4625 }
            if ($log -eq 'Application') { $filter.ProviderName=@('Microsoft-Windows-User Profiles Service','Microsoft-Windows-Winlogon','Application Error') }
            if ($log -eq 'System') { $filter.ProviderName=@('Microsoft-Windows-Winlogon','Service Control Manager','TermDD') }
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 20 -ErrorAction Stop)
            foreach ($event in $events) {
                [xml]$xml = $event.ToXml()
                # Do not dump rendered event messages, account names, addresses, or credential-bearing fields.
                $codes = @($xml.Event.EventData.Data | Where-Object {
                    $_.Name -in @('Status','SubStatus','FailureReason','LogonType','ErrorCode','ResultCode','SessionID','Reason','DisconnectReason','Error','HResult','State','StatusCode')
                } | ForEach-Object { "$($_.Name)=$($_.'#text')" }) -join ' '
                Write-Diagnostic "event log=$log id=$($event.Id) time=$($event.TimeCreated.ToUniversalTime().ToString('o')) $codes"
            }
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                Write-Diagnostic "event log=$log no matching events"
            } else {
                Write-Diagnostic "event log=$log unavailable errorId=$($_.FullyQualifiedErrorId)"
            }
        }
    }
}
$rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$initialProgramKey = Join-Path $rdpKey 'WinStations\RDP-Tcp'
function Get-SessionInitialProgramPolicy([string]$Path) {
    $key=Get-Item -LiteralPath $Path -ErrorAction Stop
    try {
        $present=$key.GetValueNames() -contains 'fInheritInitialProgram'
        $kind=if($present){$key.GetValueKind('fInheritInitialProgram').ToString()}else{$null}
        $value=if($present){$key.GetValue('fInheritInitialProgram')}else{$null}
        if($present -and ($kind -cne 'DWord' -or $value -notin @(0,1))){throw 'Unexpected initial-program policy type or value'}
        return @{ValueExisted=[bool]$present;Kind=$kind;Value=$value;Restored=$false}
    } finally { $key.Close() }
}
function Enable-SessionInitialProgram([string]$Path,[string]$StatePath,[hashtable]$State) {
    if($State.ContainsKey('InitialProgramPolicy')){throw 'Initial-program policy baseline already recorded'}
    $State.InitialProgramPolicy=Get-SessionInitialProgramPolicy $Path
    # Persist the complete original value/presence/type before the first write.
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    $before=$State.InitialProgramPolicy
    $kind=if($before.ValueExisted){'DWord'}else{'absent'}
    $value=if($before.ValueExisted){[bool]$before.Value}else{'absent'}
    Write-Diagnostic "RDP initial-program baseline present=$($before.ValueExisted) kind=$kind inherit=$value" | Out-Null
    if($State.InitialProgramPolicy.ValueExisted){Set-ItemProperty -LiteralPath $Path -Name fInheritInitialProgram -Value 1 -ErrorAction Stop}
    else{New-ItemProperty -LiteralPath $Path -Name fInheritInitialProgram -PropertyType DWord -Value 1 -ErrorAction Stop | Out-Null}
    $actual=Get-SessionInitialProgramPolicy $Path
    if(-not $actual.ValueExisted -or $actual.Kind -cne 'DWord' -or $actual.Value -ne 1){throw 'Client initial-program selection did not take effect'}
}
function Restore-SessionInitialProgram([string]$Path,$Snapshot) {
    if($Snapshot.ValueExisted -isnot [bool] -or
        ($Snapshot.ValueExisted -and ($Snapshot.Kind -cne 'DWord' -or ($Snapshot.Value -isnot [int] -and $Snapshot.Value -isnot [long]) -or $Snapshot.Value -notin @(0,1))) -or
        (-not $Snapshot.ValueExisted -and ($null -ne $Snapshot.Kind -or $null -ne $Snapshot.Value))){throw 'Invalid initial-program policy baseline'}
    $actual=Get-SessionInitialProgramPolicy $Path
    if($Snapshot.ValueExisted){
        if($actual.ValueExisted){Set-ItemProperty -LiteralPath $Path -Name fInheritInitialProgram -Value $Snapshot.Value -ErrorAction Stop}
        else{New-ItemProperty -LiteralPath $Path -Name fInheritInitialProgram -PropertyType DWord -Value $Snapshot.Value -ErrorAction Stop | Out-Null}
    }elseif($actual.ValueExisted){Remove-ItemProperty -LiteralPath $Path -Name fInheritInitialProgram -ErrorAction Stop}
    $actual=Get-SessionInitialProgramPolicy $Path
    if($actual.ValueExisted -ne $Snapshot.ValueExisted -or $actual.Kind -cne $Snapshot.Kind -or $actual.Value -ne $Snapshot.Value){throw 'Initial-program policy baseline was not restored'}
}
function Assert-SessionInitialEnvironment($Setting) {
    foreach($name in @('InitialProgramPolicy','PolicySourceInitialProgramPath','PolicySourceStartIn')){
        $value=$Setting.$name
        if(($value -isnot [int] -and $value -isnot [uint32] -and $value -isnot [long]) -or $value -notin @(0,1,2)){
            throw 'Unsupported connection initial-program policy enum'
        }
    }
}
function Get-SessionInitialEnvironment([scriptblock]$Query) {
    if(-not $Query){$Query={Get-CimInstance -Namespace root/cimv2/terminalservices -ClassName Win32_TSEnvironmentSetting -Filter "TerminalName='RDP-Tcp'" -OperationTimeoutSec 2 -ErrorAction Stop}}
    $settings=@(& $Query)
    if($settings.Count -ne 1 -or $settings[0].TerminalName -ine 'RDP-Tcp'){throw 'One exact RDP-Tcp connection setting required'}
    Assert-SessionInitialEnvironment $settings[0]
    return $settings[0]
}
function Set-SessionInitialEnvironment($Setting,[ValidateSet(0,1,2)][int]$Value,[scriptblock]$Set) {
    if($Set){& $Set $Setting $Value | Out-Null}
    else{Set-CimInstance -InputObject $Setting -Property @{InitialProgramPolicy=[uint32]$Value} -ErrorAction Stop | Out-Null}
}
function Enable-SessionInitialEnvironment([string]$StatePath,[hashtable]$State,[scriptblock]$Query,[scriptblock]$Set) {
    if($State.ContainsKey('InitialProgramEnvironment')){throw 'Connection initial-program baseline already recorded'}
    $before=Get-SessionInitialEnvironment $Query
    $State.InitialProgramEnvironment=@{InitialProgramPolicy=[int]$before.InitialProgramPolicy;
        PolicySourceInitialProgramPath=[int]$before.PolicySourceInitialProgramPath;PolicySourceStartIn=[int]$before.PolicySourceStartIn;Restored=$false}
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    Write-Diagnostic "RDP initial-program environment baseline policy=$($before.InitialProgramPolicy) source=$($before.PolicySourceInitialProgramPath) start-in-source=$($before.PolicySourceStartIn)" | Out-Null
    # The documented Per User (0) policy admits the client-selected startup
    # program. The observed Server-Override (1) selected an empty shell.
    if($before.InitialProgramPolicy -eq 0){return}
    Set-SessionInitialEnvironment $before 0 $Set
    if((Get-SessionInitialEnvironment $Query).InitialProgramPolicy -ne 0){throw 'Connection did not admit per-user initial-program selection'}
}
function Restore-SessionInitialEnvironment($Snapshot,[scriptblock]$Query,[scriptblock]$Set) {
    Assert-SessionInitialEnvironment $Snapshot
    $actual=Get-SessionInitialEnvironment $Query
    if($actual.InitialProgramPolicy -eq $Snapshot.InitialProgramPolicy){return}
    Set-SessionInitialEnvironment $actual $Snapshot.InitialProgramPolicy $Set
    if((Get-SessionInitialEnvironment $Query).InitialProgramPolicy -ne $Snapshot.InitialProgramPolicy){throw 'Connection initial-program baseline was not restored'}
}
function Format-SessionProgram([ValidateSet('client-start','server-start','policy-start')][string]$Label,[string]$Value,[string]$Expected) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try{$digest=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-','').ToLowerInvariant()}
    finally{$hash.Dispose()}
    return "$Label length=$($Value.Length) sha256=$digest equals-requested=$($Value -ceq $Expected)"
}
function Write-SessionInitialProgramObservation($Client,$Activation,[ValidateSet('before-logon','after-logon')][string]$Phase,
        [int]$Session=-1,[string]$PolicyPath=$initialProgramKey) {
    $expected=if($Activation){$Activation.StartProgram}else{''}
    try{
        $secured=$Client.SecuredSettings
        if($null -eq $secured){throw 'Client initial-program settings unavailable'}
        $selected=$secured.StartProgram
        if($null -eq $selected){throw 'Client initial program unavailable'}
        Write-Diagnostic ("RDP $Phase "+(Format-SessionProgram 'client-start' ([string]$selected) $expected)) | Out-Null
    }
    catch{Write-Diagnostic "RDP $Phase client-start unavailable" | Out-Null}
    if($Session -ge 0){
        try{Write-Diagnostic ("RDP $Phase "+(Format-SessionProgram 'server-start' ([OASessions]::InitialProgram($Session)) $expected)) | Out-Null}
        catch{Write-Diagnostic "RDP $Phase server-start unavailable" | Out-Null}
    }
    try{
        $policy=Get-SessionInitialProgramPolicy $PolicyPath
        $inherits=if($policy.ValueExisted){[bool]$policy.Value}else{'absent'}
        Write-Diagnostic "RDP $Phase inherit-client-program=$inherits" | Out-Null
    }catch{Write-Diagnostic "RDP $Phase inherit-client-program unavailable" | Out-Null}
    try{
        $setting=Get-SessionInitialEnvironment
        foreach($name in @('InitialProgramPolicy','PolicySourceInitialProgramPath','PolicySourceStartIn')){
            Write-Diagnostic "RDP $Phase $name=$($setting.$name)" | Out-Null
        }
        Write-Diagnostic ("RDP $Phase "+(Format-SessionProgram 'policy-start' ([string]$setting.InitialProgramPath) $expected)) | Out-Null
    }catch{Write-Diagnostic "RDP $Phase connection-initial-program unavailable" | Out-Null}
}
function Wait-Condition([scriptblock]$Check, [int]$Seconds, [string]$Description) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        [System.Windows.Forms.Application]::DoEvents()
        $result = & $Check
        if ($result) { return $result }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    Get-CimInstance Win32_Service -Filter "Name LIKE 'OpenAbstractionsSupervisor%'" | Format-Table Name,State,ProcessId | Out-Host
    throw "Timed out after ${Seconds}s: $Description"
}
# The command a caller runs as the session's account. Its directory is granted
# to that account, so it must be a runner-owned directory, never a system one.
function Resolve-SessionCommand([string]$Path, [string]$Directory) {
    $command = @(Get-Command -Name $Path -CommandType Application -ErrorAction SilentlyContinue)
    if ($command.Count -eq 0) { throw "Session command is not an application: $Path" }
    if (-not $Directory -or -not [IO.Path]::IsPathRooted($Directory) -or -not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw 'A session command needs -CommandDirectory, an existing absolute directory'
    }
    $folder = (Resolve-Path -LiteralPath $Directory).Path.TrimEnd('\')
    $roots = @($env:RUNNER_TEMP, $env:GITHUB_WORKSPACE | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') })
    if (-not @($roots | Where-Object { $folder -ieq $_ -or $folder.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) }).Count) {
        throw "Session command directory must lie under RUNNER_TEMP or GITHUB_WORKSPACE: $folder"
    }
    return [pscustomobject]@{ Path = $command[0].Source; Directory = $folder }
}
# Runs the command as the account through a credential logon, after writing the
# session's identity beside it. The command's output stays in its own log.
function Invoke-SessionCommand($Command, [string[]]$Arguments, [int]$Seconds, $Account, [hashtable]$Context) {
    Grant-AccountAccess -Path $Command.Directory -Sid $Account.Sid -Access Modify
    $Context | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $Command.Directory 'service-session-context.json')
    $result = Invoke-AccountProcess -Account $Account -FileName $Command.Path -Arguments $Arguments -WorkingDirectory $Command.Directory -Seconds $Seconds
    @($result.Output, $result.Diagnostics) -join "`n" | Set-Content -Encoding UTF8 'service-session-command.log'
    Write-Diagnostic "session command exit=$($result.ExitCode)" | Out-Null
    if ($result.ExitCode -ne 0) { throw "Session command exited $($result.ExitCode)" }
}
function New-SessionActivation([string]$Directory, [string]$Runtime, [string]$Module, [string]$Sid, [DateTime]$Deadline) {
    if (Test-Path -LiteralPath $Directory) { throw 'Fresh session activation directory required' }
    foreach ($path in @($Runtime,$Module)) {
        $item=Get-Item -LiteralPath $path
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Ordinary session activation inputs required' }
    }
    if ($Deadline.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'Session activation deadline expired' }
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $diagnostics=Join-Path $Directory 'diagnostics'
    [IO.Directory]::CreateDirectory($diagnostics) | Out-Null
    $moduleCopy=Join-Path $Directory 'OAFixture.psm1'
    Copy-Item -LiteralPath $Module -Destination $moduleCopy
    $runtimeHash=(Get-FileHash -LiteralPath $Runtime -Algorithm SHA256).Hash.ToLowerInvariant()
    $moduleHash=(Get-FileHash -LiteralPath $moduleCopy -Algorithm SHA256).Hash.ToLowerInvariant()
    $script=@'
$ErrorActionPreference='Stop'
[IO.File]::WriteAllText(($PSScriptRoot+'\diagnostics\start-entry.txt'),[DateTime]::UtcNow.ToString('o'),[Text.UTF8Encoding]::new($false))
$record=[ordered]@{ExitCode=$null;Closure='unknown';Sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Session=(Get-Process -Id $PID).SessionId;Failure=''}
try {
    if ([DateTime]::UtcNow -ge [DateTime]::Parse('__DEADLINE__').ToUniversalTime()) { throw 'RDP activation deadline expired' }
    if ($record.Sid -cne '__SID__') { throw 'RDP activation account differs' }
    if ((Get-FileHash -LiteralPath '__RUNTIME__' -Algorithm SHA256).Hash.ToLowerInvariant() -cne '__RUNTIME_HASH__') { throw 'Installed activation image changed' }
    if ((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'OAFixture.psm1') -Algorithm SHA256).Hash.ToLowerInvariant() -cne '__MODULE_HASH__') { throw 'Activation process owner changed' }
    Import-Module (Join-Path $PSScriptRoot 'OAFixture.psm1') -Force
    $env:ABSTRACTION_RUNTIME_ENDPOINT=$null
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName='__RUNTIME__'
    $info.Arguments='start --timeout 30s'
    $info.WorkingDirectory=Split-Path $info.FileName
    $result=Invoke-FixtureProcess $info 35 -ObservationPath (Join-Path $PSScriptRoot 'diagnostics/start-process.json')
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'diagnostics/start.stdout'),$result.Output,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'diagnostics/start.stderr'),$result.Diagnostics,[Text.UTF8Encoding]::new($false))
    $record.ExitCode=$result.ExitCode;$record.Closure=$result.Closure
} catch { $record.Failure=$_.Exception.Message }
$resultPath=Join-Path $PSScriptRoot 'diagnostics/start-result.json'
[IO.File]::WriteAllText(($resultPath+'.tmp'),($record|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
[IO.File]::Move($resultPath+'.tmp',$resultPath)
# The initial RDP program must stay alive for uninstall to observe the live
# service instance after disconnect. The caller's bound ends it
# even if the existing account/session Cleanup cannot run.
while ([DateTime]::UtcNow -lt [DateTime]::Parse('__DEADLINE__').ToUniversalTime()) { Start-Sleep -Milliseconds 200 }
'@
    foreach ($entry in @(@('__RUNTIME__',$Runtime),@('__SID__',$Sid),@('__RUNTIME_HASH__',$runtimeHash),@('__MODULE_HASH__',$moduleHash),@('__DEADLINE__',$Deadline.ToUniversalTime().ToString('o')))) {
        $script=$script.Replace($entry[0],$entry[1].Replace("'","''"))
    }
    $scriptPath=Join-Path $Directory 'activate.ps1'
    [IO.File]::WriteAllText($scriptPath,$script,[Text.UTF8Encoding]::new($false))
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$scriptPath+'"'
    $program='"'+$powershell+'" '+$arguments
    if ($program.Length -gt 259) { throw 'RDP activation start program exceeds its native bound' }
    return [pscustomobject]@{Directory=$Directory;Diagnostics=$diagnostics;Script=$scriptPath;Module=$moduleCopy;
        ScriptSha256=(Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant();ModuleSha256=$moduleHash;
        Program=$powershell;Arguments=$arguments;StartProgram=$program;Deadline=$Deadline.ToUniversalTime().ToString('o')}
}
function Assert-SessionActivationInputs($Activation) {
    foreach ($entry in @(@($Activation.Script,$Activation.ScriptSha256),@($Activation.Module,$Activation.ModuleSha256))) {
        if ((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[1]) { throw 'Pinned session activation source changed' }
    }
}
function Get-SessionActivationTask([string]$Name,[scriptblock]$Query) {
    try{$tasks=@(if($Query){& $Query $Name}else{Get-ScheduledTask -TaskName $Name -TaskPath '\' -ErrorAction Stop})}
    catch{if($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound){return};throw}
    if($tasks.Count -eq 0){return}
    if($tasks.Count -ne 1){throw 'One exact activation task required'}
    return $tasks[0]
}
function Assert-SessionActivationTask($Task,$Record) {
    $sid=if($Task.Principal.UserId -like 'S-1-*'){[Security.Principal.SecurityIdentifier]::new($Task.Principal.UserId).Value}
        else{[Security.Principal.NTAccount]::new($Task.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}
    $actions=@($Task.Actions)
    $limit=[Xml.XmlConvert]::ToTimeSpan($Task.Settings.ExecutionTimeLimit).TotalSeconds
    if($Task.TaskName -cne $Record.Name -or $Task.TaskPath -cne '\' -or $sid -cne $Record.Sid -or
        [int]$Task.Principal.LogonType -ne 3 -or [int]$Task.Principal.RunLevel -ne 0 -or $Task.Principal.GroupId -or
        $Task.Triggers -or $actions.Count -ne 1 -or $actions[0].Execute -cne $Record.Program -or $actions[0].Arguments -cne $Record.Arguments -or
        $actions[0].WorkingDirectory -cne $Record.Directory -or [int]$Task.Settings.MultipleInstances -ne 2 -or
        $limit -le 0 -or $limit -gt $Record.LimitSeconds){throw 'Activation task differs from the exact interactive-account action'}
}
function Start-SessionActivationTask($Activation,[string]$Sid,[int]$Session,[hashtable]$State,[string]$StatePath,
        [scriptblock]$Query,[scriptblock]$Register,[scriptblock]$Start,[scriptblock]$Build) {
    if(($Query -or $Register -or $Start -or $Build) -and (-not $Query -or -not $Register -or -not $Start -or -not $Build)){throw 'Complete task I/O callbacks required'}
    if($Session -le 0 -or $Sid -cne $State.Sid -or $State.ContainsKey('ActivationTask')){throw 'One fresh account/session activation required'}
    Assert-SessionActivationInputs $Activation
    $seconds=[int][Math]::Floor(([DateTime]::Parse($Activation.Deadline).ToUniversalTime()-[DateTime]::UtcNow).TotalSeconds)
    if($seconds -le 0 -or $seconds -gt 600){throw 'Session activation deadline expired or exceeds caller bound'}
    $record=@{Name=('OA-CI-RDP-'+[Guid]::NewGuid().ToString('N'));Sid=$Sid;Session=$Session;
        Program=$Activation.Program;Arguments=$Activation.Arguments;Directory=$Activation.Directory;LimitSeconds=$seconds;Removed=$false}
    if(Get-SessionActivationTask $record.Name $Query){throw 'Fresh activation task name required'}
    $State.ActivationTask=$record
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    $definition=if($Build){& $Build $record}else{
        @{Action=(New-ScheduledTaskAction -Execute $record.Program -Argument $record.Arguments -WorkingDirectory $record.Directory);
          Principal=(New-ScheduledTaskPrincipal -UserId $Sid -LogonType Interactive -RunLevel Limited);
          Settings=(New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds($seconds)) -MultipleInstances IgnoreNew)}
    }
    $action=$definition.Action;$principal=$definition.Principal;$settings=$definition.Settings
    if($Register){& $Register $record.Name $action $principal $settings | Out-Null}
    else{Register-ScheduledTask -TaskName $record.Name -TaskPath '\' -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null}
    Assert-SessionActivationTask (Get-SessionActivationTask $record.Name $Query) $record
    Assert-SessionActivationInputs $Activation
    if($Start){& $Start $record.Name | Out-Null}else{Start-ScheduledTask -TaskName $record.Name -TaskPath '\' -ErrorAction Stop}
    Write-Diagnostic 'RDP interactive activation task started=True' | Out-Null
}
function Remove-SessionActivationTask($Record,[string]$Sid,[scriptblock]$Query,[scriptblock]$Remove) {
    if(($Query -or $Remove) -and (-not $Query -or -not $Remove)){throw 'Complete task I/O callbacks required'}
    if($Record.Name -cnotmatch '^OA-CI-RDP-[0-9a-f]{32}$' -or $Record.Sid -cne $Sid -or $Record.Session -le 0){throw 'Unrecognized activation task ownership'}
    $task=Get-SessionActivationTask $Record.Name $Query
    if(-not $task){return}
    Assert-SessionActivationTask $task $Record
    if($Remove){& $Remove $Record.Name | Out-Null}else{Unregister-ScheduledTask -TaskName $Record.Name -TaskPath '\' -Confirm:$false -ErrorAction Stop}
    if(Get-SessionActivationTask $Record.Name $Query){throw 'Activation task survived removal'}
}
function Assert-SessionActivation($Activation,[int]$Session,[string]$Sid) {
    $resultPath=Join-Path $Activation.Diagnostics 'start-result.json'
    Wait-Condition { if (Test-Path -LiteralPath $resultPath -PathType Leaf) { $true } } 45 'installed start in the fresh RDP session' | Out-Null
    $result=Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ($result.Session -ne $Session -or $result.Sid -cne $Sid) { throw 'Installed start ran outside the fresh RDP account/session' }
    Write-Diagnostic "installed start exit=$($result.ExitCode) closure=$($result.Closure) session=$($result.Session)" | Out-Null
    foreach ($name in @('start.stdout','start.stderr')) {
        $path=Join-Path $Activation.Diagnostics $name
        if (Test-Path -LiteralPath $path) { Write-Diagnostic (Protect-StatusText (Get-Content -LiteralPath $path -Raw)) | Out-Null }
    }
    if ($null -eq $result.ExitCode -or $result.ExitCode -ne 0 -or $result.Closure -cne 'known' -or $result.Failure) { throw "Installed demand-start activation failed: $($result.Failure)" }
}
# Snapshot the bounded wrapper's existing observations before account cleanup.
# An absent entry/result remains absent evidence; no startup success is inferred.
function Save-SessionActivationDiagnostics($Activation,[string]$Directory) {
    if (-not $Activation) { return }
    if (Test-Path -LiteralPath $Directory) { throw 'Fresh activation diagnostic output required' }
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    foreach ($name in @('start-entry.txt','start-process.json','start-result.json','start.stdout','start.stderr')) {
        $path=Join-Path $Activation.Diagnostics $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $item=Get-Item -LiteralPath $path
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Ordinary activation diagnostics required' }
        Copy-Item -LiteralPath $path -Destination (Join-Path $Directory $name)
    }
}
# Removal is checked before Cleanup logs off the account and can terminate its processes.
if ($Mode -eq 'VerifyRemoved') {
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    if ($state.User -notmatch '^oa_ci_[0-9a-f]{10}$' -or -not $state.RuntimeVerified) {
        throw 'Removal verification requires a completed fresh-user runtime test'
    }
    Wait-Condition {
        $children = @(Get-CimInstance Win32_Process -Filter "Name='openabstractions.exe'" | Where-Object {
            if ($_.SessionId -eq $state.Session) {
                $owner = Get-ProcessOwnerSid $_
                $null -ne $owner -and $owner -eq $state.Sid
            }
        })
        $services = @(Get-CimInstance Win32_Service -Filter "Name LIKE 'OpenAbstractionsSupervisor%'")
        $pipes = @(Get-CapabilityPipes $state.Sid -Runtime)
        if ($children.Count -eq 0 -and $services.Count -eq 0 -and $pipes.Count -eq 0) { $true }
    } 30 'uninstall removed runtime processes, capability endpoints and SCM registrations' | Out-Null
    Write-Diagnostic 'ok: runtime and capability endpoints absent before account cleanup'
    exit 0
}
if ($Mode -eq 'Cleanup') {
    if (-not (Test-Path $StatePath)) { exit 0 }
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    if ($state.User -notmatch '^oa_ci_[0-9a-f]{10}$') { throw 'Refusing unrecognized cleanup account' }
    $account = Get-LocalUser -Name $state.User -ErrorAction SilentlyContinue
    if ($account -and $state.Sid -and $account.SID.Value -ne $state.Sid) { throw 'Cleanup account SID changed' }
    if($state.PSObject.Properties['ActivationTask']){
        Remove-SessionActivationTask $state.ActivationTask $state.Sid
        $state.ActivationTask.Removed=$true
        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
        Write-Diagnostic 'RDP interactive activation task removed=True' | Out-Null
    }
    # Restore connection policy even if subsequent account/session cleanup fails.
    if($state.PSObject.Properties['InitialProgramEnvironment']){
        Restore-SessionInitialEnvironment $state.InitialProgramEnvironment
        $state.InitialProgramEnvironment.Restored=$true
        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
        Write-Diagnostic 'RDP initial-program environment baseline restored=True' | Out-Null
    }
    # Older diagnostic state recorded the registry flag instead.
    if($state.PSObject.Properties['InitialProgramPolicy']){
        Restore-SessionInitialProgram $initialProgramKey $state.InitialProgramPolicy
        $state.InitialProgramPolicy.Restored=$true
        $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
        Write-Diagnostic 'RDP initial-program baseline restored=True' | Out-Null
    }
    foreach ($session in [OASessions]::ForUser($state.User)) {
        if ($session -eq (Get-Process -Id $PID).SessionId -or $session -eq 0) { throw 'Refusing to log off runner/session zero' }
        if (-not [OASessions]::WTSLogoffSession([IntPtr]::Zero,$session,$false)) { throw 'Test account logoff failed' }
    }
    Wait-Condition { if (@([OASessions]::ForUser($state.User)).Count -eq 0) { $true } } 30 'test account logoff' | Out-Null
    if ($account) { Remove-LocalUser -Name $state.User }
    Set-ItemProperty $rdpKey -Name fDenyTSConnections -Value $state.Deny
    Get-NetFirewallRule -Name "$($state.Rule)*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item -LiteralPath $StatePath
    'ok: only the temporary account was logged off and removed; RDP setting restored'
    exit 0
}
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') { throw 'Use powershell.exe -STA -File for ActiveX hosting' }
if (Test-Path $StatePath) { throw 'State already exists; clean previous fixture first' }
if (-not $CommandPath -and ($CommandDirectory -or $CommandArguments.Count)) { throw 'CommandDirectory and CommandArguments need -CommandPath' }
if ($ActivateRuntime -and ($ExpectedImage -cne 'openabstractionsw.exe' -or $CommandPath)) { throw 'Current RDP activation requires its fixed installed runtime and bounded recovery journey' }
# Resolved before anything changes, so a bad hook changes nothing.
$sessionCommand = if ($CommandPath) { Resolve-SessionCommand $CommandPath $CommandDirectory } else { $null }
$started = Get-Date
$user = 'oa_ci_' + [Guid]::NewGuid().ToString('N').Substring(0,10)
$state = @{ User=$user; Sid=''; Rule=('OA-CI-RDP-'+[Guid]::NewGuid().ToString('N')); Deny=(Get-ItemProperty $rdpKey).fDenyTSConnections }
$state | ConvertTo-Json | Set-Content -Encoding UTF8 $StatePath
# Blocks every non-loopback source before changing RDP availability. Never enable a broad allow rule.
$remote = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
foreach ($protocol in 'TCP','UDP') {
    New-NetFirewallRule -Name "$($state.Rule)-$protocol" -DisplayName "$($state.Rule)-$protocol" -Direction Inbound -Action Block -Protocol $protocol -LocalPort 3389 -RemoteAddress $remote -Profile Any | Out-Null
}
# Remote Desktop Users, so the account can sign in over the loopback RDP session.
# The name is already in the state file, so Cleanup finds a half-created account.
$account = New-DisposableAccount -Name $user -GroupSid 'S-1-5-32-555'
$password = $account.Credential.GetNetworkCredential().Password
$state.Sid = $account.Sid
$state | ConvertTo-Json | Set-Content -Encoding UTF8 $StatePath
$activation=$null
if ($ActivateRuntime) {
    $activation=New-SessionActivation (Join-Path $env:RUNNER_TEMP ($user+'-activation')) `
        (Join-Path $env:ProgramFiles 'OpenAbstractions\tools\openabstractions.exe') `
        (Join-Path $PSScriptRoot 'OAFixture.psm1') $account.Sid ($started.ToUniversalTime().AddSeconds($ActivationSeconds))
    Grant-AccountAccess -Path $activation.Directory -Sid $account.Sid -Access ReadExecute
    Grant-AccountAccess -Path $activation.Diagnostics -Sid $account.Sid -Access Modify
}
Set-ItemProperty $rdpKey -Name fDenyTSConnections -Value 0
Start-Service TermService
$settings = Get-CimInstance -Namespace root/cimv2/terminalservices -ClassName Win32_TerminalServiceSetting
Write-Diagnostic "TerminalServerMode=$($settings.TerminalServerMode) LicensingType=$($settings.LicensingType) AllowTSConnections=$($settings.AllowTSConnections)"
Wait-Condition { if (Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue) { $true } } 30 'RDP listener ready' | Out-Null
$form = New-Object System.Windows.Forms.Form
$form.ShowInTaskbar = $false
# Establish an actual desktop-sized ActiveX surface before connection. DesktopWidth/
# Height otherwise default to the control dimensions, including minimized geometry.
$form.ClientSize = New-Object System.Drawing.Size(1024,768)
$form.WindowState = 'Normal'
$hostControl = New-Object OARdpHost
$hostControl.Dock = 'Fill'
$form.Controls.Add($hostControl)
try {
    $form.Show()
    $client = $hostControl.Client
    $hostControl.HookEvents()
    $client.DesktopWidth = 1024
    $client.DesktopHeight = 768
    Write-Diagnostic "RDP requestedDesktop=$($client.DesktopWidth)x$($client.DesktopHeight) control=$($hostControl.Width)x$($hostControl.Height)"
    $client.Server = '127.0.0.1'
    $client.UserName = $user
    $client.Domain = $env:COMPUTERNAME
    $client.AdvancedSettings2.ClearTextPassword = $password
    $client.AdvancedSettings7.EnableCredSspSupport = $true
    # The endpoint is strictly loopback; avoid an unattended self-signed certificate dialog.
    $client.AdvancedSettings7.AuthenticationLevel = 0
    try{Write-SessionInitialProgramObservation $client $null 'before-logon'}catch{Write-Warning 'RDP initial-program observation unavailable'}
    $client.Connect()
    # Connect is asynchronous. A token/process alone is not evidence of a completed GUI logon.
    $session = Wait-Condition {
        if ($hostControl.Disconnected) {
            $extended = [int]$client.ExtendedDisconnectReason
            $description = $client.GetErrorDescription($hostControl.DisconnectReason,$extended)
            throw "RDP disconnected: reason=$($hostControl.DisconnectReason) extended=$extended description=$description"
        }
        # WTS queries are synchronous: keep this STA pumping RDP callbacks until
        # logon completes, rather than querying a session that is still initializing.
        if (-not $hostControl.LoginComplete -or $client.Connected -ne 1) { return }
        $ids = @([OASessions]::ForUser($user))
        if ($hostControl.LoginComplete -and $client.Connected -eq 1 -and $ids.Count -eq 1 -and $ids[0] -gt 0) { $ids[0] }
    } 90 'fresh RDP account session'
    $form.WindowState = 'Minimized'
    if ($session -eq (Get-Process -Id $PID).SessionId) { throw 'Fresh account reused runner session' }
    try{Write-SessionInitialProgramObservation $client $null 'after-logon' $session}catch{Write-Warning 'RDP initial-program observation unavailable'}
    if($activation){Start-SessionActivationTask $activation $state.Sid $session $state $StatePath}
    if ($activation) { Assert-SessionActivation $activation $session $state.Sid }
    # The service template runs the windowless host, `openabstractionsw.exe serve supervisor --service`.
    $expectedImagePath = Join-Path $env:ProgramFiles ('OpenAbstractions\tools\' + $ExpectedImage)
    function Find-Instance {
        foreach ($svc in @(Get-CimInstance Win32_Service -Filter "Name LIKE 'OpenAbstractionsSupervisor_%'")) {
            if ($svc.State -ne 'Running' -or $svc.ProcessId -eq 0) { continue }
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($svc.ProcessId)"
            if (-not $proc -or $proc.SessionId -ne $session) { continue }
            $owner = Get-ProcessOwnerSid $proc
            if ($null -eq $owner) { continue }
            if ($owner -ne $state.Sid) { throw 'Instance has wrong principal' }
            if ($proc.ExecutablePath -ne $expectedImagePath) { throw 'Instance has wrong executable' }
            return $svc
        }
    }
    $first = Wait-Condition { Find-Instance } 60 'SCM-created instance Running in fresh session'
    $runtimeImage = Join-Path $env:ProgramFiles 'OpenAbstractions\tools\openabstractions.exe'
    $credential = $account.Credential
    function Find-Runtime([int]$ParentPid) {
        $found = @(Get-CimInstance Win32_Process -Filter "Name='openabstractions.exe'" | Where-Object {
            $_.ParentProcessId -eq $ParentPid -and $_.SessionId -eq $session
        })
        $live = @()
        foreach ($proc in $found) {
            $owner = Get-ProcessOwnerSid $proc
            if ($null -eq $owner) { continue }
            if ($owner -ne $state.Sid) { throw 'Runtime child has wrong principal' }
            if ($proc.ExecutablePath -ne $runtimeImage) { throw 'Runtime child has wrong executable' }
            $live += $proc
        }
        if ($live.Count -gt 1) { throw 'Multiple runtime children for one supervisor' }
        if ($live.Count -eq 1) { $live[0] }
    }
    $script:lastStatusFailure = $null
    $script:lastObserved = $null
    $script:lastStatusJson = $null
    $script:lastResolvedBindings = $null
    function New-RuntimeProbeInfo([string]$Arguments) {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $runtimeImage
        $info.Arguments = $Arguments
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.WorkingDirectory = Split-Path $runtimeImage
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.UserName = $credential.GetNetworkCredential().UserName
        $info.Domain = $credential.GetNetworkCredential().Domain
        $info.Password = $credential.Password
        $info.LoadUserProfile = $true
        return $info
    }
    function Test-RuntimeReady {
        $previousEndpoint = $env:ABSTRACTION_RUNTIME_ENDPOINT
        try {
            $env:ABSTRACTION_RUNTIME_ENDPOINT = $null
            # Keep the creation handle and derive bootstrap from the fresh user's token.
            $info = New-RuntimeProbeInfo 'status --json --timeout 5s'
            $probe = Invoke-StatusProcess $info
            if ($null -eq $probe.ExitCode) { throw 'Runtime status exit code was not observed' }
            $script:lastStatusJson = $probe.Output
            if ($probe.ExitCode -ne 0) {
                $line = Format-StatusFailure $probe.ExitCode $probe.Output $probe.Diagnostics
                $script:lastObserved = $line
                if ($line -ne $script:lastStatusFailure) { Write-Diagnostic $line | Out-Null; $script:lastStatusFailure = $line }
                return $false
            }
            $readiness = Get-RuntimeReadiness $probe.Output
            $script:lastObserved = $readiness.Summary
            if ($readiness.Ready) { $script:lastResolvedBindings = $readiness.Bindings; return $true }
            $line = 'runtime not ready: ' + $readiness.Summary
            if ($line -ne $script:lastStatusFailure) { Write-Diagnostic $line | Out-Null; $script:lastStatusFailure = $line }
            return $false
        } finally { $env:ABSTRACTION_RUNTIME_ENDPOINT = $previousEndpoint }
    }
    function Assert-DescribedReady([hashtable]$Bindings) {
        $previousEndpoint = $env:ABSTRACTION_RUNTIME_ENDPOINT
        try {
            $env:ABSTRACTION_RUNTIME_ENDPOINT = $null
            foreach ($endpoint in $Bindings.Keys) {
                $info = New-RuntimeProbeInfo ('status describe "' + $endpoint + '" --json --timeout 5s')
                $described = Invoke-StatusProcess $info
                if ($described.ExitCode -ne 0) { throw "Endpoint Describe failed for $endpoint" }
                try { $description = ConvertFrom-Json -InputObject $described.Output -ErrorAction Stop }
                catch { throw "Endpoint Describe returned invalid JSON for $endpoint" }
                if ($null -eq $description -or $description -is [array] -or $description.outcome -cne 'described') {
                    throw "Endpoint Describe did not describe $endpoint"
                }
                foreach ($contract in $Bindings[$endpoint]) {
                    $matches = @($description.services | Where-Object { $_.contract -ceq $contract })
                    if ($matches.Count -ne 1 -or $matches[0].readiness -cne 'ready' -or $matches[0].why -cne '') {
                        throw "Endpoint Describe did not list ready $contract"
                    }
                }
            }
        } finally { $env:ABSTRACTION_RUNTIME_ENDPOINT = $previousEndpoint }
    }
    # service-session.log is the uploaded windows-installer-logs file.
    function Save-LastRuntimeStatus([string]$Description) {
        if ($null -eq $script:lastStatusJson) { Write-Diagnostic "last runtime status for ${Description}: none observed" | Out-Null; return }
        Write-Diagnostic ("last runtime status for ${Description}: " + (Protect-StatusText $script:lastStatusJson)) | Out-Null
    }
    function Wait-RuntimeReady([int]$Seconds, [string]$Description) {
        $script:lastStatusFailure = $null
        $script:lastObserved = $null
        $script:lastStatusJson = $null
        $script:lastResolvedBindings = $null
        try {
            Wait-Condition { Test-RuntimeReady } $Seconds $Description | Out-Null
            Assert-DescribedReady $script:lastResolvedBindings
        }
        catch {
            $failure = $_
            try { Save-LastRuntimeStatus $Description } catch { Write-Warning 'Could not record the last runtime status' }
            if ($failure.Exception.Message -like 'Timed out after*') {
                $last = if ($script:lastObserved) { $script:lastObserved } else { 'no status observed' }
                throw "$($failure.Exception.Message); last status: $last"
            }
            throw $failure
        }
    }
    $runtime = Wait-Condition { Find-Runtime ([int]$first.ProcessId) } 60 'runtime child in fresh user session'
    Wait-RuntimeReady 60 'logging and config capability readiness'
    $oldRuntimePid = [int]$runtime.ProcessId
    Stop-Process -Id $oldRuntimePid -Force -ErrorAction Stop
    $recovered = Wait-Condition {
        $parent = Find-Instance
        if ($parent) {
            $child = Find-Runtime ([int]$parent.ProcessId)
            if ($child -and $child.ProcessId -ne $oldRuntimePid) { $child }
        }
    } 60 'runtime child replacement after child death'
    Wait-RuntimeReady 60 'capability readiness after runtime child death'
    $first = Find-Instance
    if (-not $first) { throw 'Supervisor disappeared after runtime recovery' }
    $oldRuntimePid = [int]$recovered.ProcessId
    $oldPid = [int]$first.ProcessId
    # Only the verified test-account service process is terminated; no service is fabricated or manually started.
    Stop-Process -Id $oldPid -Force -ErrorAction Stop
    $replacement = Wait-Condition {
        $next = Find-Instance
        if ($next -and $next.Name -eq $first.Name -and $next.ProcessId -ne $oldPid) { $next }
    } 60 'SCM restart with replacement PID'
    Wait-Condition {
        if (-not (Get-Process -Id $oldRuntimePid -ErrorAction SilentlyContinue)) { $true }
    } 30 'old runtime child exited after supervisor death' | Out-Null
    $finalRuntime = Wait-Condition { Find-Runtime ([int]$replacement.ProcessId) } 60 'runtime child after SCM recovery'
    Wait-RuntimeReady 60 'capability readiness after SCM recovery'
    $state.Session = $session
    $state.RuntimeVerified = $true
    $state.RuntimePid = [int]$finalRuntime.ProcessId
    $state | ConvertTo-Json | Set-Content -Encoding UTF8 $StatePath
    Write-Diagnostic "ok: runtime child death and supervisor death recovered logging/config readiness"
    Write-Diagnostic "ok: $($first.Name), session $session, PID $oldPid replaced by $($replacement.ProcessId)"
    if ($sessionCommand) {
        $context = @{ User=$user; Sid=$state.Sid; Session=$session; Instance=$replacement.Name; SupervisorPid=[int]$replacement.ProcessId; RuntimePid=$state.RuntimePid }
        Invoke-SessionCommand $sessionCommand $CommandArguments $CommandSeconds $account $context
        $state.CommandVerified = $true
        $state | ConvertTo-Json | Set-Content -Encoding UTF8 $StatePath
        Write-Diagnostic "ok: session command ran as the account against the SCM-created instance $($replacement.Name)"
    }
    # Disconnect retains the session so MSI uninstall must remove the live clone before Cleanup logs off.
} catch {
    try {
        $extended = [int]$client.ExtendedDisconnectReason
        Write-Diagnostic "RDP extended=$extended description=$($client.GetErrorDescription($hostControl.DisconnectReason,$extended))"
    } catch { Write-Diagnostic 'RDP extended error unavailable' }
    Write-ServerDiagnostics
    Write-Diagnostic "RDP loginComplete=$($hostControl.LoginComplete) disconnectReason=$($hostControl.DisconnectReason); $($_.Exception.Message)"
    throw
} finally {
    try { Save-SessionActivationDiagnostics $activation (Join-Path (Get-Location).Path 'service-session-activation') }
    catch { Write-Warning "Could not retain activation diagnostics: $($_.FullyQualifiedErrorId)" }
    if ($client -and $client.Connected -ne 0) { $client.Disconnect() }
    $form.Close()
    $form.Dispose()
}
exit 0
