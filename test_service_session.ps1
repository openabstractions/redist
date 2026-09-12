param(
    [ValidateSet('Verify','Cleanup','ValidateOnly')][string]$Mode = 'ValidateOnly',
    [string]$StatePath = (Join-Path $env:TEMP 'oa-service-session.json')
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
if ($Mode -eq 'ValidateOnly') { 'Harness compiled; no account, session, firewall or service changes.'; exit 0 }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This mutating fixture is restricted to disposable GitHub-hosted runners.'
}
function Write-Diagnostic([string]$Text) {
    $Text | Write-Output
    $Text | Add-Content -Encoding UTF8 'service-session.log'
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
if ($Mode -eq 'Cleanup') {
    if (-not (Test-Path $StatePath)) { exit 0 }
    $state = Get-Content $StatePath -Raw | ConvertFrom-Json
    if ($state.User -notmatch '^oa_ci_[0-9a-f]{10}$') { throw 'Refusing unrecognized cleanup account' }
    $account = Get-LocalUser -Name $state.User -ErrorAction SilentlyContinue
    if ($account -and $state.Sid -and $account.SID.Value -ne $state.Sid) { throw 'Cleanup account SID changed' }
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
$started = Get-Date
$user = 'oa_ci_' + [Guid]::NewGuid().ToString('N').Substring(0,10)
$random = New-Object byte[] 30
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($random) } finally { $rng.Dispose() }
$password = 'Aa1!' + [Convert]::ToBase64String($random)
Write-Output "::add-mask::$password"
$state = @{ User=$user; Sid=''; Rule=('OA-CI-RDP-'+[Guid]::NewGuid().ToString('N')); Deny=(Get-ItemProperty $rdpKey).fDenyTSConnections }
$state | ConvertTo-Json | Set-Content -Encoding UTF8 $StatePath
# Blocks every non-loopback source before changing RDP availability. Never enable a broad allow rule.
$remote = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
foreach ($protocol in 'TCP','UDP') {
    New-NetFirewallRule -Name "$($state.Rule)-$protocol" -DisplayName "$($state.Rule)-$protocol" -Direction Inbound -Action Block -Protocol $protocol -LocalPort 3389 -RemoteAddress $remote -Profile Any | Out-Null
}
$account = New-LocalUser -Name $user -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires
$state.Sid = $account.SID.Value
$state | ConvertTo-Json | Set-Content -Encoding UTF8 $StatePath
$group = Get-LocalGroup -SID 'S-1-5-32-555'
Add-LocalGroupMember -Group $group -Member $account
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
    $expectedImage = Join-Path $env:ProgramFiles 'OpenAbstractions\tools\jobdw.exe'
    function Find-Instance {
        foreach ($svc in @(Get-CimInstance Win32_Service -Filter "Name LIKE 'OpenAbstractionsSupervisor_%'")) {
            if ($svc.State -ne 'Running' -or $svc.ProcessId -eq 0) { continue }
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$($svc.ProcessId)"
            if (-not $proc -or $proc.SessionId -ne $session) { continue }
            $owner = Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid
            if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $state.Sid) { throw 'Instance has wrong principal' }
            if ($proc.ExecutablePath -ne $expectedImage) { throw 'Instance has wrong executable' }
            return $svc
        }
    }
    $first = Wait-Condition { Find-Instance } 60 'SCM-created instance Running in fresh session'
    $oldPid = [int]$first.ProcessId
    # Only the verified test-account service process is terminated; no service is fabricated or manually started.
    Stop-Process -Id $oldPid -Force -ErrorAction Stop
    $replacement = Wait-Condition {
        $next = Find-Instance
        if ($next -and $next.Name -eq $first.Name -and $next.ProcessId -ne $oldPid) { $next }
    } 60 'SCM restart with replacement PID'
    Write-Diagnostic "ok: $($first.Name), session $session, PID $oldPid replaced by $($replacement.ProcessId)"
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
    if ($client -and $client.Connected -ne 0) { $client.Disconnect() }
    $form.Close()
    $form.Dispose()
}
exit 0
