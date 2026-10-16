#requires -Version 7.0
<#
Fixed Certum Desktop session adapter for a fresh signing-only GitHub runner.
See certum_simplysign.NOTICE.txt. Credential values never enter child arguments,
child environments, files, diagnostics, screenshots or the public session result.
The workflow owns fresh-runner isolation, branch protection and artifact binding.
#>
param(
    [ValidateSet('Connect', 'Disconnect')][string]$Mode,
    [string]$InstallerPath,
    [string]$SessionPath,
    [switch]$LibraryOnly,
    [switch]$Help
)
$PolicyPath = Join-Path $PSScriptRoot 'certum_simplysign.json'
$script:CertumStage = 'policy'
$script:CertumCleanup = 'not-started'
$script:CertumSchemaReason = 'not-checked'
$script:CertumEditCount = 'unknown'
$script:CertumObservationResult = 'not-checked'
$script:CertumInitialCounts = $null
$script:CertumRepeatedCounts = $null
$script:CertumRoleObservation = $null
$script:CertumSubmitStep = 'not-checked'
$script:CertumSubmitFailureStep = $null
$script:CertumSubmitField = 'none'
$script:CertumSubmitFailed = $false

function ConvertTo-CertumCountBucket($Count) {
    if ($Count -cin @('zero','one','two','many')) { return $Count }
    return 'unknown'
}

function Write-CertumFailure {
    # Only fixed public categories are emitted. Never format an ErrorRecord.
    $stages = @('policy','runner','session-path','credential-validation','installer-validation',
        'installer-execution','desktop-validation','desktop-configuration','desktop-launch',
        'login-window','login-schema','credential-submit','certificate-discovery',
        'certificate-validation','certificate-chain','session-persist','disconnect-receipt','disconnect-process')
    $cleanups = @('not-started','no-process-started','process-unproven','owned-process-active',
        'process-stopped','failed','no-owned-receipt')
    $stage = if ($script:CertumStage -cin $stages) { $script:CertumStage } else { 'unknown' }
    $cleanup = if ($script:CertumCleanup -cin $cleanups) { $script:CertumCleanup } else { 'unknown' }
    $reasons = @('not-checked','assemblies','provider-initialization','focus','window-identity','field-discovery','edit-count',
        'field-owner','field-state','label-absent','label-owner','label-state','label-role','accepted')
    $reason = if ($script:CertumSchemaReason -cin $reasons) { $script:CertumSchemaReason } else { 'unknown' }
    $count = if ($script:CertumEditCount -cin @('zero','one','two','many')) { $script:CertumEditCount } else { 'unknown' }
    [Console]::Error.WriteLine("SimplySign session operation failed; stage=$stage; category=operation-failed; cleanup=$cleanup; schema_reason=$reason; edit_count=$count; credential diagnostics are disabled.")
    if ($script:CertumSubmitFailed) {
        $steps = @('target-discovery','pattern-preflight','target-revalidation','field-write','button-invoke')
        $rawStep = if ($script:CertumSubmitFailureStep) {$script:CertumSubmitFailureStep} else {$script:CertumSubmitStep}
        $step = if ($rawStep -cin $steps) {$rawStep} else {'unknown'}
        $field = if ($script:CertumSubmitField -cin @('username','token','none')) {$script:CertumSubmitField} else {'unknown'}
        [Console]::Error.WriteLine("SimplySign target submit observation; step=$step; field=$field.")
    }
    if ($null -ne $script:CertumRoleObservation) {
        $row = $script:CertumRoleObservation
        $result = if ($row.result -cin @('observed','guard-or-query-failed')) {$row.result} else {'unknown'}
        $values = @()
        foreach ($index in 0,1) {
            $items = @($row.fields)
            $field = if ($items.Count -gt $index) {$items[$index]} else {$null}
            $id = if ($field.id -cin @('username','token','other')) {$field.id} else {'unknown'}
            $label = if ($field.label -cin @('username','token','username-hint','token-hint','proxy-user','proxy-password','other')) {$field.label} else {'unknown'}
            $password = if ($field.password -cin @('yes','no')) {$field.password} else {'unknown'}
            $values += "field$($index+1)_id=$id; field$($index+1)_label=$label; field$($index+1)_password=$password"
        }
        $duplicate = if ($row.duplicate_label -cin @('yes','no')) {$row.duplicate_label} else {'unknown'}
        [Console]::Error.WriteLine("SimplySign role observation; result=$result; $($values -join '; '); duplicate_label=$duplicate.")
    }
    if ($script:CertumObservationResult -cne 'not-checked') {
        $result = if ($script:CertumObservationResult -cin @('observed','guard-or-query-failed','deadline')) { $script:CertumObservationResult } else { 'unknown' }
        $initial = $script:CertumInitialCounts; $repeated = $script:CertumRepeatedCounts
        $it = ConvertTo-CertumCountBucket $initial.uia_total; $ie = ConvertTo-CertumCountBucket $initial.uia_edit
        $ine = ConvertTo-CertumCountBucket $initial.native_edit
        $rt = ConvertTo-CertumCountBucket $repeated.uia_total; $re = ConvertTo-CertumCountBucket $repeated.uia_edit
        $rne = ConvertTo-CertumCountBucket $repeated.native_edit
        [Console]::Error.WriteLine("SimplySign schema observation; result=$result; initial_uia_total=$it; initial_uia_edit=$ie; initial_native_edit=$ine; repeated_uia_total=$rt; repeated_uia_edit=$re; repeated_native_edit=$rne.")
    }
}

function Read-CertumPolicy([string]$Path) {
    try { $policy = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable }
    catch { throw 'invalid public signing policy' }
    $cert = $policy.certificate
    if ($null -eq $cert -or $cert.sha1 -notmatch '^[0-9A-Fa-f]{40}$' -or
        $cert.sha256 -notmatch '^[0-9A-Fa-f]{64}$' -or -not $cert.subject -or -not $cert.issuer) {
        throw 'certificate policy is unresolved'
    }
    if ($policy.schema -ne 1 -or $cert.rsa_bits -ne 3072 -or $cert.eku -ne '1.3.6.1.5.5.7.3.3' -or
        $policy.totp.algorithm -cne 'SHA256' -or $policy.totp.digits -ne 6 -or $policy.totp.period -ne 30 -or
        $policy.installer.sha256 -notmatch '^[0-9a-f]{64}$' -or $policy.installer.bytes -le 0 -or
        $policy.installer.publisher_sha1 -notmatch '^[0-9A-F]{40}$' -or
        $policy.installer.publisher_cn -cne 'Asseco Data Systems S.A.') { throw 'invalid public signing policy' }
    return $policy
}

function ConvertFrom-CertumOtpUri([string]$Text) {
    $key = $null; $complete = $false
    try {
        $uri = [Uri]$Text
        if ($uri.Scheme -cne 'otpauth' -or $uri.Host -cne 'totp' -or $uri.Fragment -or
            $uri.UserInfo -or $uri.Port -ne -1 -or $uri.AbsolutePath.Length -lt 2) { throw 'invalid' }
        $fields = @{}
        foreach ($part in $uri.Query.TrimStart('?').Split('&')) {
            $pair = $part.Split('=', 2)
            if ($pair.Count -ne 2) { throw 'invalid' }
            $name = [Uri]::UnescapeDataString($pair[0])
            if ($name -cnotin @('secret', 'algorithm', 'digits', 'period', 'issuer') -or $fields.ContainsKey($name)) { throw 'invalid' }
            $fields[$name] = [Uri]::UnescapeDataString($pair[1])
        }
        if ($fields.algorithm -cne 'SHA256' -or $fields.digits -cne '6' -or $fields.period -cne '30' -or
            $fields.secret -cnotmatch '^[A-Z2-7]{16,}={0,6}$') { throw 'invalid' }
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        $secret = $fields.secret.TrimEnd('=')
        $key = [byte[]]::new([Math]::Floor($secret.Length * 5 / 8))
        $buffer = 0; $bits = 0; $index = 0
        foreach ($char in $secret.ToCharArray()) {
            $buffer = ($buffer -shl 5) -bor $alphabet.IndexOf($char); $bits += 5
            if ($bits -ge 8) {
                $bits -= 8; $key[$index++] = [byte](($buffer -shr $bits) -band 255)
                $buffer = $buffer -band ((1 -shl $bits) - 1)
            }
        }
        if ($buffer -ne 0 -or $key.Length -lt 10 -or $secret.Length % 8 -notin @(0,2,4,5,7) -or
            ($fields.secret.Contains('=') -and $fields.secret.Length % 8 -ne 0)) { throw 'invalid' }
        $complete = $true
        return @{Key = $key}
    } catch { throw 'invalid OTP credential metadata' }
    finally {
        if (-not $complete -and $null -ne $key) { [Array]::Clear($key) }
        if ($null -ne $fields) { $fields.Clear() }
        $secret = $null; $Text = $null
    }
}

function Get-CertumTotp([byte[]]$Key, [long]$UnixSeconds) {
    $counter = [BitConverter]::GetBytes([long][Math]::Floor($UnixSeconds / 30))
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counter) }
    $hmac = [Security.Cryptography.HMACSHA256]::new($Key)
    $hash = $null
    try {
        $hash = $hmac.ComputeHash($counter)
        $offset = $hash[-1] -band 15
        $number = (([int]$hash[$offset] -band 127) -shl 24) -bor ([int]$hash[$offset + 1] -shl 16) -bor
                  ([int]$hash[$offset + 2] -shl 8) -bor [int]$hash[$offset + 3]
        return ($number % 1000000).ToString('D6')
    } finally {
        $hmac.Dispose(); [Array]::Clear($counter)
        if ($null -ne $hash) { [Array]::Clear($hash) }
    }
}

function New-CertumProcessInfo([string]$File, [string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File; $info.UseShellExecute = $false
    $info.Environment.Clear()
    foreach ($name in @('SystemRoot','WINDIR','SystemDrive','COMSPEC','TEMP','TMP','PATH','PATHEXT',
            'ProgramFiles','ProgramFiles(x86)','PROGRAMDATA','APPDATA','LOCALAPPDATA','USERPROFILE',
            'HOMEDRIVE','HOMEPATH','USERNAME','USERDOMAIN','SESSIONNAME','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($null -ne $value) { $info.Environment[$name] = $value }
    }
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    # No application stdout/stderr is relayed or persisted. It may contain account details.
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    return $info
}

function Initialize-CertumHandleIsolation {
    if ('CertumHandleIsolation' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CertumHandleIsolation {
 [DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int id);
 [DllImport("kernel32.dll")] public static extern bool GetHandleInformation(IntPtr handle,out uint flags);
 [DllImport("kernel32.dll")] public static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
}
'@
}

function Get-CertumHostHandleState {
    Initialize-CertumHandleIsolation
    $seen = @{}
    foreach ($id in @(-11,-12)) {
        $handle = [CertumHandleIsolation]::GetStdHandle($id)
        if ($handle -eq [IntPtr]::Zero -or $handle -eq [IntPtr](-1) -or $seen.ContainsKey($handle)) { continue }
        $seen[$handle] = $true
        [uint32]$flags = 0
        if (-not [CertumHandleIsolation]::GetHandleInformation($handle,[ref]$flags)) { throw 'host handle isolation query failed' }
        @{handle=$handle; inherit=($flags -band 1)}
    }
}

function Set-CertumHandleInheritance($State, [uint32]$Inherit) {
    if (-not [CertumHandleIsolation]::SetHandleInformation($State.handle,1,$Inherit)) { throw 'host handle isolation update failed' }
}

function Start-CertumChild([string]$File, [string[]]$Arguments) {
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = New-CertumProcessInfo $File $Arguments
    $changed = @(); $failure = $null; $restoreFailed = $false; $started = $false
    try {
        # .NET CreateProcess inherits unrelated inheritable handles even with its
        # own redirected stdio. Hosted runner pipes must close when Connect exits.
        # This adapter launches children serially; restore borrowed flags before
        # returning and leave the child's dedicated, null-drained pipes intact.
        foreach ($state in @(Get-CertumHostHandleState)) {
            if ($state.inherit -eq 0) { continue }
            $changed += $state
            Set-CertumHandleInheritance $state 0
        }
        $started = $process.Start()
        if (-not $started) { throw 'owned child did not start' }
    } catch { $failure = $_ }
    finally {
        foreach ($state in $changed) {
            try { Set-CertumHandleInheritance $state $state.inherit }
            catch { $restoreFailed = $true; if ($null -eq $failure) { $failure = $_ } }
        }
    }
    if ($null -ne $failure -or $restoreFailed) {
        try {
            if ($started) { $process.Kill(); $null = $process.WaitForExit(10000) }
        } catch { } # Preserve the original setup/start/restoration failure.
        finally { $process.Dispose() }
        throw $failure
    }
    # Drain without a log, preventing pipe backpressure and credential diagnostics.
    $null = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
    $null = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
    return $process
}

function Assert-CertumRunner($Policy) {
    if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        $env:RUNNER_OS -cne 'Windows' -or $env:RUNNER_ARCH -cne 'X64' -or $env:OA_CERTUM_SIGNING_ONLY -cne '1' -or
        $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_REPOSITORY -cne $Policy.runner.repository -or
        $env:GITHUB_REF -cne $Policy.runner.ref -or $env:GITHUB_ACTOR -cne $Policy.runner.actor -or
        $env:GITHUB_TRIGGERING_ACTOR -cne $Policy.runner.actor -or
        $env:GITHUB_WORKFLOW_REF -cne $Policy.runner.workflow_ref -or $env:GITHUB_SHA -notmatch '^[0-9a-f]{40}$') {
        throw 'fresh trusted signing-only runner required'
    }
}

function Assert-CertumSessionPath([string]$Path) {
    $root = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or -not $full.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'session path must stay inside runner temporary directory'
    }
    $parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($full))
    while ($null -ne $parent) {
        if (-not $parent.Exists -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'linked session path refused' }
        if ($parent.FullName -eq $root) { break }
        $parent = $parent.Parent
    }
    if (Test-Path -LiteralPath $full) {
        if ((Get-Item -LiteralPath $full).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'linked session path refused' }
    }
    return $full
}

function Get-CertumCertificateInfo($Certificate, $Expected, [datetime]$Now = [datetime]::UtcNow) {
    $Now = $Now.ToUniversalTime()
    $sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Certificate.RawData))
    if ($Certificate.Thumbprint -ine $Expected.sha1 -or $sha256 -ine $Expected.sha256 -or
        $Certificate.Subject -cne $Expected.subject -or $Certificate.Issuer -cne $Expected.issuer -or
        ($Expected.ContainsKey('serial') -and $Certificate.SerialNumber -ine $Expected.serial) -or
        ($Expected.ContainsKey('der_bytes') -and $Certificate.RawData.Length -ne $Expected.der_bytes) -or
        ($Expected.ContainsKey('not_before') -and $Certificate.NotBefore.ToUniversalTime() -ne [datetime]$Expected.not_before) -or
        ($Expected.ContainsKey('not_after') -and $Certificate.NotAfter.ToUniversalTime() -ne [datetime]$Expected.not_after) -or
        $Now -lt $Certificate.NotBefore.ToUniversalTime() -or $Now -gt $Certificate.NotAfter.ToUniversalTime() -or
        -not $Certificate.HasPrivateKey) { throw 'selected certificate identity or validity differs' }
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    try { if ($null -eq $rsa -or $rsa.KeySize -ne 3072) { throw 'selected certificate must use RSA3072' } }
    finally { if ($null -ne $rsa) { $rsa.Dispose() } }
    $eku = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -ne 1 -or '1.3.6.1.5.5.7.3.3' -notin @($eku[0].EnhancedKeyUsages | ForEach-Object Value)) {
        throw 'selected certificate lacks code-signing EKU'
    }
    return @{sha1=$Certificate.Thumbprint; sha256=$sha256; subject=$Certificate.Subject; issuer=$Certificate.Issuer;
        not_before=$Certificate.NotBefore.ToUniversalTime().ToString('o'); not_after=$Certificate.NotAfter.ToUniversalTime().ToString('o');
        rsa_bits=3072; private_key_association=$true; signing_usability='requires signed probe'}
}

function Assert-CertumChainResult([bool]$Built, $Statuses) {
    if (-not $Built -or @($Statuses | Where-Object Status -ne 'NoError').Count -ne 0) {
        throw 'selected certificate chain or revocation is unresolved'
    }
}

function Assert-CertumChain($Certificate) {
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = 'Online'
        $chain.ChainPolicy.RevocationFlag = 'EntireChain'
        $chain.ChainPolicy.VerificationFlags = 'NoFlag'
        $null = $chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
        Assert-CertumChainResult ($chain.Build($Certificate)) $chain.ChainStatus
    } finally { $chain.Dispose() }
}

function Get-CertumOptionalRegistryValue([string]$Path, [string]$Name) {
    # Missing optional settings are normal on a fresh signing runner. GetValue
    # returns null for absence while preserving key/access failures.
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    try { return $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    finally { $key.Dispose() }
}

function Initialize-CertumWindows {
    if ('CertumWindow' -as [type]) { return }
    Add-Type @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class CertumWindow {
    public delegate bool EnumProc(IntPtr h, IntPtr unused);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr unused);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc callback, IntPtr unused);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, System.Text.StringBuilder value, int maximum);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    public static IntPtr[] Owned(uint pid) {
        var found = new List<IntPtr>();
        EnumWindows((h, unused) => { uint owner; GetWindowThreadProcessId(h, out owner);
            if (owner == pid && IsWindowVisible(h)) found.Add(h); return true; }, IntPtr.Zero);
        return found.ToArray();
    }
    public static int EditChildren(IntPtr handle, uint pid) {
        int count = 0; bool expired = false;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        EnumChildWindows(handle, (h, unused) => {
            if (clock.ElapsedMilliseconds >= 250) { expired = true; return false; }
            uint owner; if (GetWindowThreadProcessId(h, out owner) == 0) { expired = true; return false; }
            if (owner == pid) {
                var value = new System.Text.StringBuilder(256);
                if (GetClassName(h, value, value.Capacity) == 0) { expired = true; return false; }
                string name = value.ToString();
                if (name == "Edit" || name.StartsWith("WindowsForms10.EDIT.", StringComparison.Ordinal)) count++;
            }
            return true;
        }, IntPtr.Zero);
        return expired ? -1 : count;
    }
}
'@
}

function Assert-CertumFocus([IntPtr]$Handle, $Process) {
    $Process.Refresh()
    [uint32]$owner = 0
    $null = [CertumWindow]::GetWindowThreadProcessId($Handle, [ref]$owner)
    if ($Process.HasExited -or $owner -ne $Process.Id -or [CertumWindow]::GetForegroundWindow() -ne $Handle -or
        @([CertumWindow]::Owned($Process.Id)).Count -ne 1) { throw 'owned login focus changed' }
}

function Assert-CertumDeadline($Clock) {
    if ($Clock.Elapsed.TotalSeconds -ge 120) { throw 'authentication deadline exceeded' }
}

function Get-CertumLoginFieldRole($Field) {
    # Pinned LoginForm tUserName/tPassword identities are confirmed by the
    # guarded hosted observation. WinForms' associated labels can name another
    # field. Exact control ID plus actual password state owns credential roles.
    $current = $Field.Current
    if ($current.IsPassword -isnot [bool]) { return 'unknown' }
    if ($current.AutomationId -ceq 'tUserName' -and $current.IsPassword -eq $false) { return 'username' }
    if ($current.AutomationId -ceq 'tPassword' -and $current.IsPassword -eq $true) { return 'token' }
    return 'unknown'
}

function Assert-CertumLoginFields($Fields, [int]$ProcessId) {
    $number = @($Fields).Count
    $script:CertumEditCount = switch ($number) { 0 {'zero'} 1 {'one'} 2 {'two'} default {'many'} }
    $script:CertumSchemaReason = 'edit-count'
    if ($number -ne 2) { throw 'expected exactly two owned login fields' }
    $index = 0
    foreach ($field in $Fields) {
        $script:CertumSchemaReason = 'field-owner'
        if ($field.Current.ProcessId -ne $ProcessId) { throw 'login field identity differs' }
        $script:CertumSchemaReason = 'field-state'
        if (-not $field.Current.IsEnabled -or -not $field.Current.IsKeyboardFocusable -or $field.Current.IsOffscreen) { throw 'login field identity differs' }
        $label = $field.Current.LabeledBy
        $script:CertumSchemaReason = 'label-absent'
        if ($null -eq $label) { throw 'login field identity differs' }
        $script:CertumSchemaReason = 'label-owner'
        if ($label.Current.ProcessId -ne $ProcessId) { throw 'login field identity differs' }
        $script:CertumSchemaReason = 'label-state'
        if ($label.Current.IsOffscreen) { throw 'login field identity differs' }
        $script:CertumSchemaReason = 'label-role'
        if ((Get-CertumLoginFieldRole $field) -cne @('username','token')[$index]) { throw 'login field identity differs' }
        $index++
    }
    $script:CertumSchemaReason = 'accepted'
}

function Select-CertumLoginFields($Fields, [int]$ProcessId) {
    $ordered = @($Fields | Sort-Object { switch (Get-CertumLoginFieldRole $_) { 'username' {0} 'token' {1} default {2} } })
    Assert-CertumLoginFields $ordered $ProcessId
    return $ordered
}

function Get-CertumLoginWindow([IntPtr]$Handle, $Process) {
    Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
    $script:CertumSchemaReason = 'focus'
    Assert-CertumFocus $Handle $Process
    $script:CertumSchemaReason = 'window-identity'
    $window = [Windows.Automation.AutomationElement]::FromHandle($Handle)
    if ($window.Current.ProcessId -ne $Process.Id -or $window.Current.IsOffscreen -or
        $window.Current.Name -cne 'SimplySign Desktop') {
        throw 'expected Desktop login window identity'
    }
    return $window
}

function Initialize-CertumClientProviders {
    if ($script:CertumClientProvidersReady) { return }
    $script:CertumSchemaReason = 'provider-initialization'
    try {
        # FromHandle must initialize UIA before registering the Microsoft proxy table.
        # Caller has already established the exact owned root. Use the OS-installed
        # runtime provider beside the already loaded Microsoft UIA client, never
        # a current-directory/PATH lookup. CoreCLR unifies framework LoadFrom
        # requests to this runtime assembly; validate the bytes actually loaded.
        $client = [Windows.Automation.AutomationElement].Assembly
        $path = Join-Path ([IO.Path]::GetDirectoryName($client.Location)) 'UIAutomationClientSideProviders.dll'
        $file = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'provider path differs' }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -cne
            'CN=.NET, O=Microsoft Corporation, L=Redmond, S=Washington, C=US') { throw 'provider publisher differs' }
        $identity = [Reflection.AssemblyName]::GetAssemblyName($path)
        $expected = 'UIAutomationClientSideProviders, Version=' + $client.GetName().Version + ', Culture=neutral, PublicKeyToken=b77a5c561934e089'
        if ($identity.FullName -cne $expected) { throw 'provider identity differs' }
        $expectedBytes = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $assembly = [Reflection.Assembly]::LoadFrom($path)
        # Exact frozen locator agreement plus expected bytes is provenance for
        # this load; it makes no general filesystem same-file identity claim.
        if (-not [string]::Equals($assembly.Location, $file.FullName, [StringComparison]::Ordinal) -or
            $assembly.FullName -cne $identity.FullName -or
            (Get-FileHash -LiteralPath $assembly.Location -Algorithm SHA256).Hash -cne $expectedBytes) { throw 'loaded provider differs' }
        $type = $assembly.GetType('UIAutomationClientsideProviders.UIAutomationClientSideProviders', $true)
        $table = $type.GetField('ClientSideProviderDescriptionTable').GetValue($null)
        if ($null -eq $table -or $table.Length -eq 0) { throw 'provider table absent' }
        [Windows.Automation.ClientSettings]::RegisterClientSideProviders($table)
        $script:CertumClientProvidersReady = $true
    } catch { throw 'Microsoft UI Automation provider initialization failed' }
}

function Get-CertumLoginFields([IntPtr]$Handle, $Process) {
    $script:CertumSchemaReason = 'assemblies'; $script:CertumEditCount = 'unknown'
    $window = Get-CertumLoginWindow $Handle $Process
    Initialize-CertumClientProviders
    $condition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Edit)
    # Roles come from exact pinned control IDs and password states, never position.
    # An unsupported provider schema refuses before any credential reaches the clipboard.
    $script:CertumSchemaReason = 'field-discovery'
    $fields = @($window.FindAll([Windows.Automation.TreeScope]::Descendants, $condition))
    return Select-CertumLoginFields $fields $Process.Id
}

function Get-CertumNumberBucket([int]$Number) {
    switch ($Number) { 0 {'zero'} 1 {'one'} 2 {'two'} default { if ($Number -gt 2) {'many'} else {'unknown'} } }
}

function Assert-CertumDiagnosticIdentity([IntPtr]$Handle, $Process, $Session, $Clock) {
    Assert-CertumDeadline $Clock
    Assert-CertumFocus $Handle $Process
    if ($Process.Id -ne $Session.process_id -or $Process.Path -ine $Session.executable -or
        $Process.StartTime.ToUniversalTime().Ticks -ne ([datetime]$Session.process_started).ToUniversalTime().Ticks) {
        throw 'diagnostic process identity changed'
    }
    return Get-CertumLoginWindow $Handle $Process
}

function Measure-CertumLoginSchema([IntPtr]$Handle, $Process, $Session, $Clock) {
    $window = Assert-CertumDiagnosticIdentity $Handle $Process $Session $Clock
    $total = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition).Count
    Assert-CertumDeadline $Clock
    $condition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Edit)
    $edits = $window.FindAll([Windows.Automation.TreeScope]::Descendants, $condition).Count
    Assert-CertumDeadline $Clock
    $native = [CertumWindow]::EditChildren($Handle, $Process.Id)
    $null = Assert-CertumDiagnosticIdentity $Handle $Process $Session $Clock
    return @{uia_total=(Get-CertumNumberBucket $total);uia_edit=(Get-CertumNumberBucket $edits);native_edit=(Get-CertumNumberBucket $native)}
}

function Measure-CertumLoginRoles([IntPtr]$Handle, $Process, $Session, $Clock) {
    $window = Assert-CertumDiagnosticIdentity $Handle $Process $Session $Clock
    $condition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Edit)
    $fields = @($window.FindAll([Windows.Automation.TreeScope]::Descendants, $condition))
    if ($fields.Count -ne 2) { throw 'diagnostic field count changed' }
    # The original refusal may occur on the first field: independently guard
    # BOTH fields and their labels before observing any semantic metadata.
    foreach ($field in $fields) {
        Assert-CertumDeadline $Clock
        $current = $field.Current; $label = $current.LabeledBy
        if ($current.ProcessId -ne $Process.Id -or -not $current.IsEnabled -or
            -not $current.IsKeyboardFocusable -or $current.IsOffscreen -or $null -eq $label -or
            $label.Current.ProcessId -ne $Process.Id -or $label.Current.IsOffscreen -or -not $label.Current.IsEnabled) {
            throw 'diagnostic field identity changed'
        }
    }
    $rows = @($fields | ForEach-Object {
        Assert-CertumDeadline $Clock
        $id = switch -CaseSensitive ($_.Current.AutomationId) { 'tUserName' {'username'} 'tPassword' {'token'} default {'other'} }
        $label = switch -CaseSensitive ($_.Current.LabeledBy.Current.Name) {
            'ID:' {'username'} 'One-time code:' {'token'}
            'Your e-mail address' {'username-hint'} 'Token generated by the SimplySign' {'token-hint'}
            'User:' {'proxy-user'} 'Password:' {'proxy-password'} default {'other'}
        }
        @{id=$id;label=$label;password=$(if ($_.Current.IsPassword) {'yes'} else {'no'})}
    })
    $duplicate = [Windows.Automation.Automation]::Compare($fields[0].Current.LabeledBy, $fields[1].Current.LabeledBy)
    $null = Assert-CertumDiagnosticIdentity $Handle $Process $Session $Clock
    return @{result='observed';fields=$rows;duplicate_label=$(if ($duplicate) {'yes'} else {'no'})}
}

function Assert-CertumInitialLoginSchema([IntPtr]$Handle, $Process, $Session, $Clock) {
    $script:CertumObservationResult = 'not-checked'; $script:CertumInitialCounts = $null; $script:CertumRepeatedCounts = $null
    $script:CertumRoleObservation = $null
    try { $null = Get-CertumLoginFields $Handle $Process }
    catch {
        $reason = $script:CertumSchemaReason; $count = $script:CertumEditCount
        if ($reason -ceq 'label-role' -and $count -ceq 'two') {
            $script:CertumRoleObservation = @{result='guard-or-query-failed';fields=@(@{},@{})}
            try { $script:CertumRoleObservation = Measure-CertumLoginRoles $Handle $Process $Session $Clock } catch {}
        }
        if ($reason -ceq 'edit-count' -and $count -ceq 'zero') {
            $script:CertumObservationResult = 'guard-or-query-failed'
            try {
                $script:CertumInitialCounts = Measure-CertumLoginSchema $Handle $Process $Session $Clock
                if ($Clock.Elapsed.TotalSeconds -ge 118) { $script:CertumObservationResult = 'deadline' }
                else {
                    Start-Sleep -Milliseconds 1000
                    Assert-CertumDeadline $Clock
                    $script:CertumRepeatedCounts = Measure-CertumLoginSchema $Handle $Process $Session $Clock
                    $script:CertumObservationResult = 'observed'
                }
            } catch { $script:CertumObservationResult = if ($Clock.Elapsed.TotalSeconds -ge 120) {'deadline'} else {'guard-or-query-failed'} }
        }
        $script:CertumSchemaReason = $reason; $script:CertumEditCount = $count
        # A later observation never changes the original refusal or routes credentials.
        throw 'login schema refused'
    }
}

function Test-CertumSameTarget($Captured, $Fresh) { return [Windows.Automation.Automation]::Compare($Captured, $Fresh) }

function Get-CertumSubmitButton([IntPtr]$Handle, $Process) {
    $window = Get-CertumLoginWindow $Handle $Process
    $condition = [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::AutomationIdProperty, 'bOk')
    $buttons = @($window.FindAll([Windows.Automation.TreeScope]::Descendants, $condition))
    if ($buttons.Count -ne 1) { throw 'expected exactly one owned login button' }
    $button = $buttons[0]; $current = $button.Current
    # Pinned 9.4.5.95 LoginForm.InitializeComponent names Button bOk and
    # binds Click to bOk_Click, which reads tUserName.Text/tPassword.Text.
    if ($current.AutomationId -cne 'bOk' -or $current.ControlType -ne [Windows.Automation.ControlType]::Button -or
        $current.ProcessId -ne $Process.Id -or -not $current.IsEnabled -or $current.IsOffscreen) {
        throw 'login button identity differs'
    }
    return $button
}

function Get-CertumValuePattern($Field) {
    $pattern = $Field.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern)
    if ($null -eq $pattern -or $pattern.Current.IsReadOnly -isnot [bool] -or $pattern.Current.IsReadOnly) { throw 'login field is read-only or unsupported' }
    return $pattern
}
function Get-CertumInvokePattern($Button) {
    $pattern = $Button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)
    if ($null -eq $pattern) { throw 'login button invoke is unsupported' }
    return $pattern
}

function Assert-CertumSubmitTargets($CapturedFields, $CapturedButton, [IntPtr]$Handle, $Process, $Clock) {
    Assert-CertumDeadline $Clock
    $fresh = @(Get-CertumLoginFields $Handle $Process)
    $button = Get-CertumSubmitButton $Handle $Process
    foreach ($index in 0,1) {
        if (-not (Test-CertumSameTarget $CapturedFields[$index] $fresh[$index])) { throw 'login field replaced' }
    }
    if (-not (Test-CertumSameTarget $CapturedButton $button)) { throw 'login button replaced' }
    Assert-CertumFocus $Handle $Process
    Assert-CertumDeadline $Clock
}

function Submit-CertumCredential([IntPtr]$Handle, $Process, [string]$Username, [string]$Otp, $Clock) {
    $script:CertumSubmitFailed = $false
    $script:CertumSubmitFailureStep = $null; $script:CertumSubmitField = 'none'
    try {
        $script:CertumSubmitStep = 'target-discovery'
        Assert-CertumDeadline $Clock
        $fields = @(Get-CertumLoginFields $Handle $Process)
        $button = Get-CertumSubmitButton $Handle $Process
        $script:CertumSubmitStep = 'pattern-preflight'
        # Prove BOTH writable targets and the single invoke capability before
        # the first private write. There is no keyboard/clipboard fallback.
        foreach ($field in $fields) { $null = Get-CertumValuePattern $field }
        $null = Get-CertumInvokePattern $button
        $values = @($Username, $Otp)
        foreach ($index in 0,1) {
            $script:CertumSubmitField = @('username','token')[$index]
            $script:CertumSubmitStep = 'target-revalidation'
            Assert-CertumSubmitTargets $fields $button $Handle $Process $Clock
            $pattern = Get-CertumValuePattern $fields[$index]
            $script:CertumSubmitStep = 'field-write'
            $pattern.SetValue($values[$index])
            Assert-CertumFocus $Handle $Process
            Assert-CertumDeadline $Clock
        }
        $script:CertumSubmitField = 'none'; $script:CertumSubmitStep = 'target-revalidation'
        Assert-CertumSubmitTargets $fields $button $Handle $Process $Clock
        $pattern = Get-CertumInvokePattern $button
        $script:CertumSubmitStep = 'button-invoke'
        $pattern.Invoke() # Exactly once; existing certificate polling owns the result.
    } catch {
        $script:CertumSubmitFailed = $true
        $script:CertumSubmitFailureStep = $script:CertumSubmitStep
        throw
    } finally { $values = $null; $Username = $null; $Otp = $null }
}

function Stop-CertumSession($Session) {
    $expected = Join-Path $env:ProgramFiles 'Certum\SimplySign Desktop\SimplySignDesktop.exe'
    if (($Session.process_id -isnot [int] -and $Session.process_id -isnot [long]) -or
        $Session.process_id -le 0 -or $Session.process_id -gt [int]::MaxValue -or $Session.executable -ine $expected -or
        -not $Session.process_started) { throw 'invalid owned Desktop session' }
    try { $started = ([datetime]$Session.process_started).ToUniversalTime() }
    catch { throw 'invalid owned Desktop start identity' }
    $process = Get-Process -Id $Session.process_id -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        if ($process.StartTime.ToUniversalTime().Ticks -ne $started.Ticks -or
            $process.Path -ine $Session.executable) { throw 'session process ownership differs' }
        $process.Kill(); if (-not $process.WaitForExit(10000)) { throw 'owned Desktop process did not stop' }
    }
    return @{process_stopped=$true; cloud_session_revoked='unproven; hosted runner must be discarded'}
}

function Connect-CertumSession($Policy, [string]$Msi, [string]$OutputPath) {
    $script:CertumSubmitFailed = $false
    $script:CertumObservationResult = 'not-checked'; $script:CertumInitialCounts = $null; $script:CertumRepeatedCounts = $null
    $username = $env:CERTUM_USERNAME; $text = $env:CERTUM_OTP_URI
    Remove-Item Env:CERTUM_USERNAME, Env:CERTUM_OTP_URI -ErrorAction SilentlyContinue
    $credential = $null; $process = $null; $session = $null; $registry = 'HKCU:\Software\Certum\SimplySign'
    $saved = @{}; $success = $false
    $script:CertumCleanup = 'no-process-started'
    try {
        $script:CertumStage = 'credential-validation'
        if (-not $username -or $username -match '[\r\n\x00]' -or -not $text) { throw 'missing signing credential' }
        $credential = ConvertFrom-CertumOtpUri $text
        $text = $null
        $script:CertumStage = 'installer-validation'
        if (Test-Path -LiteralPath $OutputPath) { throw 'session output already exists' }
        if ((Get-Item -LiteralPath $Msi).Length -ne $Policy.installer.bytes -or
            (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash -ine $Policy.installer.sha256) { throw 'installer bytes differ' }
        $signature = Get-AuthenticodeSignature -LiteralPath $Msi
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ine $Policy.installer.publisher_sha1 -or
            $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -cne $Policy.installer.publisher_cn) { throw 'installer publisher differs' }
        $script:CertumStage = 'installer-execution'
        $installer = Start-CertumChild (Join-Path $env:SystemRoot 'System32\msiexec.exe') @('/i', [IO.Path]::GetFullPath($Msi), '/qn', '/norestart')
        try {
            if (-not $installer.WaitForExit(300000)) { $installer.Kill(); throw 'installer deadline exceeded' }
            if ($installer.ExitCode -ne 0) { throw 'pinned installer failed' }
        } finally { $installer.Dispose() }
        $script:CertumStage = 'desktop-validation'
        $exe = Join-Path $env:ProgramFiles 'Certum\SimplySign Desktop\SimplySignDesktop.exe'
        $installed = Get-AuthenticodeSignature -LiteralPath $exe
        if ($installed.Status -ne 'Valid' -or $installed.SignerCertificate.GetNameInfo('SimpleName', $false) -cne $Policy.installer.publisher_cn) {
            throw 'installed Desktop publisher differs'
        }
        $script:CertumStage = 'desktop-configuration'
        $null = New-Item -Path $registry -Force
        foreach ($name in @('ShowLoginDialogOnStart','ShowLoginDialogOnAppRequest','LangID')) {
            $value = Get-CertumOptionalRegistryValue $registry $name
            $saved[$name] = $value
            Set-ItemProperty -LiteralPath $registry -Name $name -Type DWord -Value $(if ($name -eq 'LangID') {9} else {1})
        }
        Initialize-CertumWindows
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $script:CertumStage = 'desktop-launch'
        $script:CertumCleanup = 'process-unproven'
        $process = Start-CertumChild $exe @()
        $session = @{schema=1; process_id=$process.Id; process_started=$process.StartTime.ToUniversalTime().ToString('o'); executable=$exe}
        $script:CertumCleanup = 'owned-process-active'
        $script:CertumStage = 'login-window'
        $handle = [IntPtr]::Zero
        while ($clock.Elapsed.TotalSeconds -lt 30) {
            $process.Refresh(); if ($process.HasExited) { throw 'Desktop exited before login' }
            $windows = @([CertumWindow]::Owned($process.Id))
            if ($windows.Count -gt 1) { throw 'unexpected Desktop modal window' }
            if ($windows.Count -eq 1) { $handle = $windows[0]; break }
            Start-Sleep -Milliseconds 200
        }
        if ($handle -eq [IntPtr]::Zero) { throw 'login window deadline exceeded' }
        $null = [CertumWindow]::SetForegroundWindow($handle)
        Start-Sleep -Milliseconds 200
        Assert-CertumFocus $handle $process
        $script:CertumStage = 'login-schema'
        Assert-CertumInitialLoginSchema $handle $process $session $clock
        # Every serial signing job starts in a new period; no same-window replay.
        $period = [Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30)
        while ([Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() / 30) -le $period) {
            Assert-CertumDeadline $clock
            Start-Sleep -Milliseconds 100
        }
        $otp = Get-CertumTotp $credential.Key ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        $script:CertumStage = 'credential-submit'
        Submit-CertumCredential $handle $process $username $otp $clock
        $otp = $null; $username = $null
        $script:CertumStage = 'certificate-discovery'
        while ($clock.Elapsed.TotalSeconds -lt 120) {
            $process.Refresh(); if ($process.HasExited) { throw 'Desktop exited during authentication' }
            if (@([CertumWindow]::Owned($process.Id)).Count -gt 1) { throw 'unexpected Desktop modal window' }
            $matches = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -ieq $Policy.certificate.sha1 })
            if ($matches.Count -gt 1) { throw 'ambiguous pinned certificate' }
            if ($matches.Count -eq 1) {
                $script:CertumStage = 'certificate-validation'
                $session.certificate = Get-CertumCertificateInfo $matches[0] $Policy.certificate
                $script:CertumStage = 'certificate-chain'
                Assert-CertumChain $matches[0]
                Assert-CertumDeadline $clock
                $script:CertumStage = 'session-persist'
                $session.source_sha = $env:GITHUB_SHA
                $session.policy_sha256 = (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash
                $session.runner_disposal_required = $true
                $session | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
                $success = $true
                return $session
            }
            Start-Sleep -Milliseconds 500
        }
        throw 'authentication deadline exceeded'
    } finally {
        if ($null -ne $credential) { [Array]::Clear($credential.Key) }
        $text = $null; $username = $null; $otp = $null
        Remove-Item Env:CERTUM_USERNAME, Env:CERTUM_OTP_URI -ErrorAction SilentlyContinue
        try {
            foreach ($name in $saved.Keys) {
                if ($null -eq $saved[$name]) { Remove-ItemProperty -LiteralPath $registry -Name $name -ErrorAction SilentlyContinue }
                else { Set-ItemProperty -LiteralPath $registry -Name $name -Type DWord -Value $saved[$name] }
            }
        } catch { $success = $false; $script:CertumCleanup = 'failed'; throw }
        finally {
            try {
                if (-not $success -and $null -ne $session) {
                    $null = Stop-CertumSession $session
                    if ($script:CertumCleanup -ne 'failed') { $script:CertumCleanup = 'process-stopped' }
                }
            } catch { $script:CertumCleanup = 'failed'; throw }
            finally { if ($null -ne $process) { $process.Dispose() } }
        }
    }
}

function Disconnect-CertumSession($Policy, [string]$SessionFile) {
    $script:CertumStage = 'disconnect-receipt'
    $script:CertumCleanup = 'process-unproven'
    if (-not (Test-Path -LiteralPath $SessionFile -PathType Leaf)) {
        $script:CertumCleanup = 'no-owned-receipt'
        throw 'owned session receipt absent; cleanup is unproven'
    }
    $session = Get-Content -LiteralPath $SessionFile -Raw | ConvertFrom-Json -AsHashtable
    if ($session.schema -ne 1 -or $session.source_sha -cne $env:GITHUB_SHA -or
        $session.policy_sha256 -ine (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash -or
        $session.certificate.sha256 -ine $Policy.certificate.sha256) { throw 'session binding differs' }
    $script:CertumStage = 'disconnect-process'
    $result = Stop-CertumSession $session
    $script:CertumCleanup = 'process-stopped'
    return $result
}

if ($LibraryOnly) { return }
if ($Help -or -not $Mode) {
    'Usage: certum_simplysign.ps1 -Mode Connect -InstallerPath PINNED.msi -SessionPath RUNNER_TEMP/session.json'
    '       certum_simplysign.ps1 -Mode Disconnect -SessionPath RUNNER_TEMP/session.json'
    'Requires a fresh signing-only GitHub Windows x64 runner and resolved public certificate policy.'
    return
}
try {
    $ErrorActionPreference = 'Stop'
    $policy = Read-CertumPolicy $PolicyPath
    $script:CertumStage = 'runner'
    Assert-CertumRunner $policy
    $script:CertumStage = 'session-path'
    $sessionFile = Assert-CertumSessionPath $SessionPath
    if ($Mode -eq 'Connect') { $result = Connect-CertumSession $policy $InstallerPath $sessionFile }
    else {
        Remove-Item Env:CERTUM_USERNAME, Env:CERTUM_OTP_URI -ErrorAction SilentlyContinue
        $result = Disconnect-CertumSession $policy $sessionFile
    }
    $result | ConvertTo-Json -Depth 8 -Compress
} catch {
    Remove-Item Env:CERTUM_USERNAME, Env:CERTUM_OTP_URI -ErrorAction SilentlyContinue
    Write-CertumFailure
    exit 1
}
