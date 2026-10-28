param(
    [switch]$Help,
    [switch]$HostedElevated,
    [Parameter(Mandatory=$false)][string]$BundlePath,
    [Parameter(Mandatory=$false)][string]$BundleSha256,
    [Parameter(Mandatory=$false)][string]$ExpectedRuntimeSha256,
    [ValidateSet(0,3600)][int]$SoakSeconds = 0,
    [string]$ExpectedSupervisorSha256,
    [string]$SoakRequestPath,
    [Parameter(Mandatory=$false)][string]$FixtureSha256,
    [Parameter(Mandatory=$false)][string]$ModuleSha256,
    [Parameter(Mandatory=$false)][string]$ArtifactSource,
    [Parameter(Mandatory=$false)][string]$AcceptanceTool,
    [Parameter(Mandatory=$false)][string]$Version,
    [Parameter(Mandatory=$false)][string]$ResultDirectory
)
$ErrorActionPreference = 'Stop'
if ($Help) {
    @'
test_setup_runtime.ps1 -BundlePath PATH -BundleSha256 HEX -ExpectedRuntimeSha256 HEX
  -FixtureSha256 HEX -ModuleSha256 HEX -ArtifactSource COMMIT -AcceptanceTool COMMIT
  -Version X.Y.Z -ResultDirectory DIR
  [-SoakSeconds 3600 -ExpectedSupervisorSha256 HEX -SoakRequestPath PATH]
  [-HostedElevated]

One native clean-account Setup install, machine-scope readiness and exact removal.
By default requires a real unelevated interactive user profile. Windows may ask that user to
approve UAC for installation and removal. Existing OA state is refused. The exact
bundle and owning fixture/module bytes are checked before any installer execution.
An incomplete or failed journey remains failed; its finally block attempts exact
bundle removal and retains the installer/removal logs. No account is created.
HostedElevated requires a disposable GitHub-hosted Windows runner, an elevated
Administrator token and Valid Authenticode before dispatch. It proves elevated
headless runner acceptance; standard-user MSI acceptance remains separate. Hosted
Windows Server/tooling does not prove interactive UAC, consumer Windows 11 visuals
or hardware, or standard-user first-run. Image metadata is recorded as reported.
'@
    exit 0
}
foreach ($value in @($BundleSha256,$ExpectedRuntimeSha256,$FixtureSha256,$ModuleSha256)) {
    if ($value -cnotmatch '^[0-9a-f]{64}$') { throw 'Exact SHA256 input is required' }
}
foreach ($value in @($ArtifactSource,$AcceptanceTool)) {
    if ($value -cnotmatch '^[0-9a-f]{40}$') { throw 'Exact source/tool commit is required' }
}
if ($Version -cnotmatch '^\d+\.\d+\.\d+$') { throw 'Exact package version is required' }
if ($SoakSeconds -and ($ExpectedSupervisorSha256 -cnotmatch '^[0-9a-f]{64}$' -or
    -not [IO.Path]::IsPathRooted($SoakRequestPath) -or -not (Test-Path -LiteralPath $SoakRequestPath -PathType Leaf))) { throw 'Rehearsal soak needs exact supervisor/request inputs' }
if (-not [IO.Path]::IsPathRooted($BundlePath) -or -not [IO.Path]::IsPathRooted($ResultDirectory)) { throw 'Absolute package/result paths are required' }
$taskRoot = [IO.Path]::GetFullPath($ResultDirectory)
$bundle = [IO.Path]::GetFullPath($BundlePath)
$fixture = Join-Path $PSScriptRoot 'test_user_runtime.ps1'
$module = Join-Path $PSScriptRoot 'OAFixture.psm1'
New-Item -ItemType Directory -Force -Path $taskRoot | Out-Null
foreach ($name in @('receipt.json','setup-install.log','setup-uninstall.log')) {
    if (Test-Path -LiteralPath (Join-Path $taskRoot $name)) { throw 'Refusing to overwrite an existing Setup attempt; reconcile its retained evidence' }
}
$started = [DateTime]::UtcNow
$report = [ordered]@{ artifact_source=$ArtifactSource; acceptance_tool=$AcceptanceTool; bundle_sha256=$BundleSha256; bundle_bytes=(Get-Item -LiteralPath $bundle).Length; signed=$null; started_utc=$started.ToString('o'); install_exit=$null; uninstall_exit=$null; ready=$false; cleanup_verified=$false; result='not run' }
function Get-SetupToken {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $elevated=(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return @{sid=$identity.User.Value; elevated=$elevated}
}
function Get-SetupExecutionContext([bool]$Hosted) {
    if ($Hosted) { Assert-DisposableRunner }
    $token=Get-SetupToken
    $elevated=$token.elevated
    if ($Hosted) {
        if (-not $elevated) { throw 'Hosted Setup requires an elevated Administrator token' }
    } else { Assert-UnelevatedToken { $token.elevated } }
    Assert-RealProfileView
    $os=Get-CimInstance Win32_OperatingSystem
    return [ordered]@{ sid=$token.sid; elevated=$elevated; native_session=(Get-Process -Id $PID).SessionId;
        process_bitness=$(if ([Environment]::Is64BitProcess) { 64 } else { 32 });
        native_processor_architecture=@((Get-CimInstance Win32_Processor).Architecture | Select-Object -Unique);
        process_architecture_reported=$env:PROCESSOR_ARCHITECTURE; os_architecture=$os.OSArchitecture;
        os_caption=$os.Caption; os_version=$os.Version; os_build=$os.BuildNumber;
        hosted_elevated=$Hosted; github_actions=$env:GITHUB_ACTIONS; runner_environment=$env:RUNNER_ENVIRONMENT;
        runner_os=$env:RUNNER_OS; image_os=$env:ImageOS; image_version=$env:ImageVersion;
        stock_consumer_environment='unproven: runner tooling and image metadata do not establish stock consumer state';
        limits=$(if ($Hosted) { 'Elevated headless hosted Windows acceptance; interactive UAC, consumer Windows 11 visuals/hardware and standard-user first-run unproven' } else { 'Unelevated real-profile Setup acceptance; host stock/hardware facts not inferred' }) }
}
function Set-SetupSignature([Collections.IDictionary]$Report, [string]$Path, [bool]$RequireValid) {
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    $status=[string]$signature.Status
    $Report.authenticode=[ordered]@{ status=$status; valid=($status -ceq 'Valid');
        publisher_policy='not evaluated here; windows_signing.verify_bundle owns publisher-policy verification' }
    $Report.signed=$Report.authenticode.valid
    if ($RequireValid -and $status -cne 'Valid') { throw "Hosted Setup requires Valid Authenticode; actual status: $status" }
}
function Assert-MachineSupervisorConfiguration([string]$Configuration, [string]$Recovery, [string]$RecoveryFlag, [string]$ExpectedImage) {
    if ($Configuration -notmatch 'TYPE\s*:\s*50\s+USER_OWN_PROCESS\s+TEMPLATE') { throw 'Supervisor is not the per-user service template' }
    if ($Configuration -notmatch 'START_TYPE\s*:\s*2\s+AUTO_START') { throw 'Supervisor template is not automatic' }
    $expected = '"' + $ExpectedImage + '" serve supervisor --service'
    if ($Configuration -notmatch ('BINARY_PATH_NAME\s*:\s*' + [regex]::Escape($expected) + '(?:\r?\n|$)')) { throw 'Supervisor template image/arguments differ from installed windowless host' }
    if ($Recovery -notmatch 'RESET_PERIOD[^:]*:\s*3600') { throw 'Supervisor recovery reset period differs' }
    foreach ($delay in @(3000,10000,30000)) { if ($Recovery -notmatch "RESTART -- Delay = $delay milliseconds") { throw 'Supervisor restart recovery differs' } }
    if ($RecoveryFlag -notmatch 'FAILURE_ACTIONS_ON_NONCRASH_FAILURES\s*:\s*TRUE') { throw 'Supervisor non-crash failure recovery is absent' }
}

$failure = $null
$attempted = $false
try {
    if (-not [Environment]::Is64BitProcess) { throw 'Exact x64 Setup needs native x64 PowerShell' }
    foreach ($entry in @(@($bundle,$BundleSha256),@($fixture,$FixtureSha256),@($module,$ModuleSha256))) {
        if ((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry[1]) { throw 'Reviewed artifact/acceptance input changed' }
    }
    Import-Module $module -Force
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile($fixture,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Reviewed fixture did not parse' }
    foreach ($name in @('Get-ProfileFolder','Get-OpenAbstractionsFootprint','Assert-NoOpenAbstractions','Assert-UnelevatedToken','Assert-RuntimeReady','Assert-RemovalLog',
        'Get-InstalledSoakClock','Assert-InstalledSoakClock','Get-InstalledSoakInputs','Get-InstalledSoakProcesses','Assert-InstalledSoakProcesses','Assert-InstalledRuntimeSoak')) {
        $definition=@($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name },$true))
        if ($definition.Count -ne 1) { throw "Missing exact fixture owner $name" }
        . ([scriptblock]::Create($definition[0].Extent.Text))
    }
    $report.execution_context=Get-SetupExecutionContext ([bool]$HostedElevated)
    Set-SetupSignature $report $bundle ([bool]$HostedElevated)
    $sid=$report.execution_context.sid
    $local=Get-ProfileFolder LocalApplicationData
    $startup=Get-ProfileFolder Startup
    $items=Get-OpenAbstractionsFootprint $sid $local $env:ProgramFiles $startup
    Assert-NoOpenAbstractions $items
    if (Test-Path -LiteralPath 'HKLM:\Software\OpenAbstractions') { throw 'Existing machine OA registry refuses Setup acceptance' }
    foreach ($key in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path -LiteralPath $key) {
            foreach ($registration in @(Get-ChildItem -LiteralPath $key)) {
                $value=Get-ItemProperty -LiteralPath $registration.PSPath
                if ($value.DisplayName -eq 'OpenAbstractions Setup') { throw 'Existing OA Setup registration refuses acceptance' }
            }
        }
    }
    $report.real_profile_guard='pass'
    $report.before_clean_guard='pass'
    $report.native_session=(Get-Process -Id $PID).SessionId
    $report.producer_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.fixture_sha256=$FixtureSha256
    $report.module_sha256=$ModuleSha256
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$bundle
    $info.Arguments='-install -quiet -norestart -log "' + (Join-Path $taskRoot 'setup-install.log') + '"'
    $info.WorkingDirectory=$taskRoot
    $attempted=$true
    $installed=Invoke-FixtureProcess $info 600
    $report.install_exit=$installed.ExitCode
    [IO.File]::WriteAllText((Join-Path $taskRoot 'setup-install.stdout'),$installed.Output,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $taskRoot 'setup-install.stderr'),$installed.Diagnostics,[Text.UTF8Encoding]::new($false))
    if ($installed.ExitCode -ne 0) { throw "Setup install exited $($installed.ExitCode); original log retained" }
    $products=@(Get-InstalledProducts -Context 4 | Where-Object { $_.ProductName -in @('OpenAbstractions', 'Abstraction') })
    if ($products.Count -ne 1 -or $products[0].State -ne 5 -or $products[0].VersionString -ne $Version) { throw 'Setup did not install the exact core version per-machine' }
    $user=@(Get-InstalledProducts -UserSid $sid -Context 2 | Where-Object { $_.ProductName -in @('OpenAbstractions', 'Abstraction') })
    if ($user.Count) { throw 'Setup unexpectedly installed a user-scope core' }
    $central=Join-Path $env:ProgramFiles 'OpenAbstractions\tools\openabstractions.exe'
    if ((Get-FileHash -LiteralPath $central -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedRuntimeSha256) { throw 'Installed runtime differs from exact reviewed S payload' }
    # Registration creates the per-user service template; this sign-in starts its host on demand.
    $taskSc = Join-Path $env:SystemRoot 'System32\sc.exe'
    $configuration = (& $taskSc qc OpenAbstractionsSupervisor) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Machine supervisor template is not registered' }
    $recovery = (& $taskSc qfailure OpenAbstractionsSupervisor) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Machine supervisor recovery could not be read' }
    $recoveryFlag = (& $taskSc qfailureflag OpenAbstractionsSupervisor) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Machine supervisor non-crash recovery could not be read' }
    Assert-MachineSupervisorConfiguration $configuration $recovery $recoveryFlag (Join-Path $env:ProgramFiles 'OpenAbstractions\tools\openabstractionsw.exe')
    if (-not (Test-Path -LiteralPath 'HKLM:\Software\OpenAbstractions\Abstraction')) { throw 'Machine registry registration absent' }
    $tools = Join-Path $env:ProgramFiles 'OpenAbstractions\tools'
    $machinePath = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name Path).Path
    if (-not @($machinePath.Split(';') | Where-Object { $_.Trim().TrimEnd('\') -ieq $tools.TrimEnd('\') }).Count) { throw 'Machine PATH lacks installed tools' }
    if (Test-Path -LiteralPath (Join-Path $startup 'Abstraction supervisor.lnk')) { throw 'Machine install also selected per-user Startup arm' }
    $machineConfig = Join-Path $env:ProgramData 'abstraction'
    if (-not (Test-Path -LiteralPath $machineConfig -PathType Container)) { throw 'Machine configuration folder absent' }
    if (@((Get-Acl -LiteralPath $machineConfig).Access | Where-Object { $_.IdentityReference -like '*\Users' -and $_.FileSystemRights -match 'CreateFiles|Write|FullControl|Modify' }).Count) { throw 'Users can write the machine configuration folder' }
    $activationInfo=New-Object Diagnostics.ProcessStartInfo
    $activationInfo.FileName=$central
    $activationInfo.Arguments='start --timeout 30s'
    $activation=Invoke-FixtureProcess $activationInfo 35
    [IO.File]::WriteAllText((Join-Path $taskRoot 'setup-runtime-start.stdout'),$activation.Output,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $taskRoot 'setup-runtime-start.stderr'),$activation.Diagnostics,[Text.UTF8Encoding]::new($false))
    $report.activation_exit=$activation.ExitCode
    if ($activation.ExitCode -ne 0) { throw "Installed current-user activation exited $($activation.ExitCode)" }
    Assert-RuntimeReady $central (Join-Path $taskRoot 'setup-runtime-status')
    if ($SoakSeconds) {
        Assert-InstalledRuntimeSoak $central $ExpectedRuntimeSha256 $ExpectedSupervisorSha256 $sid $SoakSeconds (Join-Path $taskRoot 'installed-soak.json') @($bundle,$PSCommandPath,$fixture,$module,$SoakRequestPath)
        $report.soak_receipt_sha256=(Get-FileHash -LiteralPath (Join-Path $taskRoot 'installed-soak.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $report.ready=$true
    $report.machine_version=$Version
    $report.installed_runtime_sha256=$ExpectedRuntimeSha256
} catch { $failure=$_; $report.failure=($_ | Out-String) } finally {
    if ($attempted) {
        try {
            $removeInfo=New-Object Diagnostics.ProcessStartInfo
            $removeInfo.FileName=$bundle
            $removeInfo.Arguments='-uninstall -quiet -norestart -log "' + (Join-Path $taskRoot 'setup-uninstall.log') + '"'
            $removeInfo.WorkingDirectory=$taskRoot
            $removed=Invoke-FixtureProcess $removeInfo 600
            $report.uninstall_exit=$removed.ExitCode
            [IO.File]::WriteAllText((Join-Path $taskRoot 'setup-uninstall.stdout'),$removed.Output,[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $taskRoot 'setup-uninstall.stderr'),$removed.Diagnostics,[Text.UTF8Encoding]::new($false))
            if ($removed.ExitCode -ne 0) { throw "Setup uninstall exited $($removed.ExitCode)" }
            $logs=@(Get-ChildItem -LiteralPath $taskRoot -File -Filter 'setup-uninstall*OpenAbstractions*.log')
            if ($logs.Count -ne 1) { throw 'Exact core uninstall log missing or ambiguous' }
            $report.removal_log_verdict=Assert-RemovalLog ([IO.File]::ReadAllText($logs[0].FullName))
            Assert-NoRuntime -Sid $sid -Seconds 20
            Assert-NoRuntime -Sid 'S-1-5-18' -Seconds 20
            $left=Get-OpenAbstractionsFootprint $sid $local $env:ProgramFiles $startup
            Assert-NoOpenAbstractions $left 'after exact Setup uninstall'
            if (Test-Path -LiteralPath 'HKLM:\Software\OpenAbstractions') { throw 'Machine OA registry remains after uninstall' }
            foreach ($key in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')) {
                if (Test-Path -LiteralPath $key) { foreach ($registration in @(Get-ChildItem -LiteralPath $key)) {
                    $value=Get-ItemProperty -LiteralPath $registration.PSPath
                    if ($value.DisplayName -eq 'OpenAbstractions Setup') { throw 'OA Setup registration remains after uninstall' }
                } }
            }
            $report.cleanup_verified=$true
            $report.retained_data='No user/machine data folders removed or inspected; platform uninstaller alone removes its installation.'
        } catch { $report.cleanup_failure=($_ | Out-String); if (-not $failure) { $failure=$_ } }
    }
    $report.finished_utc=[DateTime]::UtcNow.ToString('o')
    $report.result=if ($failure) { 'fail' } elseif ($report.ready -and $report.cleanup_verified) { 'pass' } else { 'not run' }
    [IO.File]::WriteAllText((Join-Path $taskRoot 'receipt.json'),($report | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
if ($failure) { throw $failure }
if ($report.result -ne 'pass') { throw 'Setup acceptance incomplete' }
