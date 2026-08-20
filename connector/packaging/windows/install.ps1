#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string[]]$WorkspaceRoot,
  [string]$InstallRoot = 'D:\sub2api-codex-connector',
  [string]$StateDir,
  [string]$Origin = 'https://sub2api.wyswd.top',
  [string]$DisplayName = $env:COMPUTERNAME,
  [string]$ConnectorBinary,
  [string]$CodexBinary,
  [string]$TaskName = 'sub2api-codex-connector',
  [switch]$AllowCodexVersionMismatch,
  [switch]$SkipTask
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PinnedCodexVersion = '0.147.0'
$FilePersistentAcls = 0x8

function Fail {
  param([string]$Message)
  [Console]::Error.WriteLine("connector-install: $Message")
  exit 1
}

function Report {
  param([string]$Message)
  [Console]::Out.WriteLine($Message)
}

trap { Fail $_.Exception.Message }

function Add-VolumeInformationType {
  if (-not ('Sub2Api.Volume' -as [type])) {
    $signature = @"
[DllImport("kernel32.dll", EntryPoint = "GetVolumeInformationW", CharSet = CharSet.Unicode, SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool GetVolumeInformation(
  string rootPathName,
  System.Text.StringBuilder volumeNameBuffer,
  int volumeNameSize,
  out uint volumeSerialNumber,
  out uint maximumComponentLength,
  out uint fileSystemFlags,
  System.Text.StringBuilder fileSystemNameBuffer,
  int fileSystemNameSize);
"@
    Add-Type -Namespace 'Sub2Api' -Name 'Volume' -MemberDefinition $signature
  }
}

function Get-VolumeFacts {
  param([string]$Root)
  Add-VolumeInformationType
  $volumeName = New-Object System.Text.StringBuilder 261
  $fileSystem = New-Object System.Text.StringBuilder 261
  $serial = [uint32]0
  $componentLength = [uint32]0
  $flags = [uint32]0
  $ok = [Sub2Api.Volume]::GetVolumeInformation(
    $Root, $volumeName, $volumeName.Capacity, [ref]$serial, [ref]$componentLength,
    [ref]$flags, $fileSystem, $fileSystem.Capacity)
  if (-not $ok) {
    $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Fail "cannot query volume information for $Root (win32 error $code)"
  }
  return [pscustomobject]@{
    FileSystem    = $fileSystem.ToString()
    Flags         = $flags
    PersistentAcl = (($flags -band $FilePersistentAcls) -ne 0)
  }
}

function Test-PathUnder {
  param([string]$Child, [string]$Ancestor)
  $c = [IO.Path]::GetFullPath($Child).TrimEnd('\')
  $a = [IO.Path]::GetFullPath($Ancestor).TrimEnd('\')
  if ($c -ieq $a) { return $true }
  return $c.StartsWith($a + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-StatePathShape {
  param([string]$Path)
  if ($Path -notmatch '^[A-Za-z]:\\') {
    Fail "state_dir must be an absolute local path on a drive letter, not a UNC or relative path: $Path"
  }
  $tail = $Path.Substring(2)
  if ($tail.Contains(':')) {
    Fail "state_dir must not name an NTFS alternate data stream: $Path"
  }
  if ($tail.IndexOfAny([char[]]@('*', '?', '"', '<', '>', '|')) -ge 0) {
    Fail "state_dir must not contain wildcard characters: $Path"
  }
}

function Assert-NotReparsePoint {
  param([string]$Path)
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail "refusing a symlink, junction, or mount point: $Path"
  }
}

function Protect-Directory {
  param([string]$Path, [string]$UserSid)
  $arguments = @(
    $Path, '/inheritance:r',
    '/grant:r', ('*' + $UserSid + ':(OI)(CI)F'),
    '/grant:r', '*S-1-5-18:(OI)(CI)F',
    '/grant:r', '*S-1-5-32-544:(OI)(CI)F'
  )
  $output = & icacls.exe @arguments 2>&1
  if ($LASTEXITCODE -ne 0) {
    Fail ("icacls failed on " + $Path + ": " + ($output -join ' '))
  }
  $acl = Get-Acl -LiteralPath $Path
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($null -eq $owner -or $owner.Value -ne $UserSid) {
    $acl.SetOwner([System.Security.Principal.SecurityIdentifier]$UserSid)
    Set-Acl -LiteralPath $Path -AclObject $acl
  }
}

function Assert-ProtectedDirectory {
  param([string]$Path, [string]$UserSid)
  Assert-NotReparsePoint $Path
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) {
    Fail "DACL inheritance is still enabled on $Path; the volume root grants inheritable access to other principals"
  }
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($null -eq $owner -or $owner.Value -ne $UserSid) {
    $observed = 'unknown'
    if ($null -ne $owner) { $observed = $owner.Value }
    Fail "$Path is owned by $observed, not by the Connector user $UserSid"
  }
  $inherited = @($acl.GetAccessRules($false, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($inherited.Count -ne 0) {
    Fail "$Path still carries $($inherited.Count) inherited access rule(s)"
  }
  $expected = @($UserSid, 'S-1-5-18', 'S-1-5-32-544')
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  foreach ($rule in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
    if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) { continue }
    $trustee = $rule.IdentityReference.Value
    if ($expected -notcontains $trustee) {
      # icacls /grant:r replaces the rights of the trustees it names and leaves every
      # other explicit ACE in place, so an adopted directory can still carry one.
      Fail (
        "$Path grants access to $trustee; only the Connector user, SYSTEM, and Administrators " +
        "are allowed. Establish why that trustee was granted access, then remove it with " +
        "'icacls `"$Path`" /remove:g *$trustee' and run this installer again.")
    }
    if (([int]$rule.FileSystemRights -band 0x1F01FF) -ne 0x1F01FF) {
      Fail "$Path grants $trustee less than full control"
    }
    if ($rule.InheritanceFlags -ne $inheritance -or
        $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
      Fail "$Path grants $trustee a rule that does not propagate to every child object"
    }
    [void]$seen.Add($trustee)
  }
  foreach ($trustee in $expected) {
    if (-not $seen.Contains($trustee)) {
      Fail "$Path is missing the required full-control grant for $trustee"
    }
  }
}

function Resolve-CodexBinary {
  $npm = Get-Command 'npm.cmd' -ErrorAction SilentlyContinue
  if ($null -eq $npm) { $npm = Get-Command 'npm' -ErrorAction SilentlyContinue }
  if ($null -eq $npm) {
    Fail "npm is not on PATH, so the vendored codex.exe cannot be located; install codex-cli $PinnedCodexVersion or pass -CodexBinary"
  }
  # The output is enumerated in full before $LASTEXITCODE is read: a pipeline that
  # stops a native command early can leave the variable unset.
  $output = @(& $npm.Source 'prefix' '-g' 2>$null)
  $status = $LASTEXITCODE
  $prefix = ''
  if ($output.Count -gt 0) { $prefix = "$($output[0])".Trim() }
  if ($status -ne 0 -or [string]::IsNullOrWhiteSpace($prefix)) {
    Fail 'npm prefix -g failed, so the vendored codex.exe cannot be located; pass -CodexBinary'
  }
  $package = Join-Path $prefix 'node_modules\@openai\codex'
  if (-not (Test-Path -LiteralPath $package -PathType Container)) {
    Fail "the @openai/codex package is not installed under $prefix; install codex-cli $PinnedCodexVersion or pass -CodexBinary"
  }
  $vendor = 'codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe'
  if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    $vendor = 'codex-win32-arm64\vendor\aarch64-pc-windows-msvc\bin\codex.exe'
  }
  $candidate = Join-Path $package (Join-Path 'node_modules\@openai' $vendor)
  if (Test-Path -LiteralPath $candidate -PathType Leaf) {
    return (Resolve-Path -LiteralPath $candidate).ProviderPath
  }
  $found = @(Get-ChildItem -LiteralPath $package -Recurse -Filter 'codex.exe' -File -ErrorAction SilentlyContinue)
  if ($found.Count -eq 1) { return $found[0].FullName }
  if ($found.Count -eq 0) {
    Fail "no codex.exe exists under $package; the codex and codex.cmd shims are not usable, so pass -CodexBinary with the vendored executable"
  }
  Fail "$($found.Count) codex.exe candidates exist under $package; pass -CodexBinary to select one"
}

function Assert-CodexBinary {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Fail "codex_binary does not exist: $Path"
  }
  if ([IO.Path]::GetExtension($Path).ToLowerInvariant() -ne '.exe') {
    Fail "codex_binary must be the vendored codex.exe; a .cmd or .bat shim launches cmd.exe and breaks the pinned --version identity check: $Path"
  }
  Assert-NotReparsePoint $Path
  $output = @(& $Path '--version' 2>&1)
  $status = $LASTEXITCODE
  $banner = ''
  if ($output.Count -gt 0) { $banner = "$($output[0])".Trim() }
  if ($status -ne 0) {
    Fail "'$Path --version' failed: $banner"
  }
  $expected = "codex-cli $PinnedCodexVersion"
  if ($banner -ne $expected) {
    $message = "codex reports '$banner' but the Connector pins '$expected'; upgrade with 'npm install -g @openai/codex@$PinnedCodexVersion'"
    if (-not $AllowCodexVersionMismatch) { Fail $message }
    Write-Warning "connector-install: $message"
    Write-Warning 'connector-install: the Connector still refuses to start app-server until the pinned version is installed'
  }
}

function Write-PrivateText {
  param([string]$Path, [string]$Text)
  [IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

if ([string]::IsNullOrWhiteSpace($DisplayName)) {
  Fail 'display_name is empty; pass -DisplayName'
}
if ($Origin -notmatch '^https://[^/?#@\s]+$') {
  Fail "-Origin must be an https origin without a path, query, fragment, or credentials: $Origin"
}
$Origin = $Origin.TrimEnd('/')

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userSid = $identity.User.Value
$userName = $identity.Name

if ($InstallRoot -notmatch '^[A-Za-z]:\\') {
  Fail "-InstallRoot must be an absolute local path on a drive letter: $InstallRoot"
}
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($StateDir)) {
  $StateDir = Join-Path $InstallRoot 'state'
}
Assert-StatePathShape $StateDir
$StateDir = [IO.Path]::GetFullPath($StateDir).TrimEnd('\')

$profilesRoot = Split-Path -Parent ([IO.Path]::GetFullPath($env:USERPROFILE))
if ((Test-PathUnder $StateDir $profilesRoot) -or (Test-PathUnder $InstallRoot $profilesRoot)) {
  Fail (
    "refusing to install under $profilesRoot. The user profile grants FILE_DELETE_CHILD to " +
    'CodexSandboxUsers and to a second non-local SID, so a principal in either group can delete ' +
    'and replace any direct child of the profile. The Connector rejects that ancestor at startup ' +
    'and names it in the error. Choose a path such as D:\sub2api-codex-connector.')
}

$stateVolume = $StateDir.Substring(0, 3)
$facts = Get-VolumeFacts $stateVolume
if (-not $facts.PersistentAcl) {
  Fail (
    "$stateVolume is $($facts.FileSystem) (flags 0x$('{0:X}' -f $facts.Flags)) and does not report " +
    'FILE_PERSISTENT_ACLS. exFAT and FAT32 record no ownership and no ACLs, so the owner-only ' +
    'state guarantee is unenforceable there and the Connector fails closed instead of skipping ' +
    'the check. Choose an NTFS volume for -StateDir.')
}
$installVolume = $InstallRoot.Substring(0, 3)
if ($installVolume -ine $stateVolume) {
  $installFacts = Get-VolumeFacts $installVolume
  if (-not $installFacts.PersistentAcl) {
    Fail "$installVolume is $($installFacts.FileSystem) and does not report FILE_PERSISTENT_ACLS; choose an NTFS volume for -InstallRoot"
  }
}

$roots = @()
foreach ($root in $WorkspaceRoot) {
  if ($root -notmatch '^([A-Za-z]:\\|\\\\)') {
    Fail "-WorkspaceRoot must be an absolute path: $root"
  }
  if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    Fail "-WorkspaceRoot does not exist or is not a directory: $root"
  }
  $resolved = (Resolve-Path -LiteralPath $root).ProviderPath.TrimEnd('\')
  if ((Test-PathUnder $resolved $StateDir) -or (Test-PathUnder $StateDir $resolved)) {
    Fail "state_dir and workspace root $resolved must not overlap"
  }
  if ($roots -contains $resolved) {
    Fail "workspace root $resolved is duplicated"
  }
  $roots += $resolved
}

if ([string]::IsNullOrWhiteSpace($CodexBinary)) {
  $CodexBinary = Resolve-CodexBinary
}
Assert-CodexBinary $CodexBinary

if ([string]::IsNullOrWhiteSpace($ConnectorBinary)) {
  $stagedArch = 'windows-amd64'
  if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $stagedArch = 'windows-arm64' }
  $staged = Join-Path $PSScriptRoot "bin\$stagedArch\sub2api-codex-connector.exe"
  if (-not (Test-Path -LiteralPath $staged -PathType Leaf)) {
    Fail "no Connector executable at $staged; pass -ConnectorBinary with the built sub2api-codex-connector.exe"
  }
  $ConnectorBinary = (Resolve-Path -LiteralPath $staged).ProviderPath
} elseif (Test-Path -LiteralPath $ConnectorBinary -PathType Leaf) {
  $ConnectorBinary = (Resolve-Path -LiteralPath $ConnectorBinary).ProviderPath
} else {
  Fail "-ConnectorBinary does not exist: $ConnectorBinary"
}
Assert-NotReparsePoint $ConnectorBinary

$templatePath = Join-Path $PSScriptRoot 'connector.example.json'
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
  Fail "the configuration template is missing: $templatePath"
}

# The install root is hardened before the state directory is created inside it, so the
# new directory never exists, even briefly, with the volume root's inheritable
# Authenticated Users grant applied to it.
if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
  [void](New-Item -ItemType Directory -Path $InstallRoot)
}
Protect-Directory $InstallRoot $userSid
Assert-ProtectedDirectory $InstallRoot $userSid

$binRoot = Join-Path $InstallRoot 'bin'
if (-not (Test-Path -LiteralPath $binRoot -PathType Container)) {
  [void](New-Item -ItemType Directory -Path $binRoot)
}

if (-not (Test-Path -LiteralPath $StateDir -PathType Container)) {
  [void](New-Item -ItemType Directory -Path $StateDir)
}
Protect-Directory $StateDir $userSid
Assert-ProtectedDirectory $StateDir $userSid

$installedConnector = Join-Path $binRoot 'sub2api-codex-connector.exe'
if ($ConnectorBinary -ine $installedConnector) {
  Copy-Item -LiteralPath $ConnectorBinary -Destination $installedConnector -Force
}

$configPath = Join-Path $InstallRoot 'connector.json'
if (Test-Path -LiteralPath $configPath) {
  Report "Kept the existing configuration $configPath"
} else {
  $config = (Get-Content -LiteralPath $templatePath -Raw) | ConvertFrom-Json
  $config.control_url = ($Origin -replace '^https://', 'wss://') + '/codex-ws/device'
  $config.pairing_url = "$Origin/codex-api/v1/device-pairings/start"
  $config.token_url = "$Origin/codex-api/v1/device/connect-token"
  $config.display_name = $DisplayName
  $config.state_dir = $StateDir
  $config.workspace_roots = @($roots)
  $config.codex_binary = $CodexBinary
  Write-PrivateText $configPath (($config | ConvertTo-Json -Depth 5) + "`n")
  Report "Created $configPath"
}

if (-not $SkipTask) {
  if ($null -eq (Get-Command 'Register-ScheduledTask' -ErrorAction SilentlyContinue)) {
    Fail 'the ScheduledTasks module is unavailable, so the Connector cannot be supervised at logon'
  }
  $action = New-ScheduledTaskAction -Execute $installedConnector `
    -Argument "-config `"$configPath`"" -WorkingDirectory $InstallRoot
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $userName
  $settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  $principal = New-ScheduledTaskPrincipal -UserId $userName -LogonType Interactive -RunLevel Limited
  [void](Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action `
    -Trigger $trigger -Settings $settings -Principal $principal `
    -Description 'Sub2API Codex Connector (outbound only).' -Force)
  $registered = Get-ScheduledTask -TaskName $TaskName -TaskPath '\'
  if ($registered.Actions[0].Execute -ine $installedConnector) {
    Fail "the registered task runs $($registered.Actions[0].Execute) instead of $installedConnector"
  }
  Report "Registered scheduled task \$TaskName for $userName at logon, restarting 3 times at 1 minute."
}

Report ''
Report "State directory: $StateDir (protected DACL, owner $userName)"
Report "Codex binary:    $CodexBinary"
Report ''
Report "Run '.\sub2api-codex-connector-ctl.ps1 pair', enter the private pairing code in the Control PWA,"
Report "then run '.\sub2api-codex-connector-ctl.ps1 start'."
