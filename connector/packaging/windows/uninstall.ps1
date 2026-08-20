#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$InstallRoot = 'D:\sub2api-codex-connector',
  [string]$Config,
  [string]$TaskName = 'sub2api-codex-connector',
  [int]$TimeoutSeconds = 60,
  [switch]$PurgeState,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExecutableName = 'sub2api-codex-connector.exe'

function Fail {
  param([string]$Message)
  [Console]::Error.WriteLine("connector-uninstall: $Message")
  exit 1
}

function Report {
  param([string]$Message = '')
  [Console]::Out.WriteLine($Message)
}

trap { Fail $_.Exception.Message }

function Get-ConnectorProcesses {
  param([string]$Executable)
  $processes = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = '$ExecutableName'" -ErrorAction SilentlyContinue)
  return @($processes | Where-Object { $_.ExecutablePath -ieq $Executable })
}

$configPath = $Config
if ([string]::IsNullOrWhiteSpace($configPath)) {
  $configPath = Join-Path $InstallRoot 'connector.json'
}
$stateDir = $null
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
  $parsed = (Get-Content -LiteralPath $configPath -Raw) | ConvertFrom-Json
  if ($null -ne $parsed.PSObject.Properties['state_dir']) {
    $stateDir = $parsed.state_dir
  }
}
if ($PurgeState -and [string]::IsNullOrWhiteSpace($stateDir)) {
  Fail "-PurgeState needs a state_dir, but $configPath does not exist or does not define one"
}

$executable = Join-Path (Join-Path $InstallRoot 'bin') $ExecutableName

if ($null -ne (Get-Command 'Get-ScheduledTask' -ErrorAction SilentlyContinue)) {
  $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
  if ($null -ne $task) {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false
    Report "Removed scheduled task \$TaskName."
  } else {
    Report "Scheduled task \$TaskName was not registered."
  }
} else {
  Report 'The ScheduledTasks module is unavailable; no task was removed.'
}

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
  if (@(Get-ConnectorProcesses $executable).Count -eq 0) { break }
  Start-Sleep -Milliseconds 250
}
$remaining = @(Get-ConnectorProcesses $executable)
if ($remaining.Count -ne 0) {
  foreach ($process in $remaining) {
    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep -Milliseconds 500
  $remaining = @(Get-ConnectorProcesses $executable)
  if ($remaining.Count -ne 0) {
    Fail "the Connector is still running (pid $($remaining.ProcessId -join ', ')); stop it before uninstalling"
  }
}
Report 'The Connector process is stopped.'

if (-not $PurgeState) {
  if ([string]::IsNullOrWhiteSpace($stateDir)) {
    Report "No configuration was found at $configPath, so no state directory was identified."
    Report 'Nothing was deleted.'
  } else {
    Report "Kept $stateDir. It holds the paired device credential; deleting it forces a re-pair."
    Report 'Revoke the device in the Control PWA first, then re-run with -PurgeState to remove it.'
    Report 'The configuration and the Connector executable were preserved too.'
  }
  exit 0
}

if (-not (Test-Path -LiteralPath $stateDir -PathType Container)) {
  Report "State directory $stateDir does not exist; nothing was deleted."
  exit 0
}

if (-not $Force) {
  Report "About to permanently delete $stateDir."
  Report 'It holds the device identity and the paired device credential. Revoke this device in the'
  Report 'Control PWA first, otherwise the server keeps a claim this host can no longer serve.'
  $answer = Read-Host 'Type the word purge to continue'
  if ($answer -ne 'purge') {
    Fail 'purge was not confirmed; no files were changed'
  }
}

Remove-Item -LiteralPath $stateDir -Recurse -Force
Report "Removed $stateDir."
Report 'Codex configuration, Codex credentials, and workspace files were not touched.'
