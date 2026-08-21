#Requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Command,
  [string]$InstallRoot = 'D:\sub2api-codex-connector',
  [string]$Config,
  [string]$TaskName = 'sub2api-codex-connector',
  [string]$LogPath,
  [int]$Tail = 200,
  [int]$TimeoutSeconds = 60,
  [switch]$Follow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$FreshnessSeconds = 60
$ExecutableName = 'sub2api-codex-connector.exe'
$LogName = 'connector.log'
$MetricsName = 'connector.prom'
$PairingCodeName = 'pairing-code.json'
$FreshnessMetric = 'codex_control_connector_last_update_timestamp_seconds'

function Fail {
  param([string]$Message)
  [Console]::Error.WriteLine("connector-ctl: $Message")
  exit 1
}

function Report {
  param([string]$Message = '')
  [Console]::Out.WriteLine($Message)
}

function Usage {
  [Console]::Error.WriteLine(@'
usage: sub2api-codex-connector-ctl.ps1 COMMAND [OPTIONS]

Commands:
  start    start the registered scheduled task
  stop     stop the scheduled task and its Connector process
  status   report the task state, the process, and metrics freshness
  pair     pair this device and print the one-time code
  logs     print the tail of the Connector log

Options:
  -InstallRoot DIR      installation root (default D:\sub2api-codex-connector)
  -Config FILE          connector.json path (default INSTALLROOT\connector.json)
  -TaskName NAME        scheduled task name (default sub2api-codex-connector)
  -LogPath FILE         log file (default STATEDIR\connector.log)
  -Tail N               log lines to print (default 200)
  -TimeoutSeconds N     stop and pair timeout (default 60)
  -Follow               keep printing new log lines
'@)
  exit 2
}

trap { Fail $_.Exception.Message }

function Get-ConnectorConfig {
  $path = $Config
  if ([string]::IsNullOrWhiteSpace($path)) {
    $path = Join-Path $InstallRoot 'connector.json'
  }
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    Fail "no Connector configuration at $path; run install.ps1 first or pass -Config"
  }
  $parsed = (Get-Content -LiteralPath $path -Raw) | ConvertFrom-Json
  foreach ($field in @('state_dir', 'codex_binary')) {
    if ($null -eq $parsed.PSObject.Properties[$field]) {
      Fail "$path does not define $field"
    }
  }
  $executable = Join-Path (Join-Path $InstallRoot 'bin') $ExecutableName
  return [pscustomobject]@{
    Path       = (Resolve-Path -LiteralPath $path).ProviderPath
    StateDir   = $parsed.state_dir
    Executable = $executable
  }
}

function Get-Task {
  if ($null -eq (Get-Command 'Get-ScheduledTask' -ErrorAction SilentlyContinue)) {
    Fail 'the ScheduledTasks module is unavailable on this host'
  }
  return (Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue)
}

function Get-ConnectorProcesses {
  param([string]$Executable)
  $query = "Name = '$ExecutableName'"
  $processes = @(Get-CimInstance -ClassName Win32_Process -Filter $query -ErrorAction SilentlyContinue)
  return @($processes | Where-Object { $_.ExecutablePath -ieq $Executable })
}

function Get-MetricsFreshness {
  param([string]$StateDir)
  $path = Join-Path $StateDir $MetricsName
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    return [pscustomobject]@{ Path = $path; Present = $false; Healthy = $false; Detail = 'no textfile has been written yet' }
  }
  $value = $null
  foreach ($line in (Get-Content -LiteralPath $path)) {
    if ($line -match "^$FreshnessMetric\s+(\S+)$") {
      $value = $Matches[1]
    }
  }
  if ($null -eq $value) {
    return [pscustomobject]@{ Path = $path; Present = $true; Healthy = $false; Detail = "$FreshnessMetric is absent" }
  }
  $parsed = 0.0
  if (-not [double]::TryParse($value, [ref]$parsed)) {
    return [pscustomobject]@{ Path = $path; Present = $true; Healthy = $false; Detail = "$FreshnessMetric is not numeric" }
  }
  $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $age = [int]($now - $parsed)
  $detail = "last update ${age}s ago"
  $healthy = ($age -ge -$FreshnessSeconds -and $age -le $FreshnessSeconds)
  if ($age -lt -$FreshnessSeconds) { $detail = "last update is $([Math]::Abs($age))s in the future" }
  elseif ($age -gt $FreshnessSeconds) { $detail = "stale: last update ${age}s ago, limit ${FreshnessSeconds}s" }
  return [pscustomobject]@{ Path = $path; Present = $true; Healthy = $healthy; Detail = $detail }
}

function Invoke-Start {
  $task = Get-Task
  if ($null -eq $task) {
    Fail "scheduled task \$TaskName is not registered; run install.ps1"
  }
  Start-ScheduledTask -TaskName $TaskName -TaskPath '\'
  Report "Started scheduled task \$TaskName."
}

function Invoke-Stop {
  $configuration = Get-ConnectorConfig
  $task = Get-Task
  if ($null -ne $task) {
    Stop-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
  }
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    if (@(Get-ConnectorProcesses $configuration.Executable).Count -eq 0) {
      Report 'Stopped the Connector.'
      return
    }
    Start-Sleep -Milliseconds 250
  }
  $remaining = @(Get-ConnectorProcesses $configuration.Executable)
  if ($remaining.Count -eq 0) {
    Report 'Stopped the Connector.'
    return
  }
  Fail "the Connector is still running after ${TimeoutSeconds}s (pid $($remaining.ProcessId -join ', ')); it holds the state_dir lock"
}

function Invoke-Status {
  $configuration = Get-ConnectorConfig
  $healthy = $true

  $task = Get-Task
  if ($null -eq $task) {
    Report "task:    \$TaskName is not registered"
    $healthy = $false
  } else {
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath '\'
    Report "task:    \$TaskName $($task.State), last run $($info.LastRunTime), last result 0x$('{0:X}' -f $info.LastTaskResult)"
    if ($task.State -ne 'Running') { $healthy = $false }
  }

  $processes = @(Get-ConnectorProcesses $configuration.Executable)
  if ($processes.Count -eq 0) {
    Report "process: $($configuration.Executable) is not running"
    $healthy = $false
  } else {
    Report "process: $($configuration.Executable) pid $($processes.ProcessId -join ', ')"
  }

  # codex_control_connector_up 0 is evidence of a graceful stop only; a hard kill
  # leaves the last atomic textfile intact, so freshness is the health signal.
  $freshness = Get-MetricsFreshness $configuration.StateDir
  Report "metrics: $($freshness.Path) $($freshness.Detail)"
  if (-not $freshness.Healthy) { $healthy = $false }

  Report "config:  $($configuration.Path)"
  Report "state:   $($configuration.StateDir)"
  if (-not $healthy) { exit 1 }
}

function Invoke-Pair {
  $configuration = Get-ConnectorConfig
  if (-not (Test-Path -LiteralPath $configuration.Executable -PathType Leaf)) {
    Fail "no Connector executable at $($configuration.Executable); run install.ps1"
  }
  if (@(Get-ConnectorProcesses $configuration.Executable).Count -ne 0) {
    Fail 'the Connector is already running and holds the state_dir lock; run stop first'
  }
  $codePath = Join-Path $configuration.StateDir $PairingCodeName
  if (Test-Path -LiteralPath $codePath) {
    Remove-Item -LiteralPath $codePath -Force
  }
  # Start-Process joins ArgumentList with spaces without quoting, so a config
  # path containing a space would arrive as two arguments. install.ps1 quotes
  # the same path for the scheduled task; this has to match.
  $arguments = @("-config", "`"$($configuration.Path)`"", '-pair-only')
  $process = Start-Process -FilePath $configuration.Executable -ArgumentList $arguments -NoNewWindow -PassThru
  try {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $published = $false
    while ((Get-Date) -lt $deadline) {
      if (Test-Path -LiteralPath $codePath -PathType Leaf) { $published = $true; break }
      if ($process.HasExited) { break }
      Start-Sleep -Milliseconds 250
    }
    if ($published) {
      $code = (Get-Content -LiteralPath $codePath -Raw) | ConvertFrom-Json
      $expires = $code.expires_at
      if ($expires -is [datetime]) {
        $expires = $expires.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
      }
      Report ''
      Report "Pairing code: $($code.code)"
      Report "Expires at:   $expires"
      Report "Code file:    $codePath"
      Report ''
      Report 'Treat the code as sensitive until it expires or is claimed. Enter it only in the'
      Report 'authenticated same-origin Control PWA, and restrict access to the state directory.'
      Report ''
      Report 'Leave this command running until it confirms the browser claim and exits.'
    }
    $process.WaitForExit()
  } finally {
    if (-not $process.HasExited) {
      Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
  }
  if ($process.ExitCode -ne 0) {
    Fail "pairing exited with code $($process.ExitCode)"
  }
  Report "Paired. Run '$PSCommandPath start'."
}

function Invoke-Logs {
  $configuration = Get-ConnectorConfig
  $path = $LogPath
  if ([string]::IsNullOrWhiteSpace($path)) {
    $path = Join-Path $configuration.StateDir $LogName
  }
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    Fail "no Connector log at $path; the log is created inside state_dir on the first run under the scheduled task"
  }
  if ($Follow) {
    Get-Content -LiteralPath $path -Tail $Tail -Wait
  } else {
    Get-Content -LiteralPath $path -Tail $Tail
  }
}

switch ($Command) {
  'start' { Invoke-Start }
  'stop' { Invoke-Stop }
  'status' { Invoke-Status }
  'pair' { Invoke-Pair }
  'logs' { Invoke-Logs }
  default { Usage }
}
