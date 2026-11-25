<#
  C:\SOAR\responder.ps1 — hanh dong SOAR tren Windows (DATN, Goi A)

  Shuffle goi qua OpenSSH (user soar-responder):
    powershell -NoProfile -NonInteractive -File C:\SOAR\responder.ps1 -Action <Ten> [tham so]

  Moi ket qua in ra MOT dong JSON. Ma thoat 0 = thanh cong / khong can lam gi, 1 = tu choi hoac loi.
  Moi lan chay deu ghi Event Log Application, nguon DATN-SOAR (Winlogbeat gui ve ELK de doi chieu).

  Pham vi lab (an toan):
    - File: chi trong C:\DATN\  (Quarantine/Restore)
    - Task: chi ten \DATN-*      (DisableTask/EnableTask)
    - Kill: PID phai khop dung duong dan exe; khong kill tien trinh he thong
    - Audit policy (PB23, ban goi-a-2): AuditBaseline chup chinh sach dang dung lam chuan,
      RestoreAuditPolicy nap lai tu C:\SOAR\baseline\audit.csv, AuditStatus so sanh voi chuan.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('Status', 'ProcessInfo', 'KillProcess', 'Hash', 'Quarantine', 'Restore', 'TestPath',
               'DisableTask', 'EnableTask', 'TaskState', 'EnableDefender', 'DefenderStatus',
               'EnableFirewall', 'FirewallStatus', 'RestoreLabData', 'LabDataStatus',
               'AuditBaseline', 'RestoreAuditPolicy', 'AuditStatus')]
  [string]$Action,
  [int]$ProcessId,
  [string]$Image,
  [string]$Path,
  [string]$Sha256,
  [string]$Id,
  [string]$TaskName
)

$ErrorActionPreference = 'Stop'
$LabRoot   = 'C:\DATN\'
$QDir      = 'C:\SOAR\quarantine'
$BackupDir = 'C:\SOAR\backup'
$Baseline  = 'C:\SOAR\baseline'
$Protected = @('system', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'msmpeng',
               'nissrv', 'securityhealthservice', 'sshd', 'winlogbeat', 'sysmon', 'sysmon64', 'explorer',
               'dwm', 'fontdrvhost', 'conhost', 'vmtoolsd')

function Out-Json([hashtable]$obj, [int]$code = 0) {
  $obj['action'] = $Action
  $obj['host']   = $env:COMPUTERNAME
  $obj['time']   = (Get-Date).ToUniversalTime().ToString('o')
  $json = $obj | ConvertTo-Json -Compress -Depth 5
  try {
    $type = 'Information'; if ($code -ne 0) { $type = 'Warning' }
    Write-EventLog -LogName Application -Source 'DATN-SOAR' -EventId (1000 + $code) -EntryType $type -Message $json
  } catch { }
  Write-Output $json
  exit $code
}
function Fail([string]$msg) { Out-Json @{ result = 'ERROR'; message = $msg } 1 }

function Test-LabPath([string]$p) {
  if (-not $p -or $p -match '\.\.') { return $false }
  $full = [IO.Path]::GetFullPath($p)
  return $full.StartsWith($LabRoot, [StringComparison]::OrdinalIgnoreCase)
}
function Get-Sha([string]$p) { (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() }
function Get-AuditMap {
  # Subcategory GUID -> Inclusion Setting, doc tu "auditpol /get /category:* /r" (CSV, khong phu thuoc ngon ngu)
  $rows = & auditpol /get /category:* /r | Where-Object { $_ -match ',' } | ConvertFrom-Csv
  $map = @{}
  foreach ($r in $rows) { if ($r.'Subcategory GUID') { $map[$r.'Subcategory GUID'] = $r.'Inclusion Setting' } }
  return $map
}
function Compare-Audit {
  $basefile = Join-Path $Baseline 'audit-get.csv'
  if (-not (Test-Path $basefile)) { Fail 'Chua co C:\SOAR\baseline\audit-get.csv (chay -Action AuditBaseline luc may sach)' }
  $base = @{}
  foreach ($r in (Import-Csv $basefile)) { if ($r.'Subcategory GUID') { $base[$r.'Subcategory GUID'] = $r.'Inclusion Setting' } }
  $now = Get-AuditMap
  $diff = @($base.Keys | Where-Object { $now[$_] -ne $base[$_] })
  $enabled = @($now.Values | Where-Object { $_ -and $_ -notmatch '^No Auditing$' }).Count
  return @{ match = ($diff.Count -eq 0); diff = $diff.Count; enabled_subcategories = $enabled; baseline_entries = $base.Count }
}
function Get-TaskParts([string]$tn) {
  if ($tn -match '^\\?(DATN-[A-Za-z0-9_.-]{1,60})$') { return @{ path = '\'; name = $Matches[1] } }
  Fail "Task '$tn' ngoai pham vi lab (chi \DATN-*)"
}

try {
  switch ($Action) {

    'Status' {
      $mp = Get-MpComputerStatus
      $off = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object { $_.Name })
      Out-Json @{ result = 'OK'; responder = 'goi-a-2'; defender_rtp = [bool]$mp.RealTimeProtectionEnabled; firewall_off = $off }
    }

    'AuditBaseline' {
      New-Item -ItemType Directory -Force $Baseline | Out-Null
      $csv = Join-Path $Baseline 'audit.csv'
      & auditpol /backup /file:$csv | Out-Null
      & auditpol /get /category:* /r | Where-Object { $_ -match ',' } | Set-Content -Encoding UTF8 (Join-Path $Baseline 'audit-get.csv')
      $c = Compare-Audit
      Out-Json @{ result = 'OK'; baseline = $csv; entries = $c.baseline_entries; enabled_subcategories = $c.enabled_subcategories }
    }

    'RestoreAuditPolicy' {
      $csv = Join-Path $Baseline 'audit.csv'
      if (-not (Test-Path $csv)) { Fail 'Chua co C:\SOAR\baseline\audit.csv (chay -Action AuditBaseline luc may sach)' }
      $before = Compare-Audit
      & auditpol /restore /file:$csv | Out-Null
      $after = Compare-Audit
      $r = 'RESTORED'; if (-not $after.match) { $r = 'PARTIAL' }
      Out-Json @{ result = $r; from = $csv; diff_before = $before.diff; diff_after = $after.diff; match = $after.match;
                  enabled_subcategories = $after.enabled_subcategories }
    }

    'AuditStatus' {
      $c = Compare-Audit
      $r = 'MATCH'; if (-not $c.match) { $r = 'DRIFT' }
      Out-Json @{ result = $r; match = $c.match; diff = $c.diff; enabled_subcategories = $c.enabled_subcategories }
    }

    'ProcessInfo' {
      if (-not $ProcessId) { Fail 'Can -ProcessId' }
      $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId"
      if (-not $p) { Out-Json @{ result = 'NOT_RUNNING'; pid = $ProcessId } }
      Out-Json @{ result = 'RUNNING'; pid = $ProcessId; image = $p.ExecutablePath; command_line = $p.CommandLine;
                  parent_pid = $p.ParentProcessId; started = $p.CreationDate.ToUniversalTime().ToString('o') }
    }

    'KillProcess' {
      if (-not $ProcessId -or -not $Image) { Fail 'Can -ProcessId va -Image' }
      $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId"
      if (-not $p) { Out-Json @{ result = 'NOT_RUNNING'; pid = $ProcessId; note = 'tien trinh da ket thuc truoc khi phan ung' } }
      if (-not $p.ExecutablePath -or ($p.ExecutablePath -ne $Image)) {
        Fail "PID $ProcessId dang chay '$($p.ExecutablePath)', khong khop '$Image' (co the PID da bi tai su dung)"
      }
      $name = [IO.Path]::GetFileNameWithoutExtension($p.ExecutablePath).ToLower()
      if ($Protected -contains $name) { Fail "Tien trinh he thong '$name', tu choi" }
      $kids = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" | Where-Object {
        $Protected -notcontains ([IO.Path]::GetFileNameWithoutExtension("$($_.ExecutablePath)")).ToLower() })
      foreach ($k in $kids) { Stop-Process -Id $k.ProcessId -Force -ErrorAction SilentlyContinue }
      Stop-Process -Id $ProcessId -Force
      Start-Sleep -Milliseconds 700
      $still = [bool](Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
      $r = 'KILLED'; if ($still) { $r = 'STILL_RUNNING' }
      Out-Json @{ result = $r; pid = $ProcessId; image = $Image; children_killed = $kids.Count }
    }

    'Hash' {
      if (-not $Path) { Fail 'Can -Path' }
      if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Out-Json @{ result = 'MISSING'; path = $Path } }
      $i = Get-Item -LiteralPath $Path -Force
      $sig = Get-AuthenticodeSignature -LiteralPath $i.FullName
      Out-Json @{ result = 'OK'; path = $i.FullName; sha256 = (Get-Sha $i.FullName); size = $i.Length;
                  signature = "$($sig.Status)"; signer = "$($sig.SignerCertificate.Subject)" }
    }

    'Quarantine' {
      if (-not (Test-LabPath $Path)) { Fail "Duong dan ngoai pham vi lab (chi C:\DATN\): $Path" }
      if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Out-Json @{ result = 'MISSING'; path = $Path } }
      $i = Get-Item -LiteralPath $Path -Force
      if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail 'File la reparse point/symlink, tu choi' }
      $h = Get-Sha $i.FullName
      if ($Sha256 -and ($Sha256.ToLower() -ne $h)) { Fail "SHA-256 khong khop (thuc te $h)" }
      $qid = '{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), $h.Substring(0, 12)
      $dst = Join-Path $QDir $qid
      New-Item -ItemType Directory -Force $dst | Out-Null
      Move-Item -LiteralPath $i.FullName -Destination (Join-Path $dst 'file.quarantined') -Force
      @{ original_path = $i.FullName; sha256 = $h; size = $i.Length; time = (Get-Date).ToUniversalTime().ToString('o') } |
        ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $dst 'meta.json')
      Out-Json @{ result = 'QUARANTINED'; id = $qid; sha256 = $h; path = $i.FullName }
    }

    'Restore' {
      if ($Id -notmatch '^\d{14}-[0-9a-f]{12}$') { Fail 'Id khong hop le' }
      $dst = Join-Path $QDir $Id
      $meta = Get-Content -Raw (Join-Path $dst 'meta.json') | ConvertFrom-Json
      if (Test-Path -LiteralPath $meta.original_path) { Fail 'Da co file o duong dan goc' }
      Move-Item -LiteralPath (Join-Path $dst 'file.quarantined') -Destination $meta.original_path
      Out-Json @{ result = 'RESTORED'; path = $meta.original_path; sha256 = $meta.sha256 }
    }

    'TestPath' {
      if (-not $Path) { Fail 'Can -Path' }
      $r = 'ABSENT'; if (Test-Path -LiteralPath $Path) { $r = 'PRESENT' }
      Out-Json @{ result = $r; path = $Path }
    }

    'DisableTask' {
      $t = Get-TaskParts $TaskName
      $task = Get-ScheduledTask -TaskPath $t.path -TaskName $t.name -ErrorAction SilentlyContinue
      if (-not $task) { Out-Json @{ result = 'MISSING'; task = $TaskName } }
      $xml = Join-Path $BackupDir ('task-{0}-{1}.xml' -f $t.name, (Get-Date -Format 'yyyyMMddHHmmss'))
      Export-ScheduledTask -TaskPath $t.path -TaskName $t.name | Set-Content -Encoding Unicode $xml
      Disable-ScheduledTask -TaskPath $t.path -TaskName $t.name | Out-Null
      $s = (Get-ScheduledTask -TaskPath $t.path -TaskName $t.name).State
      Out-Json @{ result = 'OK'; task = $TaskName; state = "$s"; backup = $xml }
    }

    'EnableTask' {
      $t = Get-TaskParts $TaskName
      Enable-ScheduledTask -TaskPath $t.path -TaskName $t.name | Out-Null
      $s = (Get-ScheduledTask -TaskPath $t.path -TaskName $t.name).State
      Out-Json @{ result = 'OK'; task = $TaskName; state = "$s" }
    }

    'TaskState' {
      $t = Get-TaskParts $TaskName
      $task = Get-ScheduledTask -TaskPath $t.path -TaskName $t.name -ErrorAction SilentlyContinue
      if (-not $task) { Out-Json @{ result = 'MISSING'; task = $TaskName } }
      Out-Json @{ result = 'OK'; task = $TaskName; state = "$($task.State)" }
    }

    'EnableDefender' {
      Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
                       -DisableIOAVProtection $false -DisableScriptScanning $false
      $base = @(Get-Content (Join-Path $Baseline 'defender-exclusions.txt') -ErrorAction SilentlyContinue)
      $pref = Get-MpPreference
      $removed = @()
      foreach ($x in @($pref.ExclusionPath)) {
        if ($x -and ($base -notcontains $x)) { Remove-MpPreference -ExclusionPath $x; $removed += "path:$x" }
      }
      foreach ($x in @($pref.ExclusionProcess)) { if ($x) { Remove-MpPreference -ExclusionProcess $x; $removed += "process:$x" } }
      foreach ($x in @($pref.ExclusionExtension)) { if ($x) { Remove-MpPreference -ExclusionExtension $x; $removed += "ext:$x" } }
      Start-Sleep -Seconds 2
      $s = Get-MpComputerStatus
      $r = 'ENABLED'; if (-not $s.RealTimeProtectionEnabled) { $r = 'STILL_DISABLED' }
      Out-Json @{ result = $r; rtp = [bool]$s.RealTimeProtectionEnabled; behavior = [bool]$s.BehaviorMonitorEnabled;
                  ioav = [bool]$s.IoavProtectionEnabled; removed_exclusions = $removed }
    }

    'DefenderStatus' {
      $s = Get-MpComputerStatus
      $r = 'ENABLED'; if (-not $s.RealTimeProtectionEnabled) { $r = 'DISABLED' }
      Out-Json @{ result = $r; rtp = [bool]$s.RealTimeProtectionEnabled; exclusions = @((Get-MpPreference).ExclusionPath) }
    }

    'EnableFirewall' {
      Set-NetFirewallProfile -All -Enabled True
      $off = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object { $_.Name })
      $r = 'ENABLED'; if ($off.Count -gt 0) { $r = 'STILL_DISABLED' }
      Out-Json @{ result = $r; disabled_profiles = $off }
    }

    'FirewallStatus' {
      $off = @(Get-NetFirewallProfile | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object { $_.Name })
      $r = 'ENABLED'; if ($off.Count -gt 0) { $r = 'DISABLED' }
      Out-Json @{ result = $r; disabled_profiles = $off }
    }

    'RestoreLabData' {
      $src = 'C:\DATN\backup\share'; $dst = 'C:\DATN\share'
      if (-not (Test-Path $src)) { Fail 'Chua co ban sao luu C:\DATN\backup\share' }
      Get-ChildItem $dst -File -Force | Where-Object { $_.Extension -eq '.datnlock' -or $_.Name -like 'README-DATN*' } |
        Remove-Item -Force
      robocopy $src $dst /E /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
      $n = @(Get-ChildItem $dst -File).Count
      $locked = @(Get-ChildItem $dst -File -Filter '*.datnlock').Count
      $r = 'RESTORED'; if ($locked -gt 0) { $r = 'PARTIAL' }
      Out-Json @{ result = $r; files = $n; locked_left = $locked }
    }

    'LabDataStatus' {
      $dst = 'C:\DATN\share'
      $n = @(Get-ChildItem $dst -File -ErrorAction SilentlyContinue).Count
      $locked = @(Get-ChildItem $dst -File -Filter '*.datnlock' -ErrorAction SilentlyContinue).Count
      Out-Json @{ result = 'OK'; files = $n; locked = $locked; clean = ($n - $locked) }
    }
  }
} catch {
  Fail $_.Exception.Message
}
