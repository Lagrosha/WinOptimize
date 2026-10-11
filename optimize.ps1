#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Conservative Windows 11 optimization script with full rollback.

.DESCRIPTION
    Applies only changes that are known to work and are safe to undo.
    Before changing anything, the script records the original value of every
    registry entry, service startup type and power plan it touches into
    %ProgramData%\WinOptimize\state.json. Run with -Mode Rollback to undo.

    Not reversible: the cleanup step (temp files, update cache).

.PARAMETER Mode
    Apply (default) or Rollback.

.PARAMETER DisableSearchIndexing
    Opt-in. Disables the Windows Search service (file search becomes slower).

.PARAMETER ManualUpdates
    Opt-in. Windows will notify you about updates instead of installing them
    automatically. You must install updates yourself, or you lose security fixes.

.EXAMPLE
    .\optimize.ps1
    .\optimize.ps1 -SkipPower -SkipVisualEffects
    .\optimize.ps1 -Mode Rollback
#>

[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Rollback')]
    [string]$Mode = 'Apply',

    [switch]$SkipRestorePoint,
    [switch]$SkipTelemetry,
    [switch]$SkipBackgroundApps,
    [switch]$SkipPower,
    [switch]$SkipGameDvr,
    [switch]$SkipVisualEffects,
    [switch]$SkipCleanup,

    [switch]$DisableSearchIndexing,
    [switch]$ManualUpdates
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:StateDir  = Join-Path $env:ProgramData 'WinOptimize'
$script:StatePath = Join-Path $script:StateDir 'state.json'
$script:LogPath   = Join-Path $script:StateDir 'optimize.log'
$script:State     = $null

if (-not (Test-Path -LiteralPath $script:StateDir)) {
    New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
}

# ---------------------------------------------------------------------------
# Logging and state
# ---------------------------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $script:LogPath -Value $line
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function New-State {
    return [pscustomobject]@{
        Registry            = @()
        Services            = @()
        OriginalPowerScheme = $null
        CreatedPowerScheme  = $null
    }
}

function Get-State {
    if (Test-Path -LiteralPath $script:StatePath) {
        return (Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json)
    }
    return (New-State)
}

function Save-State {
    $script:State | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Log "=== $Name ==="
    try {
        & $Action
    }
    catch {
        Write-Log "Step failed ($Name): $($_.Exception.Message)" 'ERROR'
    }
}

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String')][string]$Type = 'DWord'
    )

    # Remember the original value only the first time we touch this entry.
    $known = @($script:State.Registry) | Where-Object { $_.Path -eq $Path -and $_.Name -eq $Name }
    if (-not $known) {
        $existed  = $false
        $original = $null
        if (Test-Path -LiteralPath $Path) {
            $item = Get-ItemProperty -LiteralPath $Path
            if ($item.PSObject.Properties[$Name]) {
                $existed  = $true
                $original = $item.$Name
            }
        }
        $script:State.Registry = @($script:State.Registry) + [pscustomobject]@{
            Path    = $Path
            Name    = $Name
            Type    = $Type
            Existed = $existed
            Value   = $original
        }
        Save-State
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Log "Registry set: $Path\$Name = $Value"
}

function Restore-RegistryValues {
    foreach ($e in @($script:State.Registry)) {
        try {
            if ($e.Existed) {
                if (-not (Test-Path -LiteralPath $e.Path)) {
                    New-Item -Path $e.Path -Force | Out-Null
                }
                New-ItemProperty -LiteralPath $e.Path -Name $e.Name -Value $e.Value -PropertyType $e.Type -Force | Out-Null
                Write-Log "Registry restored: $($e.Path)\$($e.Name) = $($e.Value)"
            }
            elseif (Test-Path -LiteralPath $e.Path) {
                Remove-ItemProperty -LiteralPath $e.Path -Name $e.Name -ErrorAction SilentlyContinue
                Write-Log "Registry value removed: $($e.Path)\$($e.Name)"
            }
        }
        catch {
            Write-Log "Could not restore $($e.Path)\$($e.Name): $($_.Exception.Message)" 'WARN'
        }
    }
    $script:State.Registry = @()
}

# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

function Disable-ServiceSafe {
    param([Parameter(Mandatory)][string]$Name)

    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log "Service not found, skipping: $Name" 'WARN'
        return
    }

    $known = @($script:State.Services) | Where-Object { $_.Name -eq $Name }
    if (-not $known) {
        $delayed = $false
        $props = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -ErrorAction SilentlyContinue
        if ($props -and $props.PSObject.Properties['DelayedAutostart'] -and $props.DelayedAutostart -eq 1) {
            $delayed = $true
        }
        $script:State.Services = @($script:State.Services) + [pscustomobject]@{
            Name      = $Name
            StartMode = [string]$svc.StartMode
            Delayed   = $delayed
        }
        Save-State
    }

    if ($svc.State -eq 'Running') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }
    Set-Service -Name $Name -StartupType Disabled
    Write-Log "Service disabled: $Name"
}

function Restore-Services {
    foreach ($s in @($script:State.Services)) {
        try {
            if ($s.Delayed) {
                & sc.exe config $s.Name start= delayed-auto | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe returned $LASTEXITCODE" }
            }
            else {
                $type = switch ($s.StartMode) {
                    'Auto'     { 'Automatic' }
                    'Manual'   { 'Manual' }
                    'Disabled' { 'Disabled' }
                    default    { 'Manual' }
                }
                Set-Service -Name $s.Name -StartupType $type
            }
            if ($s.StartMode -eq 'Auto') {
                Start-Service -Name $s.Name -ErrorAction SilentlyContinue
            }
            Write-Log "Service restored: $($s.Name) ($($s.StartMode))"
        }
        catch {
            Write-Log "Could not restore service $($s.Name): $($_.Exception.Message)" 'WARN'
        }
    }
    $script:State.Services = @()
}

# ---------------------------------------------------------------------------
# Power plan
# ---------------------------------------------------------------------------

$script:GuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

function Enable-UltimatePerformance {
    $template = 'e9a42b02-d5df-448d-aa00-03f14749eb61'

    if (-not $script:State.OriginalPowerScheme) {
        $active = (& powercfg.exe /getactivescheme) -join ' '
        $m = [regex]::Match($active, $script:GuidPattern)
        if ($m.Success) {
            $script:State.OriginalPowerScheme = $m.Value
            Save-State
        }
    }

    # Reuse the scheme from a previous run if it still exists.
    $schemeGuid = $script:State.CreatedPowerScheme
    $listing = (& powercfg.exe /list) -join "`n"
    if (-not $schemeGuid -or -not $listing.ToLower().Contains(([string]$schemeGuid).ToLower())) {
        $out = (& powercfg.exe -duplicatescheme $template 2>$null) -join ' '
        $m = [regex]::Match($out, $script:GuidPattern)
        if ($LASTEXITCODE -ne 0 -or -not $m.Success) {
            Write-Log 'Ultimate Performance is not available on this device. Power plan left unchanged.' 'WARN'
            return
        }
        $schemeGuid = $m.Value
        $script:State.CreatedPowerScheme = $schemeGuid
        Save-State
    }

    # Keep all cores unparked while on AC power.
    & powercfg.exe /setacvalueindex $schemeGuid SUB_PROCESSOR CPMINCORES 100 | Out-Null
    & powercfg.exe /setactive $schemeGuid
    if ($LASTEXITCODE -ne 0) { throw 'powercfg /setactive failed.' }
    Write-Log "Power plan active: Ultimate Performance ($schemeGuid), core parking off on AC."
    Write-Log 'Note: on a laptop this raises heat and battery drain. Switch plans when unplugged.' 'WARN'
}

function Restore-PowerPlan {
    $balanced = '381b4222-f694-41f0-9685-ff5bb260df2e'
    $orig = $script:State.OriginalPowerScheme
    if ($orig) {
        & powercfg.exe /setactive $orig 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Log 'Original power plan no longer exists. Switching to Balanced.' 'WARN'
            & powercfg.exe /setactive $balanced
        }
        else {
            Write-Log "Power plan restored: $orig"
        }
    }
    if ($script:State.CreatedPowerScheme) {
        & powercfg.exe /delete $script:State.CreatedPowerScheme 2>$null | Out-Null
        Write-Log 'Ultimate Performance scheme created by this script was deleted.'
    }
    $script:State.OriginalPowerScheme = $null
    $script:State.CreatedPowerScheme  = $null
}

# ---------------------------------------------------------------------------
# Cleanup helpers (not reversible)
# ---------------------------------------------------------------------------

function Clear-FolderContents {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

function Get-FreeSpaceBytes {
    return ([System.IO.DriveInfo]::new($env:SystemDrive)).AvailableFreeSpace
}

function Clear-UpdateCache {
    $wasRunning = @()
    foreach ($n in @('wuauserv', 'bits')) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq 'Running') {
            $wasRunning += $n
            Stop-Service -Name $n -Force -ErrorAction SilentlyContinue
        }
    }
    Clear-FolderContents -Path (Join-Path $env:SystemRoot 'SoftwareDistribution\Download')
    foreach ($n in $wasRunning) {
        Start-Service -Name $n -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------

function New-SafetyRestorePoint {
    try {
        Enable-ComputerRestore -Drive "$($env:SystemDrive)\"
        Checkpoint-Computer -Description 'Before optimize.ps1' -RestorePointType 'MODIFY_SETTINGS'
        Write-Log 'Restore point created.'
    }
    catch {
        Write-Log "Could not create a restore point: $($_.Exception.Message)" 'WARN'
        Write-Log 'Continuing. The script has its own rollback (-Mode Rollback).' 'WARN'
    }
}

function Optimize-Telemetry {
    # Note: on Home/Pro editions Windows treats 0 as "Required diagnostic data" (minimum allowed).
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Value 1
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0
    Disable-ServiceSafe -Name 'DiagTrack'
}

function Optimize-BackgroundApps {
    # 2 = force deny. Store apps will not run in the background (no live tiles/notifications from them).
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsRunInBackground' -Value 2
}

function Optimize-GameDvr {
    # Disables background recording and capture. Game Mode and Xbox services stay untouched.
    Set-RegistryValue -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Value 0
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Value 0
}

function Optimize-VisualEffects {
    # Takes full effect after sign-out.
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAnimations' -Value 0
    Set-RegistryValue -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name 'MinAnimate' -Value '0' -Type String
}

function Optimize-Cleanup {
    $before = Get-FreeSpaceBytes
    Clear-FolderContents -Path $env:TEMP
    Clear-FolderContents -Path (Join-Path $env:SystemRoot 'Temp')
    Write-Log 'Temp folders cleaned (files in use are skipped).'

    Clear-UpdateCache
    Write-Log 'Windows Update download cache cleaned.'

    Write-Log 'Running component store cleanup. This can take several minutes...'
    & dism.exe /Online /Cleanup-Image /StartComponentCleanup | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "DISM returned exit code $LASTEXITCODE." 'WARN'
    }

    $freedMb = [math]::Round(((Get-FreeSpaceBytes) - $before) / 1MB, 1)
    Write-Log "Free space change on $($env:SystemDrive): $freedMb MB"
}

function Optimize-SearchIndexing {
    Disable-ServiceSafe -Name 'WSearch'
}

function Optimize-ManualUpdates {
    # AUOptions 2 = notify before download and install. Updates are NOT disabled.
    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegistryValue -Path $au -Name 'NoAutoUpdate' -Value 0
    Set-RegistryValue -Path $au -Name 'AUOptions' -Value 2
    Write-Log 'Updates are now manual. Check for updates regularly in Settings.' 'WARN'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Log "Started. Mode: $Mode"
$script:State = Get-State

if ($Mode -eq 'Rollback') {
    Invoke-Step -Name 'Restore registry'   -Action { Restore-RegistryValues }
    Invoke-Step -Name 'Restore services'   -Action { Restore-Services }
    Invoke-Step -Name 'Restore power plan' -Action { Restore-PowerPlan }
    Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction SilentlyContinue
    Write-Log 'Rollback finished. Sign out or restart to apply everything.'
    Write-Log 'Cleanup (temp files, update cache) cannot be undone.'
    return
}

if (-not $SkipRestorePoint)  { Invoke-Step -Name 'Restore point'       -Action { New-SafetyRestorePoint } }
if (-not $SkipTelemetry)     { Invoke-Step -Name 'Telemetry'           -Action { Optimize-Telemetry } }
if (-not $SkipBackgroundApps){ Invoke-Step -Name 'Background apps'     -Action { Optimize-BackgroundApps } }
if (-not $SkipPower)         { Invoke-Step -Name 'Power plan'          -Action { Enable-UltimatePerformance } }
if (-not $SkipGameDvr)       { Invoke-Step -Name 'Game DVR'            -Action { Optimize-GameDvr } }
if (-not $SkipVisualEffects) { Invoke-Step -Name 'Visual effects'      -Action { Optimize-VisualEffects } }
if ($DisableSearchIndexing)  { Invoke-Step -Name 'Search indexing'     -Action { Optimize-SearchIndexing } }
if ($ManualUpdates)          { Invoke-Step -Name 'Manual updates'      -Action { Optimize-ManualUpdates } }
if (-not $SkipCleanup)       { Invoke-Step -Name 'Cleanup'             -Action { Optimize-Cleanup } }

Save-State
Write-Log 'Done. Restart your PC to apply all changes.'
Write-Log "To undo: .\optimize.ps1 -Mode Rollback    (log: $script:LogPath)"