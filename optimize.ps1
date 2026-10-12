#Requires -Version 5.1
 
<#
.SYNOPSIS
    Windows system report and opt-in optimizer with rollback for recorded reversible changes.

.DESCRIPTION
    Report is the default and does not write to disk. Audit performs read-only
    diagnostics and writes a structured JSON report under the current user's profile.
    Apply records rollback data for supported reversible changes in
    %ProgramData%\WinOptimize\state.json. Cleanup, app removal and runtime installation
    are not reversible by this script and require explicit opt-in switches.

.PARAMETER Mode
    Report (default, text only), Audit (read-only JSON audit), WhatIf (preview), Apply, or Rollback.

.PARAMETER RunCleanup
    Opt-in. Clears temporary files and caches. These operations are not reversible.

.PARAMETER InstallRuntimes
    Opt-in. Installs the listed runtime packages from winget; installations are not
    reversible by this script.

.PARAMETER RemoveApps
    Opt-in. Enables removal of selected built-in apps. Removal is not reversible by
    this script; confirmation is still requested unless -Yes is supplied.

.PARAMETER PingTargets
    Optional host names or IP addresses to probe with ICMP in Audit mode. No ping
    requests are sent unless this parameter is supplied. ICMP may be filtered.

.PARAMETER PingCount
    Number of ICMP probes per target in Audit mode, from 1 to 20. Defaults to 5.

.PARAMETER DisableSearchIndexing
    Opt-in. Disables the Windows Search service (file search becomes slower).

.PARAMETER TidyTaskbar
    Opt-in. Hides the taskbar search box and aligns the taskbar to the left.
    This is a layout preference, not a performance tweak.

.PARAMETER DisableNotifications
    Opt-in. Turns off ALL toast notifications (including Windows Security alerts)
    and the notification center.

.PARAMETER DisableHibernation
    Opt-in. Turns hibernation and Fast Startup off and deletes hiberfil.sys.
    Not recommended on laptops: a sleeping laptop with a drained battery loses unsaved work.

.PARAMETER DefenderExcludePaths
    Folders to exclude from Microsoft Defender scanning, for example a game library:
    -DefenderExcludePaths 'D:\SteamLibrary'. Real-time protection stays ON. Only exclude
    folders you trust: files in them are not scanned. Rollback removes the exclusions added here.

.PARAMETER DisableMemoryCompression
    Opt-in. Turns off memory compression. Only applied when the PC has 16 GB RAM or more.
    Needs a restart. The effect is small; leave it on if you are unsure.

.PARAMETER DisableSysMain
    Opt-in. Turns off the SysMain (Superfetch) service. Only applied when the system drive
    is detected as an SSD; on a hard disk it would make things slower.

.PARAMETER EnableHags
    Opt-in. Turns on Hardware-accelerated GPU Scheduling. Results differ between systems
    (and drivers), so measure before keeping it. Needs a restart.

.PARAMETER GpuHighPerformanceApps
    Full paths to .exe files that should always use the high-performance GPU, for example
    -GpuHighPerformanceApps 'C:\Games\Dota\game\bin\win64\dota2.exe'. Useful on laptops
    with integrated + discrete graphics.

.PARAMETER FixedPagefile
    Opt-in. Replaces the system-managed paging file on the system drive with a fixed size
    chosen from your RAM: equal to RAM, at least 4 GB and at most 16 GB. Skipped if a custom
    paging file setup already exists or free disk space is low. Needs a restart.

.PARAMETER DisableLocation
    Opt-in. Disables the Geolocation service. Automatic time zone, Find My Device and
    location-aware apps stop working.

.PARAMETER DisableWirelessDisplay
    Opt-in. Disables the Wi-Fi Direct / wireless display connection service.
    Casting to or from this PC (Miracast) stops working.

.PARAMETER DisableMemoryIntegrity
    Opt-in. Turns off Memory Integrity (HVCI, virtualization-based code integrity). This can
    raise FPS in some CPU-heavy games, but it REMOVES a kernel security protection and some
    anti-cheat or driver setups expect it. Skipped if the setting is locked by UEFI. Needs a restart.

.PARAMETER RestartExplorer
    Opt-in. Restarts the Windows shell (taskbar, desktop) at the end so shell changes apply
    without signing out. Open File Explorer windows are closed.

.PARAMETER EnableGpuMsi
    Opt-in. Switches a discrete NVIDIA/AMD GPU to Message Signaled Interrupts if it is not
    already using them. Current NVIDIA/AMD drivers usually enable MSI on their own, so check
    -Mode Report first. If the screen stays black after a restart, boot to Safe Mode and
    run -Mode Rollback.

.PARAMETER DisableMouseAcceleration
    Opt-in. Turns off "Enhance pointer precision" (mouse acceleration). Changes how the
    mouse feels; applies after you sign out and back in.

.PARAMETER RemoveXboxApps
    Opt-in. Also removes the Xbox app and Game Bar overlays. The Xbox Identity Provider,
    Gaming Services and Xbox TCUI are never removed (Game Pass / Store games need them).

.PARAMETER RemoveOneDrive
    Opt-in. Uninstalls the OneDrive client. Skipped automatically if Desktop, Documents
    or Pictures are stored inside OneDrive.

.PARAMETER KeepApps
    App name fragments that must NOT be removed, for example -KeepApps Spotify,Netflix.

.PARAMETER Yes
    Do not ask for confirmation before removing apps.

.PARAMETER ManualUpdates
    Opt-in. Windows will notify you about updates instead of installing them
    automatically. You must install updates yourself, or you lose security fixes.

.EXAMPLE
    .\optimize.ps1
    .\optimize.ps1 -Mode Audit
    .\optimize.ps1 -Mode Audit -PingTargets '192.168.1.1','1.1.1.1' -PingCount 5
    .\optimize.ps1 -Mode WhatIf
    .\optimize.ps1 -Mode Apply
    .\optimize.ps1 -Mode Apply -SkipPower -SkipVisualEffects
    .\optimize.ps1 -Mode Rollback
    .\optimize.ps1 -Mode Startup
    .\optimize.ps1 -Mode Startup -StartupAction Disable -StartupName 'OneDrive'
    .\optimize.ps1 -Mode Components
    .\optimize.ps1 -Mode Repair
    .\optimize.ps1 -Mode Compare
    .\optimize.ps1 -Mode Apply -Preset Gaming
#>

[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Rollback', 'Report', 'Audit', 'WhatIf', 'Startup', 'Components', 'Repair', 'Compare')]
    [string]$Mode = 'Report',

    [switch]$SkipRestorePoint,
    [switch]$SkipTelemetry,
    [switch]$SkipBackgroundApps,
    [switch]$SkipPower,
    [switch]$SkipGameDvr,
    [switch]$SkipVisualEffects,
    [switch]$SkipAccessibility,
    [switch]$SkipSuggestions,
    [switch]$SkipInterface,
    [switch]$SkipSystemServices,
    [switch]$SkipAppRemoval,
    [switch]$SkipEdgeTweaks,
    [switch]$SkipDefenderTuning,
    [switch]$SkipDisk,
    [switch]$SkipNetwork,
    [switch]$SkipGraphics,
    [switch]$SkipRuntimes,
    [switch]$SkipMiscServices,
    [switch]$SkipTracing,
    [switch]$SkipNicTuning,
    [switch]$SkipDevicePower,
    [switch]$SkipUpdaters,
    [string[]]$DefenderExcludePaths = @(),
    [switch]$SkipCleanup,
    [switch]$RunCleanup,
    [switch]$InstallRuntimes,
    [switch]$RemoveApps,
    [string[]]$PingTargets = @(),
    [ValidateRange(1, 20)][int]$PingCount = 5,

    [switch]$DisableSearchIndexing,
    [switch]$TidyTaskbar,
    [switch]$DisableNotifications,
    [switch]$DisableHibernation,
    [switch]$DisableMemoryCompression,
    [switch]$DisableSysMain,
    [switch]$EnableHags,
    [switch]$FixedPagefile,
    [switch]$DisableMemoryIntegrity,
    [switch]$RestartExplorer,
    [switch]$EnableGpuMsi,
    [switch]$DisableMouseAcceleration,
    [switch]$DisableNagle,
    [switch]$DisableLocation,
    [switch]$DisableWirelessDisplay,
    [string[]]$GpuHighPerformanceApps = @(),
    [switch]$RemoveXboxApps,
    [switch]$RemoveOneDrive,
    [string[]]$KeepApps = @(),
    [switch]$Yes,
    [switch]$ManualUpdates,
    [switch]$SkipBenchmark,
    [ValidateSet('List', 'Disable', 'Enable')]
    [string]$StartupAction = 'List',
    [string]$StartupName,
    [ValidateSet('List', 'Disable', 'Enable')]
    [string]$ComponentAction = 'List',
    [string]$ComponentName,
    [switch]$ComponentShowAll,
    [ValidateSet('Check', 'Scan', 'Restore')]
    [string]$RepairAction = 'Check',
    [ValidateSet('None', 'Minimal', 'Gaming', 'Full')]
    [string]$Preset = 'None'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:StateDir  = Join-Path $env:ProgramData 'WinOptimize'
$script:StatePath = Join-Path $script:StateDir 'state.json'
$script:LogPath   = Join-Path $script:StateDir 'optimize.log'
$script:BenchmarkDir = Join-Path $script:StateDir 'benchmarks'
$script:ReportsDir = Join-Path $script:StateDir 'reports'
$script:State     = $null
$script:RollbackHadWarnings = $false
$script:WhatIfStepCount = 0
$script:KeepApps = @($KeepApps | Where-Object { $_ -and $_.Trim() })
$script:PingTargetsClean = @($PingTargets | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
$script:GpuAppsClean = @($GpuHighPerformanceApps | Where-Object { $_ -and $_.Trim() })
$script:StartupPublisherCache = @{}
$script:VerifyResults = @()
$script:StepResults = @()
$script:DefenderExcludePathsClean = @($DefenderExcludePaths | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)

# ---------------------------------------------------------------------------
# Logging and state
# ---------------------------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    if ($Mode -eq 'Rollback' -and $Level -in @('WARN', 'ERROR')) {
        $script:RollbackHadWarnings = $true
    }

    if ($Mode -in @('Report', 'Audit', 'WhatIf', 'Compare') -or ($Mode -eq 'Startup' -and $StartupAction -eq 'List')) {
        Write-Host $line
        return
    }

    Add-Content -LiteralPath $script:LogPath -Value $line
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function New-State {
    return [pscustomobject]@{
        Registry                    = @()
        Services                    = @()
        Tasks                       = @()
        OriginalPowerScheme         = $null
        CreatedPowerScheme          = $null
        HibernationWasEnabled       = $null
        TrimWasDisabled             = $null
        MemoryCompressionWasEnabled = $null
        PowerSettings               = @()
        NetChanges                  = @()
        DefenderScanCpuLoad         = $null
        DefenderExclusions          = @()
        StartupApproved             = @()
        StartupFolder               = @()
        Components                  = @()
    }
}

function Get-State {
    if (Test-Path -LiteralPath $script:StatePath) {
        try {
            $loaded = Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
        }
        catch {
            throw "Cannot read state.json. The file was left untouched to protect rollback data. Details: $($_.Exception.Message)"
        }

        if ($null -eq $loaded -or $loaded -is [array] -or $loaded -is [string] -or $loaded -is [System.ValueType]) {
            throw 'state.json does not contain a valid state object. The file was left untouched.'
        }

        $arrayProps = @('Registry', 'Services', 'Tasks', 'DefenderExclusions', 'PowerSettings', 'NetChanges', 'StartupApproved', 'StartupFolder', 'Components')
        $knownProps = @($arrayProps + @(
            'OriginalPowerScheme', 'CreatedPowerScheme',
            'HibernationWasEnabled', 'TrimWasDisabled',
            'MemoryCompressionWasEnabled', 'DefenderScanCpuLoad'
        ))
        if (-not (@($knownProps | Where-Object { $loaded.PSObject.Properties[$_] }).Count)) {
            throw 'state.json has no recognized state fields. The file was left untouched.'
        }

        foreach ($n in @($arrayProps + @(
            'OriginalPowerScheme', 'CreatedPowerScheme',
            'HibernationWasEnabled', 'TrimWasDisabled',
            'MemoryCompressionWasEnabled', 'DefenderScanCpuLoad'
        ))) {
            if (-not $loaded.PSObject.Properties[$n]) {
                $default = $null
                if ($arrayProps -contains $n) { $default = @() }
                Add-Member -InputObject $loaded -MemberType NoteProperty -Name $n -Value $default
            }
        }

        foreach ($n in $arrayProps) {
            if ($null -eq $loaded.$n) { $loaded.$n = @() }
        }

        return $loaded
    }

    return (New-State)
}

function Save-State {
    if (-not $script:State) { $script:State = New-State }

    if ([string]::IsNullOrWhiteSpace($script:StatePath)) {
        throw "StatePath is not initialized."
    }

    if (-not (Test-Path -LiteralPath $script:StateDir)) {
        New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
    }

    $json = $script:State | ConvertTo-Json -Depth 8
    $tempPath = "$($script:StatePath).$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText($tempPath, $json, [System.Text.UTF8Encoding]::new($false))

        if (Test-Path -LiteralPath $script:StatePath) {
            # IMPORTANT: [NullString]::Value, not $null — PowerShell converts
            # $null to "" for [string] params, and File.Replace(..., "") throws
            # "The path is not of a legal form".
            [System.IO.File]::Replace($tempPath, $script:StatePath, [NullString]::Value)
        }
        else {
            Move-Item -LiteralPath $tempPath -Destination $script:StatePath -Force -ErrorAction Stop
        }
    }
    catch {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action,
        [scriptblock]$Verify
    )
    if ($Mode -eq 'WhatIf') {
        $script:WhatIfStepCount++
        $details = switch ($Name) {
            'Restore point' { 'Create a Windows restore point; this is a system-side effect and is not removed by script rollback.' }
            'Telemetry' { 'Change telemetry policies, selected services and scheduled tasks; supported changes are recorded for rollback.' }
            'Power plan' { 'Create/select an Ultimate Performance plan and adjust AC core parking; plan settings depend on device support.' }
            'Network' { 'Change the multimedia network throttling registry setting; no latency benefit is guaranteed.' }
            'Memory Integrity' { 'Disable HVCI, removing a kernel security protection; restart required.' }
            'Paging file' { 'Replace the system-managed pagefile configuration with a fixed size if safety checks pass; restart required.' }
            'Defender tuning' { 'Change Defender scan CPU limit and add only supplied exclusions; exclusions reduce scanning in those paths.' }
            'OneDrive' { 'Uninstall OneDrive; this script cannot restore the application.' }
            'App removal' { 'Remove selected Appx packages; this is not reversible by this script and may prompt for confirmation.' }
            'Runtimes (winget)' { 'Install selected runtime packages; installation is not reversible by this script.' }
            'Cleanup' { 'Delete temporary/update caches and run component-store cleanup; these operations are irreversible.' }
            'Disk maintenance' { 'Adjust TRIM/NTFS settings, enable the scheduled optimization task, and retrim detected SSD volumes.' }
            default { 'Run this module’s system-dependent checks and apply its documented settings; individual changes are not expanded in this preview.' }
        }
        Write-Host ('[WhatIf {0:D2}] {1} — {2}' -f $script:WhatIfStepCount, $Name, $details)
        return
    }

    Write-Log "=== $Name ==="
    $stepStateSnapshot = $null
    if ($Mode -eq 'Rollback' -and $script:State) {
        $stepStateSnapshot = $script:State | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    }

    $actionFailed = $false
    try {
        & $Action
    }
    catch {
        $actionFailed = $true
        if ($Mode -eq 'Rollback' -and $null -ne $stepStateSnapshot) {
            $script:State = $stepStateSnapshot
        }
        Write-Log "Step failed ($Name): $($_.Exception.Message)" 'ERROR'
    }

    if ($Mode -eq 'Apply') {
        $script:StepResults += [pscustomobject]@{ Step = $Name; Status = $(if ($actionFailed) { 'Failed' } else { 'OK' }) }
    }

    if ($Mode -eq 'Apply' -and -not $actionFailed -and $Verify) {
        try {
            $verified = & $Verify
            if ($verified) {
                Write-Log "Verified: $Name"
                $script:VerifyResults += [pscustomobject]@{ Step = $Name; Status = 'OK' }
            }
            else {
                Write-Log "Verification failed: $Name - the setting may not have been applied. Run -Mode Audit for details." 'WARN'
                $script:VerifyResults += [pscustomobject]@{ Step = $Name; Status = 'Failed' }
            }
        }
        catch {
            Write-Log "Verification check errored ($Name): $($_.Exception.Message)" 'WARN'
            $script:VerifyResults += [pscustomobject]@{ Step = $Name; Status = 'Error' }
        }
    }
}

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

function Backup-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('DWord', 'String', 'Binary', 'MultiString')][string]$Type
    )

    $known = @($script:State.Registry) | Where-Object { $_.Path -eq $Path -and $_.Name -eq $Name }
    if ($known) { return }

    $existed  = $false
    $original = $null

    if (Test-Path -LiteralPath $Path) {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties[$Name]) {
            $existed = $true
            $original = $item.$Name
        }
    }

    if ($Type -eq 'Binary' -and $existed -and $null -ne $original) {
        $original = [Convert]::ToBase64String([byte[]]$original)
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

function Set-RegistryValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord', 'String', 'MultiString')][string]$Type = 'DWord'
    )

    Backup-RegistryValue -Path $Path -Name $Name -Type $Type

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    if ($Type -eq 'DWord') {
        $unsignedValue = [long]$Value
        if ($unsignedValue -lt -2147483648 -or $unsignedValue -gt 4294967295) {
            throw "DWORD value is outside the valid 32-bit range: $Value"
        }
        if ($unsignedValue -lt 0) {
            $Value = [int]$unsignedValue
        }
        else {
            $Value = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$unsignedValue), 0)
        }
    }

    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Log "Registry set: $Path\$Name = $Value"
}

function Test-RegistryDwordValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][long]$Expected
    )

    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSObject.Properties[$Name]) { return $false }
    return ([long]($item.PSObject.Properties[$Name].Value) -eq $Expected)
}

function Test-RegistryStringValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Expected
    )

    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSObject.Properties[$Name]) { return $false }
    return ([string]($item.PSObject.Properties[$Name].Value) -eq $Expected)
}

function Restore-RegistryValues {
    $remaining = @()
    foreach ($e in @($script:State.Registry)) {
        try {
            if ($e.Existed) {
                if (-not (Test-Path -LiteralPath $e.Path)) {
                    New-Item -Path $e.Path -Force | Out-Null
                }

                $value = $e.Value

                if ($e.Type -eq 'Binary') {
                    if ($null -ne $value -and $value -is [string]) {
                        $value = [Convert]::FromBase64String($value)
                    }
                    else {
                        $value = [byte[]]@()
                    }
                }
                elseif ($e.Type -eq 'MultiString') {
                    $value = @($value)
                }

                New-ItemProperty -LiteralPath $e.Path -Name $e.Name -Value $value -PropertyType $e.Type -Force | Out-Null
                Write-Log "Registry restored: $($e.Path)\$($e.Name)"
            }
            else {
                if (Test-Path -LiteralPath $e.Path) {
                    $current = Get-ItemProperty -LiteralPath $e.Path -ErrorAction Stop
                    if ($current.PSObject.Properties[$e.Name]) {
                        Remove-ItemProperty -LiteralPath $e.Path -Name $e.Name -ErrorAction Stop
                        Write-Log "Registry value removed: $($e.Path)\$($e.Name)"
                    }
                }
            }
        }
        catch {
            Write-Log "Could not restore $($e.Path)\$($e.Name): $($_.Exception.Message)" 'WARN'
            $remaining += $e
        }
    }

    $script:State.Registry = @($remaining)
    Save-State
}

# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

function Disable-ServiceSafe {
    param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('Disabled', 'Manual')][string]$StartupType = 'Disabled'
    )

    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Log "Service not installed, skipping: $Name"
        return
    }

    if ($StartupType -eq 'Manual' -and [string]$svc.StartMode -eq 'Disabled') {
        Write-Log "Service already disabled, left as is: $Name"
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
            State     = [string]$svc.State
            Delayed   = $delayed
        }
        Save-State
    }

    if ($StartupType -eq 'Disabled' -and $svc.State -eq 'Running') {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    }

    Set-Service -Name $Name -StartupType $StartupType
    Write-Log "Service set to ${StartupType}: $Name"
}

function Restore-Services {
    $remaining = @()
    foreach ($s in @($script:State.Services)) {
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($s.Name)'" -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Log "Service not found during restore: $($s.Name)" 'WARN'
                $remaining += $s
                continue
            }

            if ($s.Delayed) {
                & sc.exe config $s.Name start= delayed-auto 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "Could not restore delayed-auto for $($s.Name)."
                }
            }
            else {
                $type = switch ($s.StartMode) {
                    'Auto'     { 'Automatic' }
                    'Manual'   { 'Manual' }
                    'Disabled' { 'Disabled' }
                    default    { 'Manual' }
                }

                Set-Service -Name $s.Name -StartupType $type -ErrorAction Stop
            }

            if ($s.PSObject.Properties['State']) {
                if ($s.State -eq 'Running' -and $svc.State -ne 'Running') {
                    Start-Service -Name $s.Name -ErrorAction Stop
                }
                elseif ($s.State -eq 'Stopped' -and $svc.State -ne 'Stopped') {
                    Stop-Service -Name $s.Name -Force -ErrorAction Stop
                }
            }
            elseif ($s.StartMode -eq 'Auto') {
                # Compatibility with older state files that did not save service state.
                Start-Service -Name $s.Name -ErrorAction SilentlyContinue
            }

            Write-Log "Service restored: $($s.Name) ($($s.StartMode))"
        }
        catch {
            Write-Log "Could not restore service $($s.Name): $($_.Exception.Message)" 'WARN'
            $remaining += $s
        }
    }

    $script:State.Services = @($remaining)
    Save-State
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

    & powercfg.exe /setacvalueindex $schemeGuid SUB_PROCESSOR CPMINCORES 100 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'powercfg could not disable AC core parking in the selected plan.' }
    & powercfg.exe /setactive $schemeGuid
    if ($LASTEXITCODE -ne 0) { throw 'powercfg /setactive failed.' }

    Write-Log "Power plan active: Ultimate Performance ($schemeGuid), core parking off on AC."
    Write-Log 'Note: on a laptop this raises heat and battery drain. Switch plans when unplugged.' 'WARN'
}

function Restore-PowerPlan {
    $orig = $script:State.OriginalPowerScheme
    if ($orig) {
        & powercfg.exe /setactive $orig 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Log 'Could not reactivate the original power plan; rollback data was retained.' 'WARN'
        }
        else {
            Write-Log "Power plan restored: $orig"
            $script:State.OriginalPowerScheme = $null
        }
    }
    else {
        $script:State.OriginalPowerScheme = $null
    }

    if ($script:State.CreatedPowerScheme) {
        & powercfg.exe /delete $script:State.CreatedPowerScheme 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log 'Ultimate Performance scheme created by this script was deleted.'
            $script:State.CreatedPowerScheme = $null
        }
        else {
            Write-Log 'Could not delete the Ultimate Performance scheme created by this script.' 'WARN'
        }
    }

    Save-State
}

$script:TelemetryTasks = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
    '\Microsoft\Windows\Feedback\Siuf\DmClient',
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
)

function Split-TaskPath {
    param([Parameter(Mandatory)][string]$FullPath)

    $idx = $FullPath.LastIndexOf('\')
    return [pscustomobject]@{
        Folder = $FullPath.Substring(0, $idx + 1)
        Name   = $FullPath.Substring($idx + 1)
    }
}

function Get-TaskTriggerTypeNames {
    param($Triggers)

    $names = @()
    foreach ($trigger in @($Triggers)) {
        if ($null -eq $trigger) { continue }

        $className = $null
        if ($trigger.PSObject.Properties['CimClass']) {
            $cimClass = $trigger.CimClass
            if ($null -ne $cimClass -and $cimClass.PSObject.Properties['CimClassName']) {
                $className = [string]$cimClass.CimClassName
            }
        }
        if (-not $className -and $trigger.PSObject.TypeNames.Count -gt 0) {
            # Fallback: 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskLogonTrigger'
            $typeName = [string]$trigger.PSObject.TypeNames[0]
            if ($typeName -match 'MSFT_Task\w+Trigger') { $className = $Matches[0] }
        }
        if ($className) { $names += $className }
    }
    return $names
}

function Disable-TaskSafe {
    param([Parameter(Mandatory)][string]$FullPath)

    $parts = Split-TaskPath -FullPath $FullPath
    $task = Get-ScheduledTask -TaskPath $parts.Folder -TaskName $parts.Name -ErrorAction SilentlyContinue
    if (-not $task) { return }

    $known = @($script:State.Tasks) | Where-Object { $_.Path -eq $FullPath }
    if (-not $known) {
        $script:State.Tasks = @($script:State.Tasks) + [pscustomobject]@{
            Path       = $FullPath
            WasEnabled = ($task.State -ne 'Disabled')
        }
        Save-State
    }

    Disable-ScheduledTask -TaskPath $parts.Folder -TaskName $parts.Name | Out-Null
    Write-Log "Scheduled task disabled: $FullPath"
}

function Restore-Tasks {
    $remaining = @()
    foreach ($t in @($script:State.Tasks)) {
        try {
            $parts = Split-TaskPath -FullPath $t.Path
            if ($t.WasEnabled) {
                Enable-ScheduledTask -TaskPath $parts.Folder -TaskName $parts.Name -ErrorAction Stop | Out-Null
                Write-Log "Scheduled task enabled again: $($t.Path)"
            }
            else {
                Disable-ScheduledTask -TaskPath $parts.Folder -TaskName $parts.Name -ErrorAction Stop | Out-Null
                Write-Log "Scheduled task set back to disabled: $($t.Path)"
            }
        }
        catch {
            Write-Log "Could not restore task $($t.Path): $($_.Exception.Message)" 'WARN'
            $remaining += $t
        }
    }

    $script:State.Tasks = @($remaining)
    Save-State
}

function Restore-Defender {
    if ($null -ne $script:State.DefenderScanCpuLoad) {
        try {
            Set-MpPreference -ScanAvgCPULoadFactor ([int]$script:State.DefenderScanCpuLoad)
            Write-Log "Defender scan CPU limit restored: $($script:State.DefenderScanCpuLoad)"
            $script:State.DefenderScanCpuLoad = $null
        }
        catch {
            Write-Log "Could not restore Defender scan CPU limit: $($_.Exception.Message)" 'WARN'
        }
    }

    $remaining = @()
    foreach ($path in @($script:State.DefenderExclusions)) {
        try {
            Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
            Write-Log "Defender exclusion removed: $path"
        }
        catch {
            Write-Log "Could not remove Defender exclusion $path`: $($_.Exception.Message)" 'WARN'
            $remaining += $path
        }
    }

    $script:State.DefenderExclusions = @($remaining)
    Save-State
}

function Enable-TaskSafe {
    param([Parameter(Mandatory)][string]$FullPath)

    $parts = Split-TaskPath -FullPath $FullPath
    $task = Get-ScheduledTask -TaskPath $parts.Folder -TaskName $parts.Name -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Log "Scheduled task not found: $FullPath" 'WARN'
        return
    }

    if ($task.State -ne 'Disabled') {
        Write-Log "Scheduled task already enabled: $FullPath"
        return
    }

    $known = @($script:State.Tasks) | Where-Object { $_.Path -eq $FullPath }
    if (-not $known) {
        $script:State.Tasks = @($script:State.Tasks) + [pscustomobject]@{ Path = $FullPath; WasEnabled = $false }
        Save-State
    }

    Enable-ScheduledTask -TaskPath $parts.Folder -TaskName $parts.Name | Out-Null
    Write-Log "Scheduled task enabled: $FullPath"
}

function Restore-Trim {
    if ($script:State.TrimWasDisabled -eq $true) {
        & fsutil.exe behavior set DisableDeleteNotify NTFS 1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log 'TRIM notifications set back to disabled (original state).'
            $script:State.TrimWasDisabled = $null
        }
        else {
            Write-Log 'Could not restore the TRIM setting.' 'WARN'
        }
    }
    else {
        $script:State.TrimWasDisabled = $null
    }
    Save-State
}

function Set-AcPowerSetting {
    param(
        [Parameter(Mandatory)][string]$SubGroup,
        [Parameter(Mandatory)][string]$Setting,
        [Parameter(Mandatory)][int]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    $active = (& powercfg.exe /getactivescheme) -join ' '
    $m = [regex]::Match($active, $script:GuidPattern)
    if (-not $m.Success) { throw 'Could not read the active power plan.' }
    $scheme = $m.Value

    $query = (& powercfg.exe /query $scheme $SubGroup $Setting 2>$null) -join "`n"
    $queryExit = $LASTEXITCODE
    $hex = @([regex]::Matches($query, '0x[0-9a-fA-F]{8}'))

    if ($queryExit -ne 0 -or $hex.Count -lt 2) {
        Write-Log "$Label is not available on this device. Skipped."
        return
    }

    $originalAc = [int][Convert]::ToInt64($hex[$hex.Count - 2].Value.Substring(2), 16)

    $known = @($script:State.PowerSettings) | Where-Object { $_.Scheme -eq $scheme -and $_.Setting -eq $Setting }
    if (-not $known) {
        $script:State.PowerSettings = @($script:State.PowerSettings) + [pscustomobject]@{
            Scheme     = $scheme
            SubGroup   = $SubGroup
            Setting    = $Setting
            OriginalAc = $originalAc
        }
        Save-State
    }

    & powercfg.exe /setacvalueindex $scheme $SubGroup $Setting $Value
    if ($LASTEXITCODE -ne 0) { throw "powercfg could not set: $Label" }

    & powercfg.exe /setactive $scheme
    if ($LASTEXITCODE -ne 0) { throw "powercfg could not refresh the active plan after setting: $Label" }
    Write-Log "Power setting (on AC): $Label = $Value (was $originalAc)"
}

function Restore-PowerSettings {
    $originalSettings = @($script:State.PowerSettings)
    $remaining = @()
    foreach ($ps in @($script:State.PowerSettings)) {
        try {
            & powercfg.exe /setacvalueindex $ps.Scheme $ps.SubGroup $ps.Setting ([int]$ps.OriginalAc) 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Power setting restored: $($ps.Setting) = $($ps.OriginalAc)"
            }
            else {
                Write-Log "Could not restore power setting $($ps.Setting) in plan $($ps.Scheme)." 'WARN'
                $remaining += $ps
            }
        }
        catch {
            Write-Log "Could not restore power setting $($ps.Setting): $($_.Exception.Message)" 'WARN'
            $remaining += $ps
        }
    }

    $active = (& powercfg.exe /getactivescheme) -join ' '
    $m = [regex]::Match($active, $script:GuidPattern)
    if ($m.Success) {
        & powercfg.exe /setactive $m.Value
        if ($LASTEXITCODE -ne 0) {
            Write-Log 'Could not refresh the active power plan after restoring settings.' 'WARN'
            $remaining = $originalSettings
        }
    }
    else {
        Write-Log 'Could not identify the active power plan after restoring settings.' 'WARN'
        $remaining = $originalSettings
    }

    $script:State.PowerSettings = @($remaining)
    Save-State
}

function Restore-MemoryCompression {
    if ($script:State.MemoryCompressionWasEnabled -eq $true) {
        Enable-MMAgent -MemoryCompression
        Write-Log 'Memory compression enabled again (restart needed).'
    }

    $script:State.MemoryCompressionWasEnabled = $null
    Save-State
}

function Restore-Hibernation {
    if ($script:State.HibernationWasEnabled -eq $true) {
        & powercfg.exe /hibernate on
        if ($LASTEXITCODE -eq 0) {
            Write-Log 'Hibernation turned back on.'
            $script:State.HibernationWasEnabled = $null
        }
        else {
            Write-Log 'Could not turn hibernation back on.' 'WARN'
        }
    }
    else {
        $script:State.HibernationWasEnabled = $null
    }
    Save-State
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

    try {
        Clear-FolderContents -Path (Join-Path $env:SystemRoot 'SoftwareDistribution\Download')
    }
    finally {
        foreach ($n in $wasRunning) {
            try {
                Start-Service -Name $n -ErrorAction Stop
            }
            catch {
                Write-Log "Could not restart service $n after cache cleanup: $($_.Exception.Message)" 'WARN'
            }
        }
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
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Value 1
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0
    Disable-ServiceSafe -Name 'DiagTrack'
    Disable-ServiceSafe -Name 'dmwappushservice'

    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1
    $sys = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    Set-RegistryValue -Path $sys -Name 'EnableActivityFeed' -Value 0
    Set-RegistryValue -Path $sys -Name 'PublishUserActivities' -Value 0
    Set-RegistryValue -Path $sys -Name 'UploadUserActivities' -Value 0

    foreach ($task in $script:TelemetryTasks) {
        Disable-TaskSafe -FullPath $task
    }
}

function Optimize-BackgroundApps {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsRunInBackground' -Value 2
}

function Optimize-GameDvr {
    Set-RegistryValue -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Value 0
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'UseNexusForGameBarEnabled' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'ShowStartupPanel' -Value 0
}

function Initialize-UiNative {
    if ('WinOptimize.UiNative' -as [type]) { return }
    Add-Type -Namespace WinOptimize -Name UiNative -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct ANIMATIONINFO
{
    public uint cbSize;
    public int iMinAnimate;
}

[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, System.IntPtr pvParam, uint fWinIni);

[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, EntryPoint = "SystemParametersInfo")]
public static extern bool SystemParametersInfoAnim(uint uiAction, uint uiParam, ref ANIMATIONINFO pvParam, uint fWinIni);
'@
}

$script:SpiFlags = 3

function Set-UiFlag {
    param(
        [Parameter(Mandatory)][uint32]$Action,
        [Parameter(Mandatory)][string]$Label
    )

    if ([WinOptimize.UiNative]::SystemParametersInfo($Action, 0, [IntPtr]::Zero, $script:SpiFlags)) {
        Write-Log "UI effect off: $Label"
    }
    else {
        Write-Log "Could not change UI effect: $Label" 'WARN'
    }
}

function Optimize-VisualEffects {
    Backup-RegistryValue -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary
    Backup-RegistryValue -Path 'HKCU:\Control Panel\Desktop' -Name 'DragFullWindows' -Type String
    Backup-RegistryValue -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name 'MinAnimate' -Type String

    Initialize-UiNative

    Set-UiFlag -Action 0x1003 -Label 'menu animation'
    Set-UiFlag -Action 0x1013 -Label 'menu fade'
    Set-UiFlag -Action 0x1005 -Label 'combo box animation'
    Set-UiFlag -Action 0x1007 -Label 'list box smooth scrolling'
    Set-UiFlag -Action 0x1015 -Label 'selection fade'
    Set-UiFlag -Action 0x1017 -Label 'tooltip animation'
    Set-UiFlag -Action 0x1019 -Label 'tooltip fade'
    Set-UiFlag -Action 0x101B -Label 'shadow under mouse pointer'
    Set-UiFlag -Action 0x1025 -Label 'drop shadows'
    Set-UiFlag -Action 0x1043 -Label 'client area animation'

    $anim = New-Object WinOptimize.UiNative+ANIMATIONINFO
    $anim.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($anim)
    $anim.iMinAnimate = 0
    if ([WinOptimize.UiNative]::SystemParametersInfoAnim(0x0049, $anim.cbSize, [ref]$anim, $script:SpiFlags)) {
        Write-Log 'UI effect off: window minimize/maximize animation'
    }
    else {
        Write-Log 'Could not change window animation.' 'WARN'
    }

    if ([WinOptimize.UiNative]::SystemParametersInfo(0x0025, 0, [IntPtr]::Zero, $script:SpiFlags)) {
        Write-Log 'UI effect off: show window contents while dragging'
    }
    else {
        Write-Log 'Could not change window dragging mode.' 'WARN'
    }

    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAnimations' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewAlphaSelect' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewShadow' -Value 0

    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Value 0
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableAcrylicBackgroundOnLogon' -Value 1
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 3

    Write-Log 'Visual effects reduced. Sign out and back in for everything to apply.'
}

function Optimize-TaskbarLayout {
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAl' -Value 0
    Write-Log 'Taskbar layout changed. Sign out and back in to apply.'
}

function Disable-AccessibilityHotkey {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][int]$DefaultFlags
    )

    $flags = $DefaultFlags
    if (Test-Path -LiteralPath $Path) {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties['Flags']) {
            $parsed = 0
            if ([int]::TryParse([string]$item.Flags, [ref]$parsed)) { $flags = $parsed }
        }
    }

    $newFlags = $flags -band (-bnot 0x04)
    Set-RegistryValue -Path $Path -Name 'Flags' -Value ([string]$newFlags) -Type String
}

function Optimize-Accessibility {
    Disable-AccessibilityHotkey -Path 'HKCU:\Control Panel\Accessibility\StickyKeys'       -DefaultFlags 510
    Disable-AccessibilityHotkey -Path 'HKCU:\Control Panel\Accessibility\Keyboard Response' -DefaultFlags 126
    Disable-AccessibilityHotkey -Path 'HKCU:\Control Panel\Accessibility\ToggleKeys'       -DefaultFlags 62
    Write-Log 'Accessibility shortcut popups disabled. Sign out and back in to apply.'
}

function Optimize-Suggestions {
    $cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
    $names = @(
        'SubscribedContent-310093Enabled',
        'SubscribedContent-338387Enabled',
        'SubscribedContent-338388Enabled',
        'SubscribedContent-338389Enabled',
        'SubscribedContent-338393Enabled',
        'SubscribedContent-353694Enabled',
        'SubscribedContent-353696Enabled',
        'SoftLandingEnabled',
        'SystemPaneSuggestionsEnabled',
        'SilentInstalledAppsEnabled',
        'OemPreInstalledAppsEnabled',
        'PreInstalledAppsEnabled',
        'PreInstalledAppsEverEnabled'
    )

    foreach ($n in $names) {
        Set-RegistryValue -Path $cdm -Name $n -Value 0
    }

    $adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-RegistryValue -Path $adv -Name 'ShowSyncProviderNotifications' -Value 0
    Set-RegistryValue -Path $adv -Name 'Start_IrisRecommendations' -Value 0
    Set-RegistryValue -Path $adv -Name 'Start_AccountNotifications' -Value 0

    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1
    Set-RegistryValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'DisableSearchBoxSuggestions' -Value 1
}

function Optimize-Notifications {
    Set-RegistryValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotification' -Value 1
    Set-RegistryValue -Path 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Value 1
    Write-Log 'All toast notifications are off, including Windows Security alerts. Sign out to apply.' 'WARN'
}

function Optimize-Interface {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -Name 'AllowNewsAndInterests' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Clipboard' -Name 'EnableClipboardHistory' -Value 0
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowCrossDeviceClipboard' -Value 0
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Name 'StartupDelayInMSec' -Value 0
}

function Optimize-SystemServices {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Value 0
    Disable-ServiceSafe -Name 'RemoteRegistry'
}

function Optimize-Hibernation {
    if ($null -eq $script:State.HibernationWasEnabled) {
        $p = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled' -ErrorAction SilentlyContinue
        if ($p -and $p.PSObject.Properties['HibernateEnabled']) {
            $script:State.HibernationWasEnabled = ($p.HibernateEnabled -eq 1)
            Save-State
        }
    }

    & powercfg.exe /hibernate off
    if ($LASTEXITCODE -ne 0) { throw 'powercfg /hibernate off failed.' }
    Write-Log 'Hibernation and Fast Startup are off; hiberfil.sys removed.'
}

# BEGIN APPLISTS
$script:BloatDefault = @(
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.GetHelp',
    'Microsoft.Getstarted',
    'Microsoft.WindowsFeedbackHub',
    'Microsoft.People',
    'Microsoft.Wallet',
    'Microsoft.MixedReality.Portal',
    'Microsoft.MSPaint',
    'Microsoft.Microsoft3DViewer',
    'Microsoft.Print3D',
    'Microsoft.SkypeApp',
    'MicrosoftTeams',
    'MicrosoftCorporationII.QuickAssist',
    'Microsoft.BingNews',
    'Microsoft.MicrosoftOfficeHub',
    'Microsoft.549981C3F5F10',
    'king.com.*',
    'SpotifyAB.SpotifyMusic',
    'Disney.37853FC22B2CE',
    'BytedancePte.Ltd.TikTok',
    'Facebook.Facebook',
    'Facebook.InstagramBeta',
    '9E2F88E3.Twitter',
    '4DF9E0F8.Netflix',
    'AmazonVideo.PrimeVideo',
    'Flipboard.Flipboard',
    '*Kindle*',
    '*Zillow*',
    '*Duolingo*',
    '*AdobePhotoshopExpress*',
    '*Hulu*'
)

$script:BloatXbox = @(
    'Microsoft.GamingApp',
    'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxSpeechToTextOverlay'
)

$script:ProtectedApps = @(
    'Microsoft.WindowsCalculator',
    'Microsoft.WindowsNotepad',
    'Microsoft.Paint',
    'Microsoft.ScreenSketch',
    'Microsoft.WindowsStore',
    'Microsoft.StorePurchaseApp',
    'Microsoft.SecHealthUI',
    'Microsoft.DesktopAppInstaller',
    'Microsoft.WindowsTerminal*',
    'Microsoft.XboxIdentityProvider',
    'Microsoft.GamingServices',
    'Microsoft.Xbox.TCUI',
    'MSTeams',
    '*VCLibs*',
    '*NET.Native*',
    '*UI.Xaml*',
    '*WindowsAppRuntime*',
    '*Extension*'
)
# END APPLISTS

function Test-AppSelected {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Patterns
    )

    foreach ($protected in $script:ProtectedApps) {
        if ($Name -like $protected) { return $false }
    }

    foreach ($keep in @($script:KeepApps)) {
        if ($keep -and $Name -like "*$keep*") { return $false }
    }

    foreach ($pattern in $Patterns) {
        if ($Name -like $pattern) { return $true }
    }

    return $false
}

function Optimize-AppRemoval {
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Write-Log 'App removal needs Windows PowerShell 5.1 (powershell.exe, not pwsh). Skipping.' 'WARN'
        return
    }

    $patterns = @($script:BloatDefault)
    if ($RemoveXboxApps) { $patterns += $script:BloatXbox }

    $installed = @(Get-AppxPackage -AllUsers | Where-Object {
        (Test-AppSelected -Name $_.Name -Patterns $patterns) -and
        (-not $_.IsFramework) -and
        (-not ($_.PSObject.Properties['NonRemovable'] -and $_.NonRemovable))
    })

    $provisioned = @(Get-AppxProvisionedPackage -Online | Where-Object {
        Test-AppSelected -Name $_.DisplayName -Patterns $patterns
    })

    $names = @()
    $names += @($installed | ForEach-Object { $_.Name })
    $names += @($provisioned | ForEach-Object { $_.DisplayName })
    $names = @($names | Sort-Object -Unique)

    if ($names.Count -eq 0) {
        Write-Log 'No removable apps from the list were found.'
        return
    }

    Write-Log "Apps selected for removal ($($names.Count)):"
    foreach ($n in $names) { Write-Log "  $n" }

    if (-not $Yes) {
        $answer = Read-Host 'Remove these apps? This cannot be undone by the script. Type Y to continue'
        if ($answer -notmatch '^[Yy]') {
            Write-Log 'App removal cancelled by the user.'
            return
        }
    }

    $removedLog = Join-Path $script:StateDir 'removed-apps.txt'
    foreach ($pkg in $installed) {
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            Add-Content -LiteralPath $removedLog -Value ('{0} installed {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $pkg.Name)
            Write-Log "Removed app: $($pkg.Name)"
        }
        catch {
            Write-Log "Could not remove $($pkg.Name): $($_.Exception.Message)" 'WARN'
        }
    }

    foreach ($prov in $provisioned) {
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
            Add-Content -LiteralPath $removedLog -Value ('{0} provisioned {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $prov.DisplayName)
            Write-Log "Removed provisioned package: $($prov.DisplayName)"
        }
        catch {
            Write-Log "Could not remove provisioned $($prov.DisplayName): $($_.Exception.Message)" 'WARN'
        }
    }

    Write-Log "Removed app names are listed in $removedLog. Reinstall any of them from the Microsoft Store."
}

function Optimize-Edge {
    $edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    Set-RegistryValue -Path $edge -Name 'StartupBoostEnabled' -Value 0
    Set-RegistryValue -Path $edge -Name 'BackgroundModeEnabled' -Value 0
    Set-RegistryValue -Path $edge -Name 'DefaultBrowserSettingEnabled' -Value 0
    Set-RegistryValue -Path $edge -Name 'HubsSidebarEnabled' -Value 0
}

function Remove-OneDriveClient {
    foreach ($folder in @('Desktop', 'MyDocuments', 'MyPictures')) {
        $path = [Environment]::GetFolderPath($folder)
        if ($path -like '*OneDrive*') {
            Write-Log "$folder is stored in OneDrive ($path). OneDrive was NOT removed." 'WARN'
            Write-Log 'Move your folders back to the local disk first (OneDrive settings > Backup), then run again.' 'WARN'
            return
        }
    }

    Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    $setup = Join-Path $env:SystemRoot 'SysWOW64\OneDriveSetup.exe'
    if (-not (Test-Path -LiteralPath $setup)) {
        $setup = Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe'
    }

    if (-not (Test-Path -LiteralPath $setup)) {
        Write-Log 'OneDriveSetup.exe not found. OneDrive may already be removed.' 'WARN'
        return
    }

    $proc = Start-Process -FilePath $setup -ArgumentList '/uninstall' -Wait -PassThru
    if ($proc.ExitCode -eq 0) {
        Write-Log 'OneDrive client uninstalled. To get it back: winget install Microsoft.OneDrive'
    }
    else {
        Write-Log "OneDrive uninstaller returned exit code $($proc.ExitCode)." 'WARN'
    }
}

function Optimize-Defender {
    if (-not (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Log 'Microsoft Defender cmdlets are not available (another antivirus may be active). Skipping.' 'WARN'
        return
    }

    $pref = Get-MpPreference

    if ($null -eq $script:State.DefenderScanCpuLoad) {
        $script:State.DefenderScanCpuLoad = [int]$pref.ScanAvgCPULoadFactor
        Save-State
    }

    Set-MpPreference -ScanAvgCPULoadFactor 20
    Write-Log 'Defender scans limited to about 20% average CPU. Real-time protection is untouched.'

    foreach ($path in @($script:DefenderExcludePathsClean)) {
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Log "Exclusion path does not exist, skipped: $path" 'WARN'
            continue
        }

        if (@($pref.ExclusionPath) -contains $path) {
            Write-Log "Already excluded, left as is: $path"
            continue
        }

        $script:State.DefenderExclusions = @($script:State.DefenderExclusions) + $path
        Save-State
        Add-MpPreference -ExclusionPath $path -ErrorAction Stop
        Write-Log "Defender exclusion added: $path (files there are no longer scanned; use only for trusted folders)" 'WARN'
    }
}

function Optimize-Trim {
    $out = (& fsutil.exe behavior query DisableDeleteNotify) -join "`n"
    $m = [regex]::Match($out, 'NTFS\s+DisableDeleteNotify\s*=\s*(\d)')
    if (-not $m.Success) { $m = [regex]::Match($out, 'DisableDeleteNotify\s*=\s*(\d)') }

    if (-not $m.Success) {
        Write-Log 'Could not read the TRIM setting. Left unchanged.' 'WARN'
        return
    }

    if ($m.Groups[1].Value -eq '0') {
        Write-Log 'TRIM is already enabled.'
        return
    }

    $script:State.TrimWasDisabled = $true
    Save-State

    & fsutil.exe behavior set DisableDeleteNotify NTFS 0 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        & fsutil.exe behavior set DisableDeleteNotify 0 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'fsutil could not enable TRIM.' }
    }

    Write-Log 'TRIM was disabled and is now enabled.'
}

function Optimize-LastAccess {
    Backup-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisableLastAccessUpdate' -Type DWord
    & fsutil.exe behavior set disablelastaccess 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'fsutil disablelastaccess failed.' }
    Write-Log 'NTFS last access time updates disabled (restart needed for full effect).'
}

function Invoke-SsdRetrim {
    $volumes = @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and ([string]$_.DriveLetter) -match '^[A-Za-z]$' })
    foreach ($vol in $volumes) {
        $letter = [string]$vol.DriveLetter
        $media = $null
        try {
            $media = (Get-Partition -DriveLetter $letter | Get-Disk | Get-PhysicalDisk).MediaType
        }
        catch {
            Write-Log "Could not detect drive type for ${letter}:" 'WARN'
        }

        if ("$media" -eq 'SSD') {
            try {
                Optimize-Volume -DriveLetter $letter -ReTrim -ErrorAction Stop
                Write-Log "ReTrim finished on ${letter}: (SSD)"
            }
            catch {
                Write-Log "ReTrim failed on ${letter}: $($_.Exception.Message)" 'WARN'
            }
        }
        else {
            Write-Log "Skipped ${letter}: (drive type: $media)"
        }
    }
}

function Optimize-Disk {
    Optimize-Trim
    Optimize-LastAccess
    Enable-TaskSafe -FullPath '\Microsoft\Windows\Defrag\ScheduledDefrag'
    Invoke-SsdRetrim
}

function Optimize-Network {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value 0xFFFFFFFF
}

function Optimize-EthernetPower {
    $classPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e10b-11ce-bfc1-08002be10318}'
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { [string]$_.PhysicalMediaType -eq '802.3' })
    if ($adapters.Count -eq 0) {
        Write-Log 'No physical Ethernet adapter found. Adapter power saving left unchanged.'
        return
    }

    foreach ($adapter in $adapters) {
        $guid = [string]$adapter.InterfaceGuid
        foreach ($key in @(Get-ChildItem -LiteralPath $classPath -ErrorAction SilentlyContinue)) {
            if ($key.PSChildName -notmatch '^\d{4}$') { continue }
            $keyPath = Join-Path $classPath $key.PSChildName
            $props = Get-ItemProperty -LiteralPath $keyPath -ErrorAction SilentlyContinue
            if ($props -and $props.PSObject.Properties['NetCfgInstanceId'] -and [string]$props.NetCfgInstanceId -eq $guid) {
                Set-RegistryValue -Path $keyPath -Name 'PnPCapabilities' -Value 24
                Write-Log "Ethernet adapter power saving off: $($adapter.Name) (restart needed)"
            }
        }
    }
}

function Optimize-DevicePower {
    Set-AcPowerSetting -SubGroup '2a737441-1930-4402-8d77-b2bebba308a3' -Setting '48e6b7a6-50f5-4782-a5d4-53bb8f07e226' -Value 0 -Label 'USB selective suspend'
    Set-AcPowerSetting -SubGroup '501a4d13-42af-4429-9fd1-a8218c268e20' -Setting 'ee12f906-d277-404b-b6da-e5fa1a576df5' -Value 0 -Label 'PCIe link state power management'
    Optimize-EthernetPower
}

function Optimize-UpdaterServices {
    foreach ($name in @('gupdate', 'gupdatem', 'edgeupdate', 'edgeupdatem', 'AdobeARMservice')) {
        Disable-ServiceSafe -Name $name -StartupType Manual
    }

    Disable-ServiceSafe -Name 'NvTelemetryContainer'
}

function Optimize-SysMain {
    $letter = $env:SystemDrive.TrimEnd(':')
    $media = $null
    try {
        $media = (Get-Partition -DriveLetter $letter | Get-Disk | Get-PhysicalDisk).MediaType
    }
    catch {
        Write-Log 'Could not detect the system drive type.' 'WARN'
    }

    if ("$media" -ne 'SSD') {
        Write-Log "System drive is not detected as an SSD (type: $media). SysMain left on." 'WARN'
        return
    }

    Disable-ServiceSafe -Name 'SysMain'
}

function Optimize-MemoryCompression {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (-not $cs -or -not $cs.TotalPhysicalMemory) {
        Write-Log 'Could not detect RAM. Memory compression left unchanged.' 'WARN'
        return
    }

    $ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

    if ($ramGb -lt 16) {
        Write-Log "This PC has $ramGb GB RAM. Memory compression left on (it helps on less than 16 GB)." 'WARN'
        return
    }

    $mm = Get-MMAgent -ErrorAction SilentlyContinue
    if (-not $mm) {
        Write-Log 'MMAgent is not available. Memory compression left unchanged.' 'WARN'
        return
    }

    if (-not $mm.MemoryCompression) {
        Write-Log 'Memory compression is already off.'
        return
    }

    if ($null -eq $script:State.MemoryCompressionWasEnabled) {
        $script:State.MemoryCompressionWasEnabled = $true
        Save-State
    }

    Disable-MMAgent -MemoryCompression
    Write-Log 'Memory compression disabled (restart needed).'
}

function Get-RegistryValueOrNull {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )

    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($item -and $item.PSObject.Properties[$Name]) { return $item.$Name }
    return $null
}

function Write-ReportLine {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Value
    )
    try {
        $text = & $Value
        Write-Log ('{0}: {1}' -f $Label, $text)
    }
    catch {
        Write-Log ('{0}: unavailable' -f $Label)
    }
}

function Show-SystemReport {
    Write-Log '=== System report (read only, nothing is changed) ==='
    Write-ReportLine 'OS' { $o = Get-CimInstance -ClassName Win32_OperatingSystem; "$($o.Caption), build $($o.BuildNumber)" }
    Write-ReportLine 'CPU' { (Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1).Name }
    Write-ReportLine 'RAM' { "$([math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)) GB" }
    Write-ReportLine 'GPU' { (Get-CimInstance -ClassName Win32_VideoController | ForEach-Object { "$($_.Name) (driver $($_.DriverVersion))" }) -join '; ' }
    Write-ReportLine 'RAM modules' {
        $m = @(Get-CimInstance -ClassName Win32_PhysicalMemory)
        $list = ($m | ForEach-Object { "$([math]::Round($_.Capacity / 1GB)) GB @ $($_.ConfiguredClockSpeed) MT/s" }) -join ', '
        $hint = ''
        if ($m.Count -eq 1) { $hint = '   (one module detected; channel mode and performance impact are not confirmed)' }
        "$($m.Count) module(s): $list$hint"
    }
    Write-ReportLine 'Display mode' {
        (Get-CimInstance -ClassName Win32_VideoController | Where-Object { $_.CurrentRefreshRate } | ForEach-Object {
            "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution) @ $($_.CurrentRefreshRate) Hz ($($_.Name))"
        }) -join '; '
    }
    Write-ReportLine 'Power source' {
        $b = @(Get-CimInstance -ClassName Win32_Battery)
        if ($b.Count -eq 0) { 'no battery (desktop)' }
        elseif (@(1, 4, 5) -contains [int]$b[0].BatteryStatus) { 'ON BATTERY - plug in for full performance' }
        else { 'plugged in (AC)' }
    }
    Write-ReportLine 'GPU interrupt mode (MSI)' {
        $g = @(Get-DiscreteGpuDevices)
        if ($g.Count -eq 0) { 'no discrete NVIDIA/AMD GPU found' }
        else {
            ($g | ForEach-Object {
                $v = Get-RegistryValueOrNull -Path (Get-GpuMsiPath -Device $_) -Name 'MSISupported'
                $state = 'MSI not set'
                if ($v -eq 1) { $state = 'MSI on' }
                "$($_.FriendlyName): $state"
            }) -join '; '
        }
    }
    Write-ReportLine 'Startup programs' {
        (Get-CimInstance -ClassName Win32_StartupCommand | ForEach-Object { $_.Name }) -join ', '
    }
    Write-ReportLine 'Top memory users' {
        (Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 8 | ForEach-Object {
            "$($_.ProcessName) $([math]::Round($_.WorkingSet64 / 1MB)) MB"
        }) -join ', '
    }
    Write-ReportLine 'Disks' { (Get-PhysicalDisk | ForEach-Object { "$($_.FriendlyName) [$($_.MediaType), $($_.BusType)]" }) -join '; ' }
    Write-ReportLine 'Paging file setup' {
        $v = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles'
        if ($null -eq $v) { 'unknown' } else { (@($v) -join ' | ') + '   (?: = system managed)' }
    }
    Write-ReportLine 'Paging file in use' {
        (Get-CimInstance -ClassName Win32_PageFileUsage | ForEach-Object { "$($_.Name) $($_.AllocatedBaseSize) MB" }) -join '; '
    }
    Write-ReportLine 'Power plan' { (& powercfg.exe /getactivescheme) -join ' ' }
    Write-ReportLine 'GPU scheduling (HAGS)' {
        $v = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode'
        if ($v -eq 2) { 'on' } elseif ($v -eq 1) { 'off' } else { 'not set / not supported' }
    }
    Write-ReportLine 'Game Mode' {
        $v = Get-RegistryValueOrNull -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled'
        if ($v -eq 1) { 'on' } elseif ($v -eq 0) { 'off' } else { 'default (on)' }
    }
    Write-ReportLine 'Memory integrity (HVCI)' {
        $v = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
        if ($v -eq 1) { 'on' } elseif ($v -eq 0) { 'off' } else { 'not configured' }
    }
    Write-ReportLine 'Hibernation' {
        $v = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'
        if ($v -eq 1) { 'on' } elseif ($v -eq 0) { 'off' } else { 'unknown' }
    }
    Write-ReportLine 'TRIM (DisableDeleteNotify)' {
        $out = (& fsutil.exe behavior query DisableDeleteNotify) -join ' '
        $m = [regex]::Match($out, 'DisableDeleteNotify\s*=\s*(\d)')
        if ($m.Success -and $m.Groups[1].Value -eq '0') { 'TRIM enabled' } elseif ($m.Success) { 'TRIM disabled' } else { 'unknown' }
    }

    foreach ($name in @('DiagTrack', 'SysMain', 'WSearch')) {
        Write-ReportLine "Service $name" {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
            "$($svc.StartMode), $($svc.State)"
        }
    }

    Write-ReportLine 'winget' { (& winget.exe --version) -join ' ' }
    Write-Log "Report finished. Run '.\optimize.ps1 -Mode Report' before and after to compare."
}

function Invoke-AuditProbe {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Probe
    )

    try {
        & $Probe
    }
    catch {
        $script:AuditCollectionErrors.Add(('{0}: {1}' -f $Name, $_.Exception.Message))
    }
}

function Get-AuditPowerSetting {
    param(
        [Parameter(Mandatory)][string]$Scheme,
        [Parameter(Mandatory)][string]$SubGroup,
        [Parameter(Mandatory)][string]$Setting,
        [Parameter(Mandatory)][string]$Name
    )

    $query = (& powercfg.exe /query $Scheme $SubGroup $Setting 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "powercfg could not query '$Name'."
    }

    $acMatch = [regex]::Match($query, '(?im)Current\s+AC\s+Power\s+Setting\s+Index\s*:\s*(0x[0-9a-fA-F]{8})')
    $dcMatch = [regex]::Match($query, '(?im)Current\s+DC\s+Power\s+Setting\s+Index\s*:\s*(0x[0-9a-fA-F]{8})')
    if ($acMatch.Success -and $dcMatch.Success) {
        $acHex = $acMatch.Groups[1].Value
        $dcHex = $dcMatch.Groups[1].Value
        $parseMethod = 'Labeled AC/DC indexes'
    }
    else {
        $hexValues = @([regex]::Matches($query, '0x[0-9a-fA-F]{8}') | ForEach-Object { $_.Value })
        if ($hexValues.Count -lt 2) {
            throw "Could not parse AC/DC indexes for '$Name'."
        }
        $acHex = $hexValues[$hexValues.Count - 2]
        $dcHex = $hexValues[$hexValues.Count - 1]
        $parseMethod = 'Last two hexadecimal values; output labels may be localized'
    }

    return [pscustomobject]@{
        Name = $Name
        SubGroupGuid = $SubGroup
        SettingGuid = $Setting
        ParseMethod = $parseMethod
        AcIndex = [long][Convert]::ToInt64($acHex.Substring(2), 16)
        AcIndexHex = $acHex
        DcIndex = [long][Convert]::ToInt64($dcHex.Substring(2), 16)
        DcIndexHex = $dcHex
    }
}

function Get-SystemAuditSnapshot {
    $script:AuditCollectionErrors = New-Object 'System.Collections.Generic.List[string]'

    $computer = Invoke-AuditProbe -Name 'Computer system' -Probe {
        Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -First 1
    }
    $os = Invoke-AuditProbe -Name 'Operating system' -Probe {
        Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -First 1
    }
    $processors = @(Invoke-AuditProbe -Name 'CPU' -Probe {
        Get-CimInstance -ClassName Win32_Processor
    })
    $videoControllers = @(Invoke-AuditProbe -Name 'GPU' -Probe {
        Get-CimInstance -ClassName Win32_VideoController
    })
    $gpuPreferences = @(Invoke-AuditProbe -Name 'Per-application GPU preferences' -Probe {
        $path = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
        if (Test-Path -LiteralPath $path) {
            $properties = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            foreach ($property in $properties.PSObject.Properties) {
                if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                    [pscustomobject]@{
                        ExecutablePath = $property.Name
                        Preference = [string]$property.Value
                    }
                }
            }
        }
    })
    $memoryModules = @(Invoke-AuditProbe -Name 'Physical memory modules' -Probe {
        Get-CimInstance -ClassName Win32_PhysicalMemory
    })
    $memoryPerf = Invoke-AuditProbe -Name 'Memory performance counters' -Probe {
        Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Memory | Select-Object -First 1
    }
    $pagefileUsage = @(Invoke-AuditProbe -Name 'Pagefile usage' -Probe {
        Get-CimInstance -ClassName Win32_PageFileUsage
    })
    $physicalDisks = @(Invoke-AuditProbe -Name 'Physical disks' -Probe {
        Get-PhysicalDisk | Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size
    })
    $diskPerformance = @(Invoke-AuditProbe -Name 'Physical disk performance counters' -Probe {
        Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk |
            Where-Object { $_.Name -ne '_Total' } |
            Select-Object Name, PercentDiskTime, PercentIdleTime, CurrentDiskQueueLength,
                AvgDiskQueueLength, DiskReadBytesPersec, DiskWriteBytesPersec,
                DiskReadsPersec, DiskWritesPersec
    })
    $trimSettings = @(Invoke-AuditProbe -Name 'TRIM configuration' -Probe {
        $output = (& fsutil.exe behavior query DisableDeleteNotify 2>$null) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'fsutil could not query DisableDeleteNotify.' }

        $trimMatches = [regex]::Matches($output, '(?im)^\s*(NTFS|ReFS)\s+DisableDeleteNotify\s*=\s*(\d+)')
        if ($trimMatches.Count -eq 0) { throw 'Could not parse NTFS/ReFS DisableDeleteNotify values.' }

        foreach ($match in $trimMatches) {
            $disabled = [int]$match.Groups[2].Value
            [pscustomobject]@{
                FileSystem = $match.Groups[1].Value
                DisableDeleteNotify = $disabled
                TrimEnabled = ($disabled -eq 0)
            }
        }
    })
    $scheduledDiskMaintenance = Invoke-AuditProbe -Name 'Scheduled disk maintenance task' -Probe {
        $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop
        [pscustomobject]@{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State = [string]$task.State
            Enabled = $task.Settings.Enabled
        }
    }
    $volumes = @(Invoke-AuditProbe -Name 'Volumes' -Probe {
        Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } |
            Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, Size, SizeRemaining
    })
    $networkAdapters = @(Invoke-AuditProbe -Name 'Network adapters' -Probe {
        Get-NetAdapter -Physical | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MediaConnectionState, PhysicalMediaType
    })
    $wifiInfo = Invoke-AuditProbe -Name 'Wi-Fi diagnostics' -Probe {
        $wifiAdapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { [string]$_.PhysicalMediaType -match '802\.11' })

        $interfaces = @()
        if ($wifiAdapters.Count -gt 0) {
            # netsh output is localized; only SSID/BSSID labels and the percent value are stable across languages.
            $netshOutput = @(& netsh.exe wlan show interfaces 2>$null)
            if ($LASTEXITCODE -eq 0 -and $netshOutput.Count -gt 0) {
                $blocks = @()
                $currentBlock = @()
                foreach ($line in $netshOutput) {
                    if ([string]::IsNullOrWhiteSpace([string]$line)) {
                        if ($currentBlock.Count -gt 0) { $blocks += ,$currentBlock; $currentBlock = @() }
                    }
                    else {
                        $currentBlock += [string]$line
                    }
                }
                if ($currentBlock.Count -gt 0) { $blocks += ,$currentBlock }

                foreach ($block in $blocks) {
                    $ssid = $null
                    $bssid = $null
                    $signal = $null
                    foreach ($line in $block) {
                        if ($line -match '^\s*BSSID\s*:\s*(.+)$') { $bssid = $Matches[1].Trim() }
                        elseif ($line -match '^\s*SSID\s*:\s*(.+)$') { $ssid = $Matches[1].Trim() }
                        elseif ($null -eq $signal -and $line -match '(\d{1,3})\s*%') { $signal = [int]$Matches[1] }
                    }
                    if ($ssid -or $bssid -or $null -ne $signal) {
                        $interfaces += [pscustomobject]@{ Ssid = $ssid; Bssid = $bssid; SignalPercent = $signal }
                    }
                }
            }
        }

        [pscustomobject]@{
            Adapters = @($wifiAdapters | Select-Object Name, InterfaceDescription, Status, LinkSpeed)
            Interfaces = $interfaces
        }
    }
    $networkProfiles = @(Invoke-AuditProbe -Name 'Network profiles' -Probe {
        Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
    })
    $ipConfigurations = @(Invoke-AuditProbe -Name 'IP configurations' -Probe {
        Get-NetIPConfiguration -All -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                InterfaceAlias = $_.InterfaceAlias
                InterfaceIndex = $_.InterfaceIndex
                InterfaceDescription = $_.InterfaceDescription
                IPv4Addresses = @($_.IPv4Address | ForEach-Object {
                    [pscustomobject]@{ Address = $_.IPAddress; PrefixLength = $_.PrefixLength }
                })
                IPv6Addresses = @($_.IPv6Address | ForEach-Object {
                    [pscustomobject]@{ Address = $_.IPAddress; PrefixLength = $_.PrefixLength }
                })
                IPv4DefaultGateways = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
                IPv6DefaultGateways = @($_.IPv6DefaultGateway | ForEach-Object { $_.NextHop })
                DnsServerAddresses = @($_.DNSServer.ServerAddresses)
            }
        }
    })
    $pingTests = @()
    foreach ($target in $script:PingTargetsClean) {
        $roundTripTimes = @()
        $timeoutCount = 0
        $errorCount = 0
        $pingClient = New-Object System.Net.NetworkInformation.Ping
        try {
            for ($probeIndex = 0; $probeIndex -lt $PingCount; $probeIndex++) {
                try {
                    $reply = $pingClient.Send($target, 1500)
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $roundTripTimes += [double]$reply.RoundtripTime
                    }
                    elseif ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::TimedOut) {
                        $timeoutCount++
                    }
                    else {
                        $errorCount++
                    }
                }
                catch {
                    $errorCount++
                }
            }
        }
        finally {
            $pingClient.Dispose()
        }

        $jitterSamples = @()
        for ($sampleIndex = 1; $sampleIndex -lt $roundTripTimes.Count; $sampleIndex++) {
            $jitterSamples += [math]::Abs($roundTripTimes[$sampleIndex] - $roundTripTimes[$sampleIndex - 1])
        }

        $minimumMs = $null
        $averageMs = $null
        $maximumMs = $null
        $jitterMs = $null
        if ($roundTripTimes.Count -gt 0) {
            $statistics = $roundTripTimes | Measure-Object -Minimum -Average -Maximum
            $minimumMs = [math]::Round($statistics.Minimum, 2)
            $averageMs = [math]::Round($statistics.Average, 2)
            $maximumMs = [math]::Round($statistics.Maximum, 2)
        }
        if ($jitterSamples.Count -gt 0) {
            $jitterMs = [math]::Round((($jitterSamples | Measure-Object -Average).Average), 2)
        }

        $pingTests += [pscustomobject]@{
            Target = $target
            Method = 'ICMP Echo'
            ProbeTimeoutMs = 1500
            JitterMethod = 'Mean absolute difference between consecutive successful RTT samples'
            Sent = $PingCount
            Received = $roundTripTimes.Count
            Lost = $PingCount - $roundTripTimes.Count
            PacketLossPercent = [math]::Round((($PingCount - $roundTripTimes.Count) / [double]$PingCount) * 100, 1)
            Timeouts = $timeoutCount
            Errors = $errorCount
            MinimumMs = $minimumMs
            AverageMs = $averageMs
            MaximumMs = $maximumMs
            JitterMs = $jitterMs
            RoundTripTimesMs = @($roundTripTimes)
        }
    }
    $startup = @(Invoke-AuditProbe -Name 'Startup commands' -Probe {
        Get-CimInstance -ClassName Win32_StartupCommand |
            Select-Object Name, Command, Location, User
    })
    $startupRegistryPaths = @(
        [pscustomobject]@{ Scope = 'CurrentUser'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' }
        [pscustomobject]@{ Scope = 'CurrentUser'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' }
        [pscustomobject]@{ Scope = 'LocalMachine'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' }
        [pscustomobject]@{ Scope = 'LocalMachine'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
        [pscustomobject]@{ Scope = 'LocalMachine32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' }
        [pscustomobject]@{ Scope = 'LocalMachine32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' }
    )
    $startupRegistryEntries = @()
    foreach ($startupPath in $startupRegistryPaths) {
        $entries = Invoke-AuditProbe -Name ("Startup registry {0}" -f $startupPath.Path) -Probe {
            if (Test-Path -LiteralPath $startupPath.Path) {
                $properties = Get-ItemProperty -LiteralPath $startupPath.Path -ErrorAction Stop
                foreach ($property in $properties.PSObject.Properties) {
                    if ($property.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                        [pscustomobject]@{
                            Name = $property.Name
                            Command = [string]$property.Value
                            Scope = $startupPath.Scope
                            RegistryPath = $startupPath.Path
                        }
                    }
                }
            }
        }
        $startupRegistryEntries += @($entries)
    }

    $startupDirectories = @(
        [pscustomobject]@{
            Scope = 'CurrentUser'
            Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)
        }
        [pscustomobject]@{
            Scope = 'AllUsers'
            Path = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
        }
    )
    $startupFolderEntries = @()
    foreach ($startupDirectory in $startupDirectories) {
        $entries = Invoke-AuditProbe -Name ("Startup folder {0}" -f $startupDirectory.Scope) -Probe {
            if ($startupDirectory.Path -and (Test-Path -LiteralPath $startupDirectory.Path)) {
                Get-ChildItem -LiteralPath $startupDirectory.Path -Force -ErrorAction Stop |
                    Select-Object @{Name = 'Scope'; Expression = { $startupDirectory.Scope }},
                        Name, FullName, Extension, Length, LastWriteTime
            }
        }
        $startupFolderEntries += @($entries)
    }

    $startupTasks = @(Invoke-AuditProbe -Name 'Logon and boot scheduled tasks' -Probe {
        $startupTriggerTypes = @('MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger', 'MSFT_TaskRegistrationTrigger')
        Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $triggerTypes = Get-TaskTriggerTypeNames -Triggers $_.Triggers
            @($triggerTypes | Where-Object { $startupTriggerTypes -contains $_ }).Count -gt 0
        } | ForEach-Object {
            [pscustomobject]@{
                TaskName = $_.TaskName
                TaskPath = $_.TaskPath
                State = [string]$_.State
                UserId = $_.Principal.UserId
                LogonType = [string]$_.Principal.LogonType
                Actions = @($_.Actions | ForEach-Object {
                    $action = $_
                    [pscustomobject]@{
                        Execute = $(if ($action.PSObject.Properties['Execute']) { [string]$action.Execute } else { $null })
                        Arguments = $(if ($action.PSObject.Properties['Arguments']) { [string]$action.Arguments } else { $null })
                        WorkingDirectory = $(if ($action.PSObject.Properties['WorkingDirectory']) { [string]$action.WorkingDirectory } else { $null })
                    }
                })
            }
        }
    })
    $processes = @(Invoke-AuditProbe -Name 'Top memory processes' -Probe {
        Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 10 |
            ForEach-Object {
                [pscustomobject]@{
                    Name               = $_.ProcessName
                    ProcessId          = $_.Id
                    WorkingSetMB       = [math]::Round($_.WorkingSet64 / 1MB, 1)
                    PrivateMemoryMB    = [math]::Round($_.PrivateMemorySize64 / 1MB, 1)
                }
            }
    })

    $serviceNames = @(
        'DiagTrack', 'SysMain', 'WSearch',
        'wuauserv', 'BITS', 'UsoSvc', 'DoSvc', 'WaaSMedicSvc', 'TrustedInstaller', 'CryptSvc',
        'Dhcp', 'Dnscache', 'NlaSvc', 'WlanSvc', 'Wcmsvc', 'LanmanWorkstation',
        'BFE', 'MpsSvc', 'WinDefend', 'SecurityHealthService', 'wscsvc',
        'GamingServices', 'GamingServicesNet', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc', 'XboxGipSvc',
        'lfsvc', 'WFDSConMgrSvc'
    )
    $services = @(Invoke-AuditProbe -Name 'Selected services' -Probe {
        Get-CimInstance -ClassName Win32_Service |
            Where-Object { $serviceNames -contains $_.Name } |
            ForEach-Object {
                $service = $_
                $serviceSettings = Get-ItemProperty `
                    -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" `
                    -ErrorAction SilentlyContinue
                $delayedAutoStart = $false
                if ($serviceSettings -and $serviceSettings.PSObject.Properties['DelayedAutostart']) {
                    $delayedAutoStart = ($serviceSettings.DelayedAutostart -eq 1)
                }
                [pscustomobject]@{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    State = $service.State
                    StartMode = $service.StartMode
                    DelayedAutoStart = $delayedAutoStart
                    ProcessId = $service.ProcessId
                    StartName = $service.StartName
                }
            }
    })

    $battery = @(Invoke-AuditProbe -Name 'Battery' -Probe {
        Get-CimInstance -ClassName Win32_Battery | Select-Object Name, BatteryStatus, EstimatedChargeRemaining
    })

    $pendingReboot = @()
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $pendingReboot += 'ComponentBasedServicing'
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $pendingReboot += 'WindowsUpdate'
    }
    $pendingFileRenames = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    if ($pendingFileRenames) { $pendingReboot += 'PendingFileRenameOperations' }

    $isAdministrator = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $script:AuditCollectionErrors.Add(('Administrator status: {0}' -f $_.Exception.Message))
    }

    $activePowerScheme = Invoke-AuditProbe -Name 'Active power scheme' -Probe {
        $result = (& powercfg.exe /getactivescheme 2>$null) -join ' '
        if ($LASTEXITCODE -ne 0) { throw 'powercfg /getactivescheme failed.' }
        $result
    }
    $powerSettings = @()
    $schemeMatch = [regex]::Match([string]$activePowerScheme, $script:GuidPattern)
    if ($schemeMatch.Success) {
        $powerSettingsToAudit = @(
            [pscustomobject]@{
                Name = 'Processor minimum state'
                SubGroup = '54533251-82be-4824-96c1-47b60b740d00'
                Setting = '893dee8e-2bef-41e0-89c6-b55d0929964c'
            }
            [pscustomobject]@{
                Name = 'Processor maximum state'
                SubGroup = '54533251-82be-4824-96c1-47b60b740d00'
                Setting = 'bc5038f7-23e0-4960-96da-33abaf5935ec'
            }
            [pscustomobject]@{
                Name = 'Processor boost mode'
                SubGroup = '54533251-82be-4824-96c1-47b60b740d00'
                Setting = 'be337238-0d82-4146-a960-4f3749d470c7'
            }
            [pscustomobject]@{
                Name = 'Core parking minimum cores'
                SubGroup = '54533251-82be-4824-96c1-47b60b740d00'
                Setting = '0cc5b647-c1df-4637-891a-dec35c318583'
            }
            [pscustomobject]@{
                Name = 'Core parking maximum cores'
                SubGroup = '54533251-82be-4824-96c1-47b60b740d00'
                Setting = 'ea062031-0e34-4ff1-9b6d-eb1059334028'
            }
            [pscustomobject]@{
                Name = 'PCIe link state power management'
                SubGroup = '501a4d13-42af-4429-9fd1-a8218c268e20'
                Setting = 'ee12f906-d277-404b-b6da-e5fa1a576df5'
            }
            [pscustomobject]@{
                Name = 'USB selective suspend'
                SubGroup = '2a737441-1930-4402-8d77-b2bebba308a3'
                Setting = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'
            }
        )
        foreach ($powerSetting in $powerSettingsToAudit) {
            $record = Invoke-AuditProbe -Name ("Power setting: {0}" -f $powerSetting.Name) -Probe {
                Get-AuditPowerSetting -Scheme $schemeMatch.Value `
                    -SubGroup $powerSetting.SubGroup `
                    -Setting $powerSetting.Setting `
                    -Name $powerSetting.Name
            }
            if ($record) { $powerSettings += $record }
        }
    }
    else {
        $script:AuditCollectionErrors.Add('Power settings: active power scheme GUID was unavailable.')
    }
    $pagefileConfiguration = Get-RegistryValueOrNull `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
        -Name 'PagingFiles'

    $registry = [pscustomobject]@{
        HAGS = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode'
        GameMode = Get-RegistryValueOrNull -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled'
        GameModeAllowed = Get-RegistryValueOrNull -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AllowAutoGameMode'
        GameDVR = Get-RegistryValueOrNull -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled'
        GameDVRAppCapture = Get-RegistryValueOrNull -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled'
        SystemResponsiveness = Get-RegistryValueOrNull -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'SystemResponsiveness'
        MouseSpeed = Get-RegistryValueOrNull -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed'
        MouseThreshold1 = Get-RegistryValueOrNull -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1'
        MouseThreshold2 = Get-RegistryValueOrNull -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2'
        MemoryIntegrity = Get-RegistryValueOrNull -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
    }

    $osRecord = $null
    if ($os) {
        $osRecord = [pscustomobject]@{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            Architecture = $os.OSArchitecture
            WindowsDirectory = $os.WindowsDirectory
            SystemDrive = $os.SystemDrive
            LastBootTime = $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString('o') } else { $null })
            FreePhysicalMemoryMB = $(if ($os.FreePhysicalMemory) { [math]::Round($os.FreePhysicalMemory / 1024, 1) } else { $null })
            TotalVisibleMemoryMB = $(if ($os.TotalVisibleMemorySize) { [math]::Round($os.TotalVisibleMemorySize / 1024, 1) } else { $null })
        }
    }

    $cpuRecords = @($processors | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            Manufacturer = $_.Manufacturer
            Architecture = $_.Architecture
            Cores = $_.NumberOfCores
            LogicalProcessors = $_.NumberOfLogicalProcessors
            CurrentClockMHz = $_.CurrentClockSpeed
            MaxClockMHz = $_.MaxClockSpeed
            LoadPercent = $_.LoadPercentage
        }
    })
    $gpuRecords = @($videoControllers | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            DriverVersion = $_.DriverVersion
            DriverDate = $_.DriverDate
            VideoProcessor = $_.VideoProcessor
            AdapterMemoryMB = $(if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM / 1MB, 1) } else { $null })
            CurrentRefreshRateHz = $_.CurrentRefreshRate
        }
    })

    $thermalZonesSupported = $true
    $thermalZones = @()
    try {
        $thermalZones = @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSAcpi_ThermalZoneTemperature' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.InstanceName
                TemperatureCelsius = [math]::Round(([double]$_.CurrentTemperature / 10) - 273.15, 1)
            }
        })
    }
    catch {
        # Absent on many desktops/boards; this is expected, not a collection error.
        $thermalZonesSupported = $false
    }

    $cpuClockRatios = @($cpuRecords | ForEach-Object {
        if ($_.MaxClockMHz -and $_.CurrentClockMHz) {
            [pscustomobject]@{
                Name = $_.Name
                CurrentToMaxClockRatio = [math]::Round($_.CurrentClockMHz / [double]$_.MaxClockMHz, 2)
            }
        }
    })

    $thermalRecord = [pscustomobject]@{
        ThermalZonesSupported = $thermalZonesSupported
        ThermalZones = $thermalZones
        CpuClockRatios = $cpuClockRatios
        Notes = @(
            'CPU clock below maximum at idle is normal power saving, not throttling; throttle detection requires measurement under load.',
            'GPU temperature is not exposed through WMI and is not collected.'
        )
    }

    $memoryRecord = [pscustomobject]@{
        InstalledPhysicalMB = $(if ($computer -and $computer.TotalPhysicalMemory) { [math]::Round($computer.TotalPhysicalMemory / 1MB, 1) } else { $null })
        FreePhysicalMB = $(if ($os -and $os.FreePhysicalMemory) { [math]::Round($os.FreePhysicalMemory / 1024, 1) } else { $null })
        CommittedBytes = $(if ($memoryPerf) { $memoryPerf.CommittedBytes } else { $null })
        CommitLimitBytes = $(if ($memoryPerf) { $memoryPerf.CommitLimit } else { $null })
        Modules = @($memoryModules | ForEach-Object {
            [pscustomobject]@{
                CapacityMB = [math]::Round($_.Capacity / 1MB, 1)
                ConfiguredSpeedMHz = $_.ConfiguredClockSpeed
                RatedSpeedMHz = $_.Speed
                Manufacturer = $_.Manufacturer
                PartNumber = $_.PartNumber
            }
        })
        PagefileConfiguration = @($pagefileConfiguration)
        PagefileUsage = @($pagefileUsage | ForEach-Object {
            [pscustomobject]@{ Name = $_.Name; AllocatedMB = $_.AllocatedBaseSize; CurrentUsageMB = $_.CurrentUsage; PeakUsageMB = $_.PeakUsage }
        })
        TopProcesses = $processes
    }

    $snapshot = [pscustomobject]@{
        SchemaVersion = 11
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Machine = [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Manufacturer = $(if ($computer) { $computer.Manufacturer } else { $null })
            Model = $(if ($computer) { $computer.Model } else { $null })
            IsAdministrator = $isAdministrator
        }
        OS = $osRecord
        CPU = $cpuRecords
        GPU = [pscustomobject]@{
            Devices = $gpuRecords
            HighPerformanceApplications = $gpuPreferences
        }
        RAM = $memoryRecord
        Disk = [pscustomobject]@{
            PhysicalDisks = $physicalDisks
            PerformanceCounters = $diskPerformance
            Volumes = $volumes
            TrimSettings = $trimSettings
            ScheduledMaintenance = $scheduledDiskMaintenance
        }
        Network = [pscustomobject]@{
            Adapters = $networkAdapters
            Profiles = $networkProfiles
            IPConfigurations = $ipConfigurations
            PingTests = $pingTests
            WiFi = $wifiInfo
        }
        Services = $services
        Registry = $registry
        Thermals = $thermalRecord
        Power = [pscustomobject]@{ ActiveScheme = $activePowerScheme; Batteries = $battery; Settings = $powerSettings }
        Startup = [pscustomobject]@{
            Commands = $startup
            RegistryEntries = $startupRegistryEntries
            FolderEntries = $startupFolderEntries
            ScheduledTasks = $startupTasks
        }
        PendingRebootReasons = $pendingReboot
        Findings = @()
        Recommendations = @()
        AppliedChanges = @()
        RollbackInfo = [pscustomobject]@{ StateFileExists = (Test-Path -LiteralPath $script:StatePath) }
        ComparisonResults = $null
        RuleEvaluatorStatus = 'Populated after rule evaluation; see EvaluatedRuleIds.'
        MeasurementLimitations = @(
            'Physical mouse/keyboard-to-display input latency is not measured.',
            'Thermal zone temperatures appear only when the firmware exposes them via ACPI; they are often unavailable on desktops.',
            'GPU temperature is not collected: it is not exposed through WMI.',
            'Wi-Fi interface details come from netsh output; only SSID/BSSID and signal percent are reliable across display languages.',
            'Low CPU clock at idle is power saving, not throttling; throttling can only be judged from clocks under load.',
            'ICMP probes run only for explicitly supplied PingTargets; ICMP loss does not prove game-server packet loss.',
            'Disk performance counters are a momentary sample; queue length or active time alone does not establish a disk fault.'
        )
        CollectionErrors = @($script:AuditCollectionErrors.ToArray())
    }

    return $snapshot
}

function Invoke-RuleEvaluator {
    param([Parameter(Mandatory)]$Snapshot)

    $findings = @()
    $recommendations = @()

    $rebootReasons = @($Snapshot.PendingRebootReasons | Where-Object { $_ })
    if ($rebootReasons.Count -gt 0) {
        $findings += [pscustomobject]@{
            Id = 'SYS-REBOOT-MARKER'
            Name = 'Restart marker detected'
            Description = 'Windows contains one or more known indicators that a restart may be required.'
            ConditionsMatched = @('At least one recognized reboot marker was present during the audit.')
            Evidence = [pscustomobject]@{ Markers = $rebootReasons }
            Severity = 'Informational'
            Confidence = 'High for marker presence; this does not prove that a restart is currently required.'
            PotentialImpact = 'Some pending servicing or file operations may not complete until restart.'
            AllowedActions = @('Save work and review Windows Update/servicing status; restart at a convenient time if appropriate.')
            Risk = 'Low; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Run Audit again after a normal restart and check whether these markers remain.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-SYS-RESTART'
            FindingId = 'SYS-REBOOT-MARKER'
            Description = 'Review Windows Update status and consider a normal restart after saving work.'
            Automatic = $false
        }
    }

    $cpuLoadSamples = @($Snapshot.CPU | Where-Object { $null -ne $_.LoadPercent })
    $highLoadProcessors = @($cpuLoadSamples | Where-Object { [double]$_.LoadPercent -ge 90 })
    if ($highLoadProcessors.Count -gt 0) {
        $highestCpuLoad = ($cpuLoadSamples | Measure-Object -Property LoadPercent -Maximum).Maximum
        $findings += [pscustomobject]@{
            Id = 'CPU-HIGH-LOAD-SAMPLE'
            Name = 'High CPU load observed in one sample'
            Description = 'One or more processor packages reported at least 90% load during this audit snapshot. A single sample does not establish sustained saturation, throttling, or its cause.'
            ConditionsMatched = @('At least one Win32_Processor.LoadPercentage value is >= 90.')
            Evidence = [pscustomobject]@{
                Source = 'Win32_Processor.LoadPercentage'
                MaximumLoadPercent = [int]$highestCpuLoad
                ProcessorSamples = @($cpuLoadSamples | ForEach-Object {
                    [pscustomobject]@{ Name = $_.Name; LoadPercent = $_.LoadPercent; CurrentClockMHz = $_.CurrentClockMHz; MaxClockMHz = $_.MaxClockMHz }
                })
            }
            Severity = 'Informational'
            Confidence = 'High for the reported WMI sample; low for persistent load or any inferred cause.'
            PotentialImpact = 'If this load persists during a slowdown, it may reduce CPU time available to other work.'
            AllowedActions = @('Repeat Audit while the slowdown is occurring and inspect Task Manager for the processes using CPU.')
            Risk = 'Low; observation only.'
            Rollback = 'Not applicable; audit does not change CPU settings or terminate processes.'
            Verification = 'Compare multiple samples taken during the same workload; do not diagnose throttling from load alone.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-CPU-HIGH-LOAD-SAMPLE'
            FindingId = 'CPU-HIGH-LOAD-SAMPLE'
            Description = 'Repeat the audit during the reported slowdown; this sample alone does not identify a cause.'
            Automatic = $false
        }
    }

    $pingTimeouts = @($Snapshot.Network.PingTests | Where-Object { [int]$_.Timeouts -gt 0 })
    $pingRuleIndex = 0
    foreach ($ping in $pingTimeouts) {
        $pingRuleIndex++
        $findingId = 'NET-ICMP-TIMEOUT-{0:D2}' -f $pingRuleIndex
        $findings += [pscustomobject]@{
            Id = $findingId
            Name = 'ICMP probes timed out'
            Description = 'One or more ICMP echo probes received no reply before timeout. Firewalls, routers or the target may filter ICMP; this does not prove packet loss for game traffic.'
            ConditionsMatched = @('At least one explicitly requested ICMP probe timed out.')
            Evidence = [pscustomobject]@{
                Target = $ping.Target
                Sent = $ping.Sent
                Received = $ping.Received
                Timeouts = $ping.Timeouts
                Errors = $ping.Errors
                NoReplyPercent = $ping.PacketLossPercent
                MinimumMs = $ping.MinimumMs
                AverageMs = $ping.AverageMs
                MaximumMs = $ping.MaximumMs
                JitterMs = $ping.JitterMs
            }
            Severity = 'Informational'
            Confidence = 'High that ICMP probes timed out; low for locating the cause or inferring application traffic loss.'
            PotentialImpact = 'The target did not answer all ICMP probes; user-visible impact is not established.'
            AllowedActions = @('Compare repeated probes to the local gateway and a known remote target; check whether the target or network filters ICMP.')
            Risk = 'Low; informational only.'
            Rollback = 'Not applicable; ping probes do not change system settings.'
            Verification = 'Repeat the same ICMP probes under comparable network conditions and compare timeout counts.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-{0}' -f $findingId
            FindingId = $findingId
            Description = 'Compare gateway and remote-target results; do not treat ICMP timeouts alone as proof of game packet loss.'
            Automatic = $false
        }
    }

    $totalPhysicalMb = [double]$Snapshot.RAM.InstalledPhysicalMB
    $freePhysicalMb = [double]$Snapshot.RAM.FreePhysicalMB
    $committedBytes = [double]$Snapshot.RAM.CommittedBytes
    $commitLimitBytes = [double]$Snapshot.RAM.CommitLimitBytes
    if ($totalPhysicalMb -gt 0 -and $commitLimitBytes -gt 0 -and $committedBytes -ge 0 -and $freePhysicalMb -ge 0) {
        $commitPercent = ($committedBytes / $commitLimitBytes) * 100
        $freePhysicalPercent = ($freePhysicalMb / $totalPhysicalMb) * 100
        if ($commitPercent -ge 90 -and $freePhysicalPercent -le 10) {
            $findingId = 'RAM-MEMORY-PRESSURE'
            $findings += [pscustomobject]@{
                Id = $findingId
                Name = 'Possible memory pressure'
                Description = 'This audit snapshot shows committed memory near its limit and little free physical memory. A single sample does not establish a persistent problem or memory leak.'
                ConditionsMatched = @('CommittedBytes / CommitLimitBytes >= 90% AND FreePhysicalMB / InstalledPhysicalMB <= 10%.')
                Evidence = [pscustomobject]@{
                    CommittedBytes = [long]$committedBytes
                    CommitLimitBytes = [long]$commitLimitBytes
                    CommitPercent = [math]::Round($commitPercent, 1)
                    FreePhysicalMB = [math]::Round($freePhysicalMb, 1)
                    InstalledPhysicalMB = [math]::Round($totalPhysicalMb, 1)
                    FreePhysicalPercent = [math]::Round($freePhysicalPercent, 1)
                    TopProcesses = @($Snapshot.RAM.TopProcesses)
                }
                Severity = 'Moderate'
                Confidence = 'High for the sampled counters; low for any specific cause without repeated measurements.'
                PotentialImpact = 'Applications may experience memory allocation failures or increased paging if pressure persists.'
                AllowedActions = @('Review the listed processes and workload; save work before closing applications. Keep the pagefile system-managed unless separate evidence supports a change.')
                Risk = 'Low for observation; no process is terminated and no memory setting is changed.'
                Rollback = 'Not applicable; audit does not change memory settings.'
                Verification = 'Repeat Audit under comparable workload; look for sustained high commit usage and low free memory before diagnosing a persistent issue.'
            }
            $recommendations += [pscustomobject]@{
                Id = 'REC-{0}' -f $findingId
                FindingId = $findingId
                Description = 'Check whether high memory use persists; do not infer a leak from this one snapshot or disable the paging file.'
                Automatic = $false
            }
        }
    }

    foreach ($volume in @($Snapshot.Disk.Volumes)) {
        if ($null -eq $volume.Size -or $null -eq $volume.SizeRemaining -or [double]$volume.Size -le 0) {
            continue
        }

        $freePercent = ([double]$volume.SizeRemaining / [double]$volume.Size) * 100
        $freeBytes = [double]$volume.SizeRemaining
        if ($freeBytes -ge 10GB -and $freePercent -ge 10) {
            continue
        }

        $volumeLabel = if ($volume.DriveLetter) { '{0}:' -f $volume.DriveLetter } else { [string]$volume.FileSystemLabel }
        $findingId = 'DISK-LOW-FREE-SPACE-{0}' -f ($volumeLabel -replace '[^A-Za-z0-9_-]', '_')
        $findings += [pscustomobject]@{
            Id = $findingId
            Name = 'Low free space'
            Description = 'The measured free space is below the audit heuristic threshold (10 GB or 10% of volume capacity). This is a capacity warning, not proof of a performance fault.'
            ConditionsMatched = @('Free bytes < 10 GB OR free percentage < 10%.')
            Evidence = [pscustomobject]@{
                Volume = $volumeLabel
                FileSystemLabel = $volume.FileSystemLabel
                FreeBytes = [long]$volume.SizeRemaining
                CapacityBytes = [long]$volume.Size
                FreePercent = [math]::Round($freePercent, 1)
            }
            Severity = 'Moderate'
            Confidence = 'High for the reported capacity measurement; performance impact is not inferred.'
            PotentialImpact = 'Updates, temporary work and applications may lack required free space.'
            AllowedActions = @('Manually review storage usage and remove only files you recognize and no longer need.')
            Risk = 'Low for review; deletion is irreversible and is not performed by this rule.'
            Rollback = 'Not applicable; audit does not delete files.'
            Verification = 'Run Audit again and compare the same volume’s free bytes under similar conditions.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-{0}' -f $findingId
            FindingId = $findingId
            Description = 'Review Windows Settings > System > Storage; do not blindly delete Windows Update or system folders.'
            Automatic = $false
        }
    }

    foreach ($disk in @($Snapshot.Disk.PhysicalDisks)) {
        $health = [string]$disk.HealthStatus
        if ($health -notmatch '^(Warning|Unhealthy)$') {
            continue
        }

        $findingId = 'DISK-HEALTH-{0}' -f ([string]$disk.FriendlyName -replace '[^A-Za-z0-9_-]', '_')
        $findings += [pscustomobject]@{
            Id = $findingId
            Name = 'Disk health warning reported by Windows'
            Description = 'The storage provider reports a warning or unhealthy status. This is a hardware-health indicator, not a direct performance measurement.'
            ConditionsMatched = @('PhysicalDisk.HealthStatus is Warning or Unhealthy.')
            Evidence = [pscustomobject]@{
                FriendlyName = $disk.FriendlyName
                HealthStatus = $health
                OperationalStatus = @($disk.OperationalStatus)
                BusType = $disk.BusType
                MediaType = $disk.MediaType
            }
            Severity = 'High'
            Confidence = 'High that Windows reported this health status; cause requires vendor diagnostics.'
            PotentialImpact = 'Possible reliability or data-integrity risk; performance impact is not inferred.'
            AllowedActions = @('Back up important data and inspect vendor diagnostics/SMART before considering repair or replacement.')
            Risk = 'Low for inspection; avoid repair commands until a backup exists.'
            Rollback = 'Not applicable; audit does not modify disks.'
            Verification = 'Recheck with the drive manufacturer’s diagnostic utility and a later Audit.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-{0}' -f $findingId
            FindingId = $findingId
            Description = 'Back up important files and verify the disk using its manufacturer’s diagnostic tools.'
            Automatic = $false
        }
    }

    $solidStateDisks = @($Snapshot.Disk.PhysicalDisks | Where-Object { [string]$_.MediaType -eq 'SSD' })
    if ($solidStateDisks.Count -gt 0) {
        foreach ($trim in @($Snapshot.Disk.TrimSettings | Where-Object { [int]$_.DisableDeleteNotify -eq 1 })) {
            $findingId = 'DISK-TRIM-DISABLED-{0}' -f ([string]$trim.FileSystem -replace '[^A-Za-z0-9_-]', '_')
            $findings += [pscustomobject]@{
                Id = $findingId
                Name = 'TRIM notifications are disabled for an SSD system'
                Description = 'Windows reports DisableDeleteNotify=1 and a physical disk reports SSD media. This indicates disabled delete notifications; performance impact depends on the storage path and device.'
                ConditionsMatched = @('At least one physical disk reports MediaType=SSD and this file system reports DisableDeleteNotify=1.')
                Evidence = [pscustomobject]@{
                    FileSystem = $trim.FileSystem
                    DisableDeleteNotify = $trim.DisableDeleteNotify
                    SolidStateDisks = @($solidStateDisks | ForEach-Object { $_.FriendlyName })
                }
                Severity = 'Moderate'
                Confidence = 'High for the reported setting and media type; downstream storage-controller behavior is not verified.'
                PotentialImpact = 'The storage device may not receive delete notifications needed for its own background space management.'
                AllowedActions = @('Verify support for the drive, RAID/controller and storage driver before considering a change.')
                Risk = 'Low for inspection; changing storage configuration is not performed automatically.'
                Rollback = 'Not applicable; audit does not change the setting.'
                Verification = 'Query DisableDeleteNotify again and confirm supported behavior with the device/controller vendor.'
            }
            $recommendations += [pscustomobject]@{
                Id = 'REC-{0}' -f $findingId
                FindingId = $findingId
                Description = 'Check the storage device and controller documentation before changing TRIM behavior.'
                Automatic = $false
            }
        }
    }

    # --- Power rules (AC indexes collected via powercfg /query) ---
    $powerSettingByName = @{}
    foreach ($powerSetting in @($Snapshot.Power.Settings | Where-Object { $_ })) {
        $powerSettingByName[[string]$powerSetting.Name] = $powerSetting
    }

    $pciAspmSetting = $powerSettingByName['PCIe link state power management']
    if ($pciAspmSetting -and $pciAspmSetting.AcIndex -ne 0) {
        $findings += [pscustomobject]@{
            Id = 'PWR-PCIE-ASPM-ENABLED'
            Name = 'PCIe link state power management enabled (AC)'
            Description = 'The active power plan allows PCIe links to enter power-saving states while on AC power.'
            ConditionsMatched = @('PCIe link state power management AC index is not 0 (Off).')
            Evidence = [pscustomobject]@{ Setting = $pciAspmSetting }
            Severity = 'Informational'
            Confidence = 'High for the setting value; the latency effect varies by device.'
            PotentialImpact = 'Link power states can add device wake latency on some hardware.'
            AllowedActions = @('Disable PCIe link state power management in the power plan (the Apply "Device power" step does this).')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit and check that the PCIe link state power management AC index is 0.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-PWR-PCIE-ASPM'
            FindingId = 'PWR-PCIE-ASPM-ENABLED'
            Description = 'Consider disabling PCIe ASPM in the active power plan when on AC power.'
            Automatic = $false
        }
    }

    $usbSuspendSetting = $powerSettingByName['USB selective suspend']
    if ($usbSuspendSetting -and $usbSuspendSetting.AcIndex -ne 0) {
        $findings += [pscustomobject]@{
            Id = 'PWR-USB-SELECTIVE-SUSPEND-ENABLED'
            Name = 'USB selective suspend enabled (AC)'
            Description = 'The active power plan allows USB devices to be suspended while on AC power.'
            ConditionsMatched = @('USB selective suspend AC index is not 0 (Disabled).')
            Evidence = [pscustomobject]@{ Setting = $usbSuspendSetting }
            Severity = 'Informational'
            Confidence = 'High for the setting value; whether input devices are affected depends on the device.'
            PotentialImpact = 'Suspended USB devices can add wake latency; some mice/keyboards behave better with it off.'
            AllowedActions = @('Disable USB selective suspend in the power plan (the Apply "Device power" step does this).')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit and check that the USB selective suspend AC index is 0.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-PWR-USB-SUSPEND'
            FindingId = 'PWR-USB-SELECTIVE-SUSPEND-ENABLED'
            Description = 'Consider disabling USB selective suspend when on AC power if input devices feel laggy.'
            Automatic = $false
        }
    }

    $boostSetting = $powerSettingByName['Processor boost mode']
    if ($boostSetting -and $boostSetting.AcIndex -eq 0) {
        $findings += [pscustomobject]@{
            Id = 'PWR-CPU-BOOST-DISABLED'
            Name = 'Processor boost mode disabled (AC)'
            Description = 'The active power plan disables CPU turbo/boost while on AC power.'
            ConditionsMatched = @('Processor boost mode AC index is 0 (Disabled).')
            Evidence = [pscustomobject]@{ Setting = $boostSetting }
            Severity = 'Informational'
            Confidence = 'High for the setting value; real frequency gain depends on cooling and firmware limits.'
            PotentialImpact = 'The CPU cannot exceed its base clock; burst performance is reduced.'
            AllowedActions = @('Set processor boost mode to Enabled or Aggressive in the active power plan if temperatures allow.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit and check that the processor boost mode AC index is not 0.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-PWR-CPU-BOOST'
            FindingId = 'PWR-CPU-BOOST-DISABLED'
            Description = 'Consider enabling processor boost mode on AC power.'
            Automatic = $false
        }
    }

    # --- Service rules ---
    $serviceRecords = @($Snapshot.Services | Where-Object { $_ })
    $diagTrackRunning = @($serviceRecords | Where-Object { $_.Name -eq 'DiagTrack' -and $_.State -eq 'Running' })
    if ($diagTrackRunning.Count -gt 0) {
        $findings += [pscustomobject]@{
            Id = 'SVC-DIAGTRACK-RUNNING'
            Name = 'DiagTrack service running'
            Description = 'The Connected User Experiences and Telemetry service is running.'
            ConditionsMatched = @('DiagTrack service state is Running.')
            Evidence = [pscustomobject]@{ Service = $diagTrackRunning[0] }
            Severity = 'Informational'
            Confidence = 'High for the service state.'
            PotentialImpact = 'The service performs telemetry collection; it consumes some background resources.'
            AllowedActions = @('Disable DiagTrack (the Apply "Telemetry" step does this, with rollback data).')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit and check that DiagTrack is not Running.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-SVC-DIAGTRACK'
            FindingId = 'SVC-DIAGTRACK-RUNNING'
            Description = 'Consider disabling DiagTrack if you do not use telemetry-dependent features.'
            Automatic = $false
        }
    }

    $sysMainRecord = @($serviceRecords | Where-Object { $_.Name -eq 'SysMain' }) | Select-Object -First 1
    $ssdPresent = @($Snapshot.Disk.PhysicalDisks | Where-Object { $_ -and [string]$_.MediaType -eq 'SSD' }).Count -gt 0
    if ($sysMainRecord -and $ssdPresent -and [string]$sysMainRecord.StartMode -eq 'Auto') {
        $findings += [pscustomobject]@{
            Id = 'SVC-SYSMAIN-SSD'
            Name = 'SysMain active with SSD present'
            Description = 'SysMain (prefetch/superfetch) is set to automatic while the machine has an SSD.'
            ConditionsMatched = @('SysMain StartMode is Auto.', 'At least one physical disk reports MediaType SSD.')
            Evidence = [pscustomobject]@{ Service = $sysMainRecord; SsdPresent = $ssdPresent }
            Severity = 'Informational'
            Confidence = 'High for the facts; the benefit or harm of SysMain on SSDs is debated and hardware-specific.'
            PotentialImpact = 'On some systems SysMain causes background disk/CPU activity; on others it is harmless.'
            AllowedActions = @('Test with SysMain disabled (Apply -DisableSysMain) and keep it only if no regressions appear.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit after changing the service and compare its StartMode.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-SVC-SYSMAIN'
            FindingId = 'SVC-SYSMAIN-SSD'
            Description = 'Optionally test disabling SysMain on this SSD system; re-enable if anything regresses.'
            Automatic = $false
        }
    }

    # --- Startup rule ---
    $startupRegistryCount = @($Snapshot.Startup.RegistryEntries | Where-Object { $_ }).Count
    $startupFolderCount = @($Snapshot.Startup.FolderEntries | Where-Object { $_ -and [string]$_.Name -notmatch '(?i)\.disabled$' }).Count
    $startupTotal = $startupRegistryCount + $startupFolderCount
    if ($startupTotal -gt 10) {
        $findings += [pscustomobject]@{
            Id = 'STARTUP-COUNT-HIGH'
            Name = 'Many startup entries'
            Description = 'The number of registry and startup-folder entries is above a review threshold.'
            ConditionsMatched = @("Registry and startup-folder entries total $startupTotal (threshold: 10).")
            Evidence = [pscustomobject]@{ RegistryEntries = $startupRegistryCount; FolderEntries = $startupFolderCount }
            Severity = 'Informational'
            Confidence = 'High for the count; the impact of each entry varies.'
            PotentialImpact = 'Many startup entries lengthen sign-in time and add background processes.'
            AllowedActions = @('Review the list with -Mode Startup and disable entries you do not need.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit after trimming and compare the entry count.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-STARTUP-REVIEW'
            FindingId = 'STARTUP-COUNT-HIGH'
            Description = 'Review startup entries with -Mode Startup and disable unneeded ones.'
            Automatic = $false
        }
    }

    # --- GPU / security rules ---
    $gpuDeviceCount = @($Snapshot.GPU.Devices | Where-Object { $_ }).Count
    $gpuPreferenceCount = @($Snapshot.GPU.HighPerformanceApplications | Where-Object { $_ }).Count
    if ($gpuDeviceCount -gt 1 -and $gpuPreferenceCount -eq 0) {
        $findings += [pscustomobject]@{
            Id = 'GPU-NO-HIGH-PERF-APPS'
            Name = 'Multiple GPUs but no per-app GPU preference'
            Description = 'More than one display adapter is present, but no application is pinned to the high-performance GPU.'
            ConditionsMatched = @("$gpuDeviceCount display adapters detected.", 'HKCU DirectX UserGpuPreferences has no entries.')
            Evidence = [pscustomobject]@{ GpuCount = $gpuDeviceCount }
            Severity = 'Informational'
            Confidence = 'High for the facts; which GPU runs a game depends on the driver and game launcher.'
            PotentialImpact = 'Games may run on the power-saving GPU on hybrid-graphics systems.'
            AllowedActions = @('Pin latency-sensitive games to the high-performance GPU via -GpuHighPerformanceApps or Windows graphics settings.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit and check that HighPerformanceApplications is not empty.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-GPU-HIGH-PERF'
            FindingId = 'GPU-NO-HIGH-PERF-APPS'
            Description = 'Set per-application GPU preferences for your games on this multi-GPU system.'
            Automatic = $false
        }
    }

    if ($null -ne $Snapshot.Registry.MemoryIntegrity -and [int]$Snapshot.Registry.MemoryIntegrity -eq 1) {
        $findings += [pscustomobject]@{
            Id = 'SEC-HVCI-ENABLED'
            Name = 'Memory Integrity (HVCI) enabled'
            Description = 'Hypervisor-protected code integrity is enabled.'
            ConditionsMatched = @('HKLM DeviceGuard HVCI Enabled value is 1.')
            Evidence = [pscustomobject]@{ MemoryIntegrity = $Snapshot.Registry.MemoryIntegrity }
            Severity = 'Informational'
            Confidence = 'High for the setting; the performance cost varies by hardware and workload.'
            PotentialImpact = 'HVCI is a security feature; some benchmarks show a small frame-rate cost on some systems.'
            AllowedActions = @('Keep it on for security, or measure with it off (Apply -DisableMemoryIntegrity) and decide based on your own numbers.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit after a restart and check the HVCI value.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-SEC-HVCI'
            FindingId = 'SEC-HVCI-ENABLED'
            Description = 'Decide on HVCI based on your own measurements; it is a security feature.'
            Automatic = $false
        }
    }

    # --- RAM XMP/EXPO rule ---
    $underclockedModules = @($Snapshot.RAM.Modules | Where-Object {
        $_ -and $_.RatedSpeedMHz -and $_.ConfiguredSpeedMHz -and
        [int]$_.RatedSpeedMHz -gt 0 -and [int]$_.ConfiguredSpeedMHz -gt 0 -and
        ([int]$_.RatedSpeedMHz - [int]$_.ConfiguredSpeedMHz) -ge 200
    })
    if ($underclockedModules.Count -gt 0) {
        $findings += [pscustomobject]@{
            Id = 'RAM-XMP-DISABLED'
            Name = 'Memory runs below its rated speed'
            Description = 'One or more RAM modules run at a lower clock than their rated speed.'
            ConditionsMatched = @('At least one module has a rated speed at least 200 MT/s above its configured speed.')
            Evidence = [pscustomobject]@{ Modules = $underclockedModules }
            Severity = 'Informational'
            Confidence = 'Moderate; the SMBIOS-reported rated speed can be wrong on some boards, and the CPU or board may legitimately cap memory speed.'
            PotentialImpact = 'RAM below its rated speed reduces memory bandwidth; in CPU-bound games this can cost a measurable percentage of FPS.'
            AllowedActions = @('Enable XMP/EXPO in UEFI/BIOS if the platform supports it.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit after enabling XMP/EXPO and compare ConfiguredSpeedMHz with RatedSpeedMHz.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-RAM-XMP'
            FindingId = 'RAM-XMP-DISABLED'
            Description = 'Enable XMP/EXPO in UEFI/BIOS so RAM runs at its rated speed.'
            Automatic = $false
        }
    }

    # --- GPU driver age rule ---
    $oldGpuDrivers = @($Snapshot.GPU.Devices | Where-Object { $_ -and $_.DriverDate } | ForEach-Object {
        $parsedDate = $null
        try { $parsedDate = [Management.ManagementDateTimeConverter]::ToDateTime([string]$_.DriverDate) } catch { $parsedDate = $null }
        if ($parsedDate -and $parsedDate -lt (Get-Date).AddDays(-180)) {
            [pscustomobject]@{ Name = $_.Name; DriverVersion = $_.DriverVersion; DriverDate = $parsedDate.ToString('yyyy-MM-dd') }
        }
    })
    if ($oldGpuDrivers.Count -gt 0) {
        $findings += [pscustomobject]@{
            Id = 'GPU-DRIVER-OLD'
            Name = 'GPU driver older than 180 days'
            Description = 'At least one display adapter runs a driver released more than 180 days ago.'
            ConditionsMatched = @('A GPU DriverDate is more than 180 days in the past.')
            Evidence = [pscustomobject]@{ Devices = $oldGpuDrivers }
            Severity = 'Informational'
            Confidence = 'High for the driver date; the benefit of updating depends on the games you play.'
            PotentialImpact = 'Newer drivers often include game-specific fixes and performance work.'
            AllowedActions = @('Download the latest driver from the GPU vendor (NVIDIA/AMD/Intel).')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit after updating and check the DriverDate.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-GPU-DRIVER'
            FindingId = 'GPU-DRIVER-OLD'
            Description = 'Update the GPU driver from the vendor site.'
            Automatic = $false
        }
    }

    # --- Game Mode rule ---
    $gameModeDisabled = ($null -ne $Snapshot.Registry.GameMode -and [int]$Snapshot.Registry.GameMode -eq 0) -or
        ($null -ne $Snapshot.Registry.GameModeAllowed -and [int]$Snapshot.Registry.GameModeAllowed -eq 0)
    if ($gameModeDisabled) {
        $findings += [pscustomobject]@{
            Id = 'GAME-MODE-DISABLED'
            Name = 'Game Mode disabled'
            Description = 'Windows Game Mode is turned off in the registry.'
            ConditionsMatched = @('AutoGameModeEnabled or AllowAutoGameMode is 0.')
            Evidence = [pscustomobject]@{ GameMode = $Snapshot.Registry.GameMode; GameModeAllowed = $Snapshot.Registry.GameModeAllowed }
            Severity = 'Informational'
            Confidence = 'High for the registry values; Game Mode benefit varies by system and game.'
            PotentialImpact = 'Game Mode limits background activity during games; with it off, background tasks may compete for CPU.'
            AllowedActions = @('Re-enable Game Mode in Settings > Gaming > Game Mode.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Re-run Audit and check that the Game Mode values are 1 or absent.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-GAME-MODE'
            FindingId = 'GAME-MODE-DISABLED'
            Description = 'Turn Game Mode back on unless you disabled it deliberately.'
            Automatic = $false
        }
    }

    $wifiWeakSignal = @()
    if ($Snapshot.Network.WiFi -and $Snapshot.Network.WiFi.Interfaces) {
        $wifiWeakSignal = @($Snapshot.Network.WiFi.Interfaces | Where-Object { $null -ne $_.SignalPercent -and $_.SignalPercent -lt 40 })
    }
    if ($wifiWeakSignal.Count -gt 0) {
        $findings += [pscustomobject]@{
            Id = 'NET-WIFI-WEAK-SIGNAL'
            Name = 'Weak Wi-Fi signal'
            Description = 'A wireless interface reports a low signal percentage.'
            ConditionsMatched = @('At least one connected Wi-Fi interface reported signal below 40 percent.')
            Evidence = [pscustomobject]@{ Interfaces = $wifiWeakSignal }
            Severity = 'Informational'
            Confidence = 'Moderate; signal percent is an adapter-reported value, not a throughput measurement.'
            PotentialImpact = 'A weak signal can raise latency and packet loss on wireless connections.'
            AllowedActions = @('Move closer to the access point, switch to the 5 GHz band, or use Ethernet for latency-sensitive applications.')
            Risk = 'None; audit only.'
            Rollback = 'Not applicable; no system setting was changed.'
            Verification = 'Run Audit again after repositioning and compare SignalPercent.'
        }
        $recommendations += [pscustomobject]@{
            Id = 'REC-NET-WIFI-SIGNAL'
            FindingId = 'NET-WIFI-WEAK-SIGNAL'
            Description = 'Improve Wi-Fi signal (placement, 5 GHz band) or switch to Ethernet for latency-sensitive use.'
            Automatic = $false
        }
    }

    return [pscustomobject]@{
        Findings = @($findings)
        Recommendations = @($recommendations)
        EvaluatedRuleIds = @('SYS-REBOOT-MARKER', 'CPU-HIGH-LOAD-SAMPLE', 'RAM-MEMORY-PRESSURE', 'NET-ICMP-TIMEOUT', 'DISK-LOW-FREE-SPACE', 'DISK-HEALTH', 'DISK-TRIM-DISABLED', 'NET-WIFI-WEAK-SIGNAL', 'PWR-PCIE-ASPM-ENABLED', 'PWR-USB-SELECTIVE-SUSPEND-ENABLED', 'PWR-CPU-BOOST-DISABLED', 'SVC-DIAGTRACK-RUNNING', 'SVC-SYSMAIN-SSD', 'STARTUP-COUNT-HIGH', 'GPU-NO-HIGH-PERF-APPS', 'SEC-HVCI-ENABLED', 'RAM-XMP-DISABLED', 'GPU-DRIVER-OLD', 'GAME-MODE-DISABLED')
    }
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Write-AuditHtmlReport {
    param(
        [Parameter(Mandatory)][pscustomobject]$Snapshot,
        [Parameter(Mandatory)][string]$HtmlPath
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>WinOptimize Audit</title><style>body{font-family:''Segoe UI'',Arial,sans-serif;margin:2em;background:#1e1e1e;color:#ddd}table{border-collapse:collapse;width:100%;margin-bottom:1.5em}th,td{border:1px solid #444;padding:6px 10px;text-align:left;vertical-align:top}th{background:#333}h1,h2{color:#fff}.sev{color:#6cf}.err{color:#f66}</style></head><body>')
    [void]$sb.AppendLine(('<h1>WinOptimize Audit</h1><p>Machine: {0} &nbsp;|&nbsp; Time (UTC): {1} &nbsp;|&nbsp; Schema: {2}</p>' -f (ConvertTo-HtmlEncoded $Snapshot.Machine.ComputerName), $Snapshot.Timestamp, $Snapshot.SchemaVersion))

    $findings = @($Snapshot.Findings)
    [void]$sb.AppendLine(('<h2>Findings ({0})</h2>' -f $findings.Count))
    if ($findings.Count -gt 0) {
        [void]$sb.AppendLine('<table><tr><th>ID</th><th>Name</th><th>Severity</th><th>Description</th><th>Confidence</th><th>Verification</th></tr>')
        foreach ($finding in $findings) {
            [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td class="sev">{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (ConvertTo-HtmlEncoded $finding.Id), (ConvertTo-HtmlEncoded $finding.Name), (ConvertTo-HtmlEncoded $finding.Severity), (ConvertTo-HtmlEncoded $finding.Description), (ConvertTo-HtmlEncoded $finding.Confidence), (ConvertTo-HtmlEncoded $finding.Verification)))
        }
        [void]$sb.AppendLine('</table>')
    }
    else {
        [void]$sb.AppendLine('<p>No findings.</p>')
    }

    $recommendations = @($Snapshot.Recommendations)
    [void]$sb.AppendLine(('<h2>Recommendations ({0})</h2>' -f $recommendations.Count))
    if ($recommendations.Count -gt 0) {
        [void]$sb.AppendLine('<table><tr><th>ID</th><th>Finding</th><th>Action</th></tr>')
        foreach ($recommendation in $recommendations) {
            [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-HtmlEncoded $recommendation.Id), (ConvertTo-HtmlEncoded $recommendation.FindingId), (ConvertTo-HtmlEncoded $recommendation.Description)))
        }
        [void]$sb.AppendLine('</table>')
    }
    else {
        [void]$sb.AppendLine('<p>No recommendations.</p>')
    }

    [void]$sb.AppendLine('<h2>System</h2><table>')
    $systemRows = @()
    if ($Snapshot.OS) { $systemRows += [pscustomobject]@{ Key = 'OS'; Value = ('{0} ({1}, build {2})' -f $Snapshot.OS.Caption, $Snapshot.OS.Architecture, $Snapshot.OS.BuildNumber) } }
    $systemRows += [pscustomobject]@{ Key = 'CPU'; Value = ((@($Snapshot.CPU | ForEach-Object { $_.Name })) -join '; ') }
    $systemRows += [pscustomobject]@{ Key = 'GPU'; Value = ((@($Snapshot.GPU.Devices | ForEach-Object { $_.Name })) -join '; ') }
    if ($Snapshot.RAM) { $systemRows += [pscustomobject]@{ Key = 'RAM'; Value = ('{0} MB installed, {1} MB free' -f $Snapshot.RAM.InstalledPhysicalMB, $Snapshot.RAM.FreePhysicalMB) } }
    $systemRows += [pscustomobject]@{ Key = 'Power scheme'; Value = [string]$Snapshot.Power.ActiveScheme }
    $systemRows += [pscustomobject]@{ Key = 'Pending restart markers'; Value = (@($Snapshot.PendingRebootReasons) -join ', ') }
    foreach ($row in $systemRows) {
        [void]$sb.AppendLine(('<tr><th>{0}</th><td>{1}</td></tr>' -f (ConvertTo-HtmlEncoded $row.Key), (ConvertTo-HtmlEncoded $row.Value)))
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>Measurement limitations</h2><ul>')
    foreach ($limitation in @($Snapshot.MeasurementLimitations)) {
        [void]$sb.AppendLine(('<li>{0}</li>' -f (ConvertTo-HtmlEncoded $limitation)))
    }
    [void]$sb.AppendLine('</ul>')

    [void]$sb.AppendLine(('<h2>Collection errors ({0})</h2>' -f @($Snapshot.CollectionErrors).Count))
    [void]$sb.AppendLine('<ul>')
    foreach ($collectionError in @($Snapshot.CollectionErrors)) {
        [void]$sb.AppendLine(('<li class="err">{0}</li>' -f (ConvertTo-HtmlEncoded $collectionError)))
    }
    [void]$sb.AppendLine('</ul>')

    [void]$sb.AppendLine('</body></html>')

    [System.IO.File]::WriteAllText($HtmlPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
}

function Write-AuditJsonReport {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is unavailable; cannot choose a user-writable location for the audit JSON.'
    }

    $snapshot = Get-SystemAuditSnapshot
    $evaluation = Invoke-RuleEvaluator -Snapshot $snapshot
    $snapshot.Findings = $evaluation.Findings
    $snapshot.Recommendations = $evaluation.Recommendations
    $snapshot.RuleEvaluatorStatus = 'Rule set v1 evaluated; findings are evidence-based and no fixes are applied automatically.'
    $snapshot | Add-Member -MemberType NoteProperty -Name EvaluatedRuleIds -Value $evaluation.EvaluatedRuleIds

    $reportDirectory = Join-Path $env:LOCALAPPDATA 'WinOptimize\Reports'
    New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    $fileName = 'audit-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
    $reportPath = Join-Path $reportDirectory $fileName
    $json = $snapshot | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($reportPath, $json, [System.Text.UTF8Encoding]::new($false))

    $htmlReportPath = $null
    try {
        $htmlReportPath = [System.IO.Path]::ChangeExtension($reportPath, '.html')
        Write-AuditHtmlReport -Snapshot $snapshot -HtmlPath $htmlReportPath
    }
    catch {
        Write-Host "HTML report could not be generated: $($_.Exception.Message)"
        $htmlReportPath = $null
    }

    Write-Host 'Audit complete. No system settings were changed.'
    Write-Host ("JSON report: {0}" -f $reportPath)
    if ($htmlReportPath) {
        Write-Host ("HTML report: {0}" -f $htmlReportPath)
    }
    Write-Host ("Findings: {0}; recommendations: {1}" -f $snapshot.Findings.Count, $snapshot.Recommendations.Count)
    Write-Host ("Collection errors/unavailable sources: {0}" -f $snapshot.CollectionErrors.Count)
}

function Optimize-Graphics {
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Value 1
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\GameBar' -Name 'AllowAutoGameMode' -Value 1

    if ($EnableHags) {
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -Name 'HwSchMode' -Value 2
        Write-Log 'GPU scheduling (HAGS) enabled. Restart needed. Compare FPS and frame times before keeping it.' 'WARN'
    }

    foreach ($exe in @($script:GpuAppsClean)) {
        if (($exe -notmatch '\.exe$') -or -not (Test-Path -LiteralPath $exe)) {
            Write-Log "GPU preference skipped (not an existing .exe): $exe" 'WARN'
            continue
        }

        Set-RegistryValue -Path 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' -Name $exe -Value 'GpuPreference=2;' -Type String
        Write-Log "High-performance GPU set for: $exe"
    }
}

$script:RuntimePackages = @(
    'Microsoft.VCRedist.2015+.x64',
    'Microsoft.VCRedist.2015+.x86',
    'Microsoft.VCRedist.2013.x64',
    'Microsoft.VCRedist.2013.x86',
    'Microsoft.DotNet.DesktopRuntime.8',
    'Microsoft.DotNet.DesktopRuntime.10',
    'Microsoft.DirectX'
)

function Test-RuntimeInstalled {
    param([Parameter(Mandatory)][string]$Id)

    if ($Id -eq 'Microsoft.DirectX') {
        $dll = Join-Path $env:SystemRoot 'SysWOW64\d3dx9_43.dll'
        if (-not (Test-Path -LiteralPath $dll)) { $dll = Join-Path $env:SystemRoot 'System32\d3dx9_43.dll' }
        return (Test-Path -LiteralPath $dll)
    }

    & winget.exe list --id $Id --exact --source winget --accept-source-agreements 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Install-Runtime {
    param([Parameter(Mandatory)][string]$Id)

    if (Test-RuntimeInstalled -Id $Id) {
        Write-Log "Already installed: $Id"
        return
    }

    Write-Log "Installing: $Id"
    & winget.exe install --id $Id --exact --source winget --silent --disable-interactivity --accept-package-agreements --accept-source-agreements | Out-Null
    $code = $LASTEXITCODE

    if ($code -eq 0 -or $code -eq -1978335189 -or $code -eq -1978335135) {
        Write-Log "Installed: $Id"
    }
    elseif ($code -eq 3010) {
        Write-Log "Installed: $Id (restart needed)"
    }
    else {
        Write-Log "winget could not install $Id (exit code $code). Check your internet connection." 'WARN'
    }
}

function Optimize-Runtimes {
    if (-not (Get-Command -Name 'winget.exe' -ErrorAction SilentlyContinue)) {
        Write-Log 'winget is not available. Install "App Installer" from the Microsoft Store, then run again.' 'WARN'
        return
    }

    foreach ($id in $script:RuntimePackages) {
        Install-Runtime -Id $id
    }
}

function Get-PagefileSizeMb {
    param([Parameter(Mandatory)][double]$RamMb)

    $size = [math]::Max($RamMb, 4096)
    $size = [math]::Ceiling($size / 256) * 256
    return [int][math]::Min($size, 16384)
}

function Optimize-Pagefile {
    $memPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $current = Get-RegistryValueOrNull -Path $memPath -Name 'PagingFiles'

    foreach ($entry in @($current | Where-Object { $_ })) {
        if (([string]$entry) -notmatch '^\?:') {
            Write-Log "A custom paging file setup already exists ($entry). Left unchanged." 'WARN'
            return
        }
    }

    $ramMb  = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1MB
    $sizeMb = Get-PagefileSizeMb -RamMb $ramMb

    $freeMb = ([System.IO.DriveInfo]::new($env:SystemDrive)).AvailableFreeSpace / 1MB
    if ($freeMb -lt ($sizeMb + 10240)) {
        Write-Log "Not enough free space on $($env:SystemDrive) for a $sizeMb MB paging file plus a 10 GB reserve. Left unchanged." 'WARN'
        return
    }

    $entryText = '{0}\pagefile.sys {1} {1}' -f $env:SystemDrive, $sizeMb
    Set-RegistryValue -Path $memPath -Name 'PagingFiles' -Value ([string[]]@($entryText)) -Type MultiString
    Write-Log ("Paging file set to a fixed {0} MB (RAM: {1} MB). Restart needed." -f $sizeMb, [math]::Round($ramMb))
    Write-Log 'Note: a fixed paging file smaller than RAM means full memory dumps are not possible after a crash.' 'WARN'
}

function Optimize-MiscServices {
    Disable-ServiceSafe -Name 'MapsBroker'
    Disable-ServiceSafe -Name 'Fax'
}

function Optimize-LocationService {
    Disable-ServiceSafe -Name 'lfsvc'
    Write-Log 'Geolocation service disabled: automatic time zone and Find My Device will not work.' 'WARN'
}

function Optimize-WirelessDisplay {
    Disable-ServiceSafe -Name 'WFDSConMgrSvc'
    Write-Log 'Wi-Fi Direct / wireless display service disabled: Miracast casting will not work.' 'WARN'
}

function Optimize-MemoryIntegrity {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'

    if ((Get-RegistryValueOrNull -Path $key -Name 'Locked') -eq 1) {
        Write-Log 'Memory Integrity is locked by UEFI and cannot be changed from Windows. Left unchanged.' 'WARN'
        return
    }

    if ((Get-RegistryValueOrNull -Path $key -Name 'Enabled') -eq 0) {
        Write-Log 'Memory Integrity is already off.'
        return
    }

    Set-RegistryValue -Path $key -Name 'Enabled' -Value 0
    Write-Log 'Memory Integrity (HVCI) turned off. Restart needed.' 'WARN'
    Write-Log 'This removes a kernel security protection. To turn it back on: -Mode Rollback, or Windows Security > Device security > Core isolation.' 'WARN'
}

function Optimize-TracingSessions {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
    $sessions = @('Diagtrack-Listener', 'SQMLogger', 'WdiContextLog', 'Circular Kernel Context Logger')

    $media = $null
    try {
        $media = (Get-Partition -DriveLetter $env:SystemDrive.TrimEnd(':') | Get-Disk | Get-PhysicalDisk).MediaType
    }
    catch {
        $media = $null
    }

    if ("$media" -eq 'SSD') { $sessions += 'ReadyBoot' }

    foreach ($name in $sessions) {
        $path = "$base\$name"
        if (-not (Test-Path -LiteralPath $path)) {
            Write-Log "Trace session not present: $name"
            continue
        }

        try {
            Set-RegistryValue -Path $path -Name 'Start' -Value 0
        }
        catch {
            Write-Log "Could not change trace session ${name}: $($_.Exception.Message)" 'WARN'
        }
    }
}

function Restart-ExplorerShell {
    Get-Process -Name 'explorer' -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 3
    if (-not (Get-Process -Name 'explorer' -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe')
    }
    Write-Log 'Windows shell restarted.'
}

function Get-DiscreteGpuDevices {
    return @(Get-PnpDevice -Class Display -PresentOnly -ErrorAction SilentlyContinue | Where-Object {
        ($_.InstanceId -like 'PCI\VEN_10DE*') -or
        (($_.InstanceId -like 'PCI\VEN_1002*') -and ([string]$_.FriendlyName -match 'Radeon\s+(RX|Pro)'))
    })
}

function Get-GpuMsiPath {
    param([Parameter(Mandatory)]$Device)
    return "HKLM:\SYSTEM\CurrentControlSet\Enum\$($Device.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
}

function Optimize-GpuMsi {
    $gpus = @(Get-DiscreteGpuDevices)
    if ($gpus.Count -eq 0) {
        Write-Log 'No discrete NVIDIA/AMD GPU found. MSI left unchanged.'
        return
    }

    foreach ($gpu in $gpus) {
        $path = Get-GpuMsiPath -Device $gpu
        if ((Get-RegistryValueOrNull -Path $path -Name 'MSISupported') -eq 1) {
            Write-Log "Already using MSI: $($gpu.FriendlyName)"
            continue
        }

        Set-RegistryValue -Path $path -Name 'MSISupported' -Value 1
        Write-Log "MSI enabled for: $($gpu.FriendlyName). Restart needed." 'WARN'
    }
}

function Add-NetChange {
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Adapter,
        [string]$Keyword = '',
        [string]$Original = ''
    )

    $script:State.NetChanges = @($script:State.NetChanges) + [pscustomobject]@{
        Kind     = $Kind
        Adapter  = $Adapter
        Keyword  = $Keyword
        Original = $Original
    }

    Save-State
}

function Restore-NetChanges {
    $remaining = @()
    foreach ($c in @($script:State.NetChanges)) {
        try {
            if ($c.Kind -eq 'RSS') {
                $enabled = ($c.Original -eq 'true')
                Set-NetAdapterRss -Name $c.Adapter -Enabled $enabled
                Write-Log "RSS restored to $enabled on $($c.Adapter)"
            }
            else {
                Set-NetAdapterAdvancedProperty -Name $c.Adapter -RegistryKeyword $c.Keyword -RegistryValue $c.Original
                Write-Log "Adapter setting restored: $($c.Adapter) $($c.Keyword) = $($c.Original)"
            }
        }
        catch {
            Write-Log "Could not restore network setting on $($c.Adapter): $($_.Exception.Message)" 'WARN'
            $remaining += $c
        }
    }

    $script:State.NetChanges = @($remaining)
    Save-State
}

function Optimize-NetworkAdapters {
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { [string]$_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) {
        Write-Log 'No active physical network adapter found.'
        return
    }

    foreach ($adapter in $adapters) {
        $name = [string]$adapter.Name

        try {
            $rss = Get-NetAdapterRss -Name $name -ErrorAction Stop
            if ($rss.Enabled -eq $false) {
                Add-NetChange -Kind 'RSS' -Adapter $name -Original 'false'
                Set-NetAdapterRss -Name $name -Enabled $true -ErrorAction Stop
                Write-Log "RSS enabled on $name"
            }
            else {
                Write-Log "RSS already enabled on $name"
            }
        }
        catch {
            Write-Log "RSS is not supported or could not be changed on $name"
        }

        if ([string]$adapter.PhysicalMediaType -eq '802.3') {
            try {
                $eee = Get-NetAdapterAdvancedProperty -Name $name -RegistryKeyword '*EEE' -ErrorAction Stop
                $original = [string](@($eee.RegistryValue)[0])
                if ($original -ne '0') {
                    Add-NetChange -Kind 'Advanced' -Adapter $name -Keyword '*EEE' -Original $original
                    Set-NetAdapterAdvancedProperty -Name $name -RegistryKeyword '*EEE' -RegistryValue 0 -ErrorAction Stop
                    Write-Log "Energy-Efficient Ethernet turned off on $name"
                }
                else {
                    Write-Log "Energy-Efficient Ethernet already off on $name"
                }
            }
            catch {
                Write-Log "Energy-Efficient Ethernet setting not available on $name"
            }
        }
    }
}

function Optimize-MouseAcceleration {
    $mouse = 'HKCU:\Control Panel\Mouse'
    Set-RegistryValue -Path $mouse -Name 'MouseSpeed' -Value '0' -Type String
    Set-RegistryValue -Path $mouse -Name 'MouseThreshold1' -Value '0' -Type String
    Set-RegistryValue -Path $mouse -Name 'MouseThreshold2' -Value '0' -Type String
    Write-Log 'Mouse acceleration off. Sign out and back in to apply.'
}

function Optimize-NagleOff {
    $interfacesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) {
        Write-Log 'No active physical network adapter found. Nagle algorithm left unchanged.'
        return
    }

    foreach ($adapter in $adapters) {
        $guid = [string]$adapter.InterfaceGuid
        $keyPath = Join-Path $interfacesPath $guid
        Set-RegistryValue -Path $keyPath -Name 'TcpAckFrequency' -Value 1
        Set-RegistryValue -Path $keyPath -Name 'TCPNoDelay' -Value 1
        Set-RegistryValue -Path $keyPath -Name 'TcpDelAckTicks' -Value 0
        Write-Log "Nagle algorithm off on $($adapter.Name) ($guid). A restart or adapter reconnection may be required."
    }
    Write-Log 'Note: this only affects applications that send many small TCP packets; measure ping/jitter to your game servers before and after.'
}

function Optimize-Cleanup {
    $before = Get-FreeSpaceBytes
    Clear-FolderContents -Path $env:TEMP
    Clear-FolderContents -Path (Join-Path $env:SystemRoot 'Temp')
    Write-Log 'Temp folders cleaned (files in use are skipped).'

    Clear-UpdateCache
    Write-Log 'Windows Update download cache cleaned.'

    $wer = Join-Path $env:ProgramData 'Microsoft\Windows\WER'
    foreach ($sub in @('ReportArchive', 'ReportQueue', 'Temp')) {
        Clear-FolderContents -Path (Join-Path $wer $sub)
    }
    Write-Log 'Windows Error Reporting archive and queue cleaned.'

    if (Get-Command -Name 'Delete-DeliveryOptimizationCache' -ErrorAction SilentlyContinue) {
        Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue
        Write-Log 'Delivery Optimization cache cleaned.'
    }

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
    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegistryValue -Path $au -Name 'NoAutoUpdate' -Value 0
    Set-RegistryValue -Path $au -Name 'AUOptions' -Value 2
    Write-Log 'Updates are now manual. Check for updates regularly in Settings.' 'WARN'
}

# ---------------------------------------------------------------------------
# Step verification helpers
# ---------------------------------------------------------------------------

function Test-PowerPlanApplied {
    if (-not $script:State.CreatedPowerScheme) { return $true }
    $active = (& powercfg.exe /getactivescheme) -join ' '
    $match = [regex]::Match($active, $script:GuidPattern)
    return ($match.Success -and $match.Value -eq $script:State.CreatedPowerScheme)
}

function Test-SysMainDisabled {
    $letter = $env:SystemDrive.TrimEnd(':')
    $media = $null
    try { $media = (Get-Partition -DriveLetter $letter | Get-Disk | Get-PhysicalDisk).MediaType } catch { $media = $null }
    if ("$media" -ne 'SSD') { return $true }
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SysMain'" -ErrorAction SilentlyContinue
    if (-not $service) { return $true }
    return ($service.StartMode -eq 'Disabled')
}

function Test-MemoryCompressionDisabled {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if (-not $cs -or -not $cs.TotalPhysicalMemory) { return $true }
    if ([math]::Round($cs.TotalPhysicalMemory / 1GB, 1) -lt 16) { return $true }
    $mm = Get-MMAgent -ErrorAction SilentlyContinue
    if (-not $mm) { return $true }
    return (-not $mm.MemoryCompression)
}

function Test-GameDvrDisabled {
    return ((Test-RegistryDwordValue -Path 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Expected 0) -and
        (Test-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Expected 0))
}

function Test-NagleDisabled {
    $interfacesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) { return $true }
    foreach ($adapter in $adapters) {
        $keyPath = Join-Path $interfacesPath ([string]$adapter.InterfaceGuid)
        if (-not (Test-RegistryDwordValue -Path $keyPath -Name 'TcpAckFrequency' -Expected 1)) { return $false }
        if (-not (Test-RegistryDwordValue -Path $keyPath -Name 'TCPNoDelay' -Expected 1)) { return $false }
        if (-not (Test-RegistryDwordValue -Path $keyPath -Name 'TcpDelAckTicks' -Expected 0)) { return $false }
    }
    return $true
}

function Test-MouseAccelerationDisabled {
    $path = 'HKCU:\Control Panel\Mouse'
    return ((Test-RegistryStringValue -Path $path -Name 'MouseSpeed' -Expected '0') -and
        (Test-RegistryStringValue -Path $path -Name 'MouseThreshold1' -Expected '0') -and
        (Test-RegistryStringValue -Path $path -Name 'MouseThreshold2' -Expected '0'))
}

# ---------------------------------------------------------------------------
# Benchmark (before/after comparison)
# ---------------------------------------------------------------------------

function Get-BenchmarkSnapshot {
    param([string]$Label = 'Snapshot')

    $cpuSamples = @()
    for ($sampleIndex = 0; $sampleIndex -lt 3; $sampleIndex++) {
        $loads = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
            Where-Object { $null -ne $_.LoadPercentage } |
            ForEach-Object { [double]$_.LoadPercentage })
        if ($loads.Count -gt 0) {
            $cpuSamples += [double](($loads | Measure-Object -Average).Average)
        }
        if ($sampleIndex -lt 2) { Start-Sleep -Milliseconds 700 }
    }
    $cpuLoadAverage = $null
    if ($cpuSamples.Count -gt 0) {
        $cpuLoadAverage = [math]::Round((($cpuSamples | Measure-Object -Average).Average), 1)
    }

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $totalMb = [double]$osInfo.TotalVisibleMemorySize / 1KB
    $freeMb = [double]$osInfo.FreePhysicalMemory / 1KB
    $usedPercent = $null
    if ($totalMb -gt 0) {
        $usedPercent = [math]::Round((($totalMb - $freeMb) / $totalMb) * 100, 1)
    }

    $volumes = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
        ForEach-Object {
            $sizeBytes = [double]$_.Size
            $freeBytes = [double]$_.FreeSpace
            [pscustomobject]@{
                Drive       = $_.DeviceID
                SizeGB      = [math]::Round($sizeBytes / 1GB, 2)
                FreeGB      = [math]::Round($freeBytes / 1GB, 2)
                FreePercent = $(if ($sizeBytes -gt 0) { [math]::Round(($freeBytes / $sizeBytes) * 100, 1) } else { $null })
            }
        })

    $pingResults = @()
    foreach ($target in $script:PingTargetsClean) {
        $rtts = @()
        $lost = 0
        $pingClient = New-Object System.Net.NetworkInformation.Ping
        try {
            for ($probeIndex = 0; $probeIndex -lt $PingCount; $probeIndex++) {
                try {
                    $reply = $pingClient.Send($target, 1500)
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $rtts += [double]$reply.RoundtripTime
                    }
                    else {
                        $lost++
                    }
                }
                catch {
                    $lost++
                }
            }
        }
        finally {
            $pingClient.Dispose()
        }

        $averageMs = $null
        if ($rtts.Count -gt 0) {
            $averageMs = [math]::Round((($rtts | Measure-Object -Average).Average), 2)
        }
        $pingResults += [pscustomobject]@{
            Target      = $target
            AverageMs   = $averageMs
            LossPercent = $(if ($PingCount -gt 0) { [math]::Round(($lost / [double]$PingCount) * 100, 1) } else { $null })
        }
    }

    $schemeGuid = $null
    $schemeOutput = & powercfg.exe /getactivescheme 2>$null | Out-String
    if ($LASTEXITCODE -eq 0 -and $schemeOutput) {
        $schemeMatch = [regex]::Match($schemeOutput, '[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
        if ($schemeMatch.Success) { $schemeGuid = $schemeMatch.Value }
    }

    [pscustomobject]@{
        Label                 = $Label
        Timestamp             = (Get-Date).ToString('o')
        CpuLoadAveragePercent = $cpuLoadAverage
        MemoryTotalMB         = [math]::Round($totalMb, 0)
        MemoryFreeMB          = [math]::Round($freeMb, 0)
        MemoryUsedPercent     = $usedPercent
        Volumes               = $volumes
        Ping                  = $pingResults
        ActivePowerSchemeGuid = $schemeGuid
    }
}

function New-MetricComparison {
    param(
        [Parameter(Mandatory)][string]$Metric,
        $BeforeValue,
        $AfterValue,
        [string]$Unit = '',
        [ValidateSet('Lower', 'Higher', 'Info')][string]$Direction = 'Info',
        [double]$NoiseThreshold = 0
    )

    $delta = $null
    $assessment = 'Insufficient data'
    if ($null -ne $BeforeValue -and $null -ne $AfterValue) {
        $delta = [math]::Round([double]$AfterValue - [double]$BeforeValue, 2)
        if ($Direction -eq 'Info') {
            if ($delta -eq 0) { $assessment = 'Unchanged' } else { $assessment = 'Changed' }
        }
        elseif ([math]::Abs($delta) -le $NoiseThreshold) {
            $assessment = 'No significant change'
        }
        elseif (($Direction -eq 'Lower' -and $delta -lt 0) -or ($Direction -eq 'Higher' -and $delta -gt 0)) {
            $assessment = 'Better'
        }
        else {
            $assessment = 'Worse'
        }
    }

    [pscustomobject]@{
        Metric     = $Metric
        Before     = $BeforeValue
        After      = $AfterValue
        Delta      = $delta
        Unit       = $Unit
        Assessment = $assessment
    }
}

function Compare-BenchmarkSnapshots {
    param(
        [Parameter(Mandatory)][pscustomobject]$Before,
        [Parameter(Mandatory)][pscustomobject]$After
    )

    $comparisons = @()

    $comparisons += New-MetricComparison -Metric 'CPU load (average)' -BeforeValue $Before.CpuLoadAveragePercent -AfterValue $After.CpuLoadAveragePercent -Unit '%' -Direction Lower -NoiseThreshold 2
    $comparisons += New-MetricComparison -Metric 'Memory used' -BeforeValue $Before.MemoryUsedPercent -AfterValue $After.MemoryUsedPercent -Unit '%' -Direction Lower -NoiseThreshold 1
    $comparisons += New-MetricComparison -Metric 'Memory free' -BeforeValue $Before.MemoryFreeMB -AfterValue $After.MemoryFreeMB -Unit ' MB' -Direction Higher -NoiseThreshold 100

    foreach ($beforeVolume in @($Before.Volumes)) {
        $afterVolume = @($After.Volumes | Where-Object { $_.Drive -eq $beforeVolume.Drive }) | Select-Object -First 1
        if ($null -eq $afterVolume) { continue }
        $comparisons += New-MetricComparison -Metric ("Free space on {0}" -f $beforeVolume.Drive) -BeforeValue $beforeVolume.FreeGB -AfterValue $afterVolume.FreeGB -Unit ' GB' -Direction Higher -NoiseThreshold 0.1
    }

    foreach ($beforePing in @($Before.Ping)) {
        $afterPing = @($After.Ping | Where-Object { $_.Target -eq $beforePing.Target }) | Select-Object -First 1
        if ($null -eq $afterPing) { continue }

        $pingNoiseThreshold = 0
        if ($null -ne $beforePing.AverageMs) {
            $pingNoiseThreshold = [math]::Max(3, [math]::Round($beforePing.AverageMs * 0.1, 2))
        }
        $comparisons += New-MetricComparison -Metric ("Ping average to {0}" -f $beforePing.Target) -BeforeValue $beforePing.AverageMs -AfterValue $afterPing.AverageMs -Unit ' ms' -Direction Lower -NoiseThreshold $pingNoiseThreshold
        $comparisons += New-MetricComparison -Metric ("Packet loss to {0}" -f $beforePing.Target) -BeforeValue $beforePing.LossPercent -AfterValue $afterPing.LossPercent -Unit '%' -Direction Lower -NoiseThreshold 0.5
    }

    $comparisons += [pscustomobject]@{
        Metric     = 'Active power scheme GUID'
        Before     = $Before.ActivePowerSchemeGuid
        After      = $After.ActivePowerSchemeGuid
        Delta      = $null
        Unit       = ''
        Assessment = $(if ($Before.ActivePowerSchemeGuid -eq $After.ActivePowerSchemeGuid) { 'Unchanged' } else { 'Changed' })
    }

    return @($comparisons)
}

function Show-BenchmarkComparison {
    param([Parameter(Mandatory)][pscustomobject]$Comparison)

    Write-Host ''
    Write-Host '=== Benchmark: before vs after ==='
    foreach ($row in @($Comparison.Comparisons)) {
        $beforeText = if ($null -ne $row.Before) { '{0}{1}' -f $row.Before, $row.Unit } else { 'n/a' }
        $afterText = if ($null -ne $row.After) { '{0}{1}' -f $row.After, $row.Unit } else { 'n/a' }
        $deltaText = if ($null -ne $row.Delta) { '{0:+0.##;-0.##;0}{1}' -f [double]$row.Delta, $row.Unit } else { 'n/a' }
        Write-Host ('  {0,-28} {1,14} -> {2,14}  ({3}, {4})' -f $row.Metric, $beforeText, $afterText, $deltaText, $row.Assessment)
    }
    Write-Host 'Note: CPU, memory and ping are short point-in-time samples; small differences may be noise, not the effect of changes.'
}

function Save-BenchmarkReport {
    param([Parameter(Mandatory)][pscustomobject]$Comparison)

    if (-not (Test-Path -LiteralPath $script:BenchmarkDir)) {
        New-Item -ItemType Directory -Path $script:BenchmarkDir -Force | Out-Null
    }
    $reportName = 'benchmark-{0}.json' -f (Get-Date).ToString('yyyyMMdd-HHmmss')
    $reportPath = Join-Path $script:BenchmarkDir $reportName
    $Comparison | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8 -ErrorAction Stop
    return $reportPath
}

function Get-LatestBenchmarkBaseline {
    if (-not (Test-Path -LiteralPath $script:BenchmarkDir)) { return $null }
    $latestFile = @(Get-ChildItem -LiteralPath $script:BenchmarkDir -Filter 'benchmark-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    if ($latestFile.Count -eq 0) { return $null }
    try {
        return (Get-Content -LiteralPath $latestFile[0].FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        Write-Host "Could not read baseline file $($latestFile[0].Name): $($_.Exception.Message)"
        return $null
    }
}

function Invoke-CompareMode {
    $baselineReport = Get-LatestBenchmarkBaseline
    if (-not $baselineReport -or -not $baselineReport.Before) {
        Write-Host 'No benchmark baseline found. Run -Mode Apply once; its "before" snapshot becomes the baseline.'
        return
    }

    Write-Host ("Baseline captured: {0}" -f $baselineReport.Before.Timestamp)
    Write-Host 'Taking a fresh snapshot...'
    $now = Get-BenchmarkSnapshot -Label 'Now'

    $comparison = [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        Before      = $baselineReport.Before
        After       = $now
        Comparisons = @(Compare-BenchmarkSnapshots -Before $baselineReport.Before -After $now)
    }
    Show-BenchmarkComparison -Comparison $comparison

    $allBaselineFiles = @(Get-ChildItem -LiteralPath $script:BenchmarkDir -Filter 'benchmark-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    if ($allBaselineFiles.Count -gt 1) {
        Write-Host ''
        Write-Host '=== Benchmark history (each saved baseline vs now) ==='
        foreach ($baselineFile in $allBaselineFiles) {
            try {
                $pastReport = Get-Content -LiteralPath $baselineFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                continue
            }
            if (-not $pastReport.Before) { continue }

            $pastComparisons = @(Compare-BenchmarkSnapshots -Before $pastReport.Before -After $now)
            $betterCount = @($pastComparisons | Where-Object { $_.Assessment -eq 'Better' }).Count
            $worseCount = @($pastComparisons | Where-Object { $_.Assessment -eq 'Worse' }).Count
            $sameCount = @($pastComparisons | Where-Object { $_.Assessment -in @('Unchanged', 'No significant change') }).Count
            Write-Host ("  {0}: better {1}, worse {2}, no significant change {3}" -f $pastReport.Before.Timestamp, $betterCount, $worseCount, $sameCount)
        }
    }

    Write-Host 'Read-only mode; nothing was saved or changed.'
}

# ---------------------------------------------------------------------------
# Startup manager
# ---------------------------------------------------------------------------

function Get-StartupPublisher {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return 'Unknown' }

    $exePath = $null
    if ($Command -match '^\s*"([^"]+\.exe)"') { $exePath = $Matches[1] }
    elseif ($Command -match '^\s*([^\s]+\.exe)') { $exePath = $Matches[1] }
    if (-not $exePath) { return 'Unknown' }

    $exePath = [Environment]::ExpandEnvironmentVariables($exePath)
    if ($script:StartupPublisherCache.ContainsKey($exePath)) {
        return [string]$script:StartupPublisherCache[$exePath]
    }

    $publisher = 'Unknown'
    if (Test-Path -LiteralPath $exePath -PathType Leaf) {
        $signature = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
        if ($signature -and $signature.Status -eq 'Valid' -and $signature.SignerCertificate) {
            $subject = [string]$signature.SignerCertificate.Subject
            $commonName = $subject
            if ($subject -match 'CN=([^,]+)') { $commonName = $Matches[1] }
            if ($commonName -match 'Microsoft') { $publisher = 'Microsoft (signed)' }
            else { $publisher = "$commonName (signed)" }
        }
        else {
            $publisher = 'Unsigned'
        }
    }

    $script:StartupPublisherCache[$exePath] = $publisher
    return $publisher
}

function Get-StartupEntries {
    $entries = @()

    $runLocations = @(
        [pscustomobject]@{ Scope = 'CurrentUser';    RunPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';               ApprovedPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
        [pscustomobject]@{ Scope = 'LocalMachine';   RunPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';               ApprovedPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
        [pscustomobject]@{ Scope = 'LocalMachine32'; RunPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';   ApprovedPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32' }
    )

    foreach ($location in $runLocations) {
        if (-not (Test-Path -LiteralPath $location.RunPath)) { continue }
        $properties = Get-ItemProperty -LiteralPath $location.RunPath -ErrorAction SilentlyContinue
        if (-not $properties) { continue }
        $approvedItem = Get-ItemProperty -LiteralPath $location.ApprovedPath -ErrorAction SilentlyContinue

        foreach ($property in $properties.PSObject.Properties) {
            if ($property.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }

            $enabled = $true
            if ($approvedItem -and $approvedItem.PSObject.Properties[$property.Name]) {
                $approvedBytes = [byte[]]($approvedItem.PSObject.Properties[$property.Name].Value)
                if ($approvedBytes.Length -ge 1 -and $approvedBytes[0] -eq 3) { $enabled = $false }
            }

            $command = [string]$property.Value
            $entries += [pscustomobject]@{
                Name         = $property.Name
                Kind         = 'Registry'
                Enabled      = $enabled
                Scope        = $location.Scope
                Command      = $command
                RunPath      = $location.RunPath
                ApprovedPath = $location.ApprovedPath
                FilePath     = $null
                TaskFullPath = $null
                Publisher    = (Get-StartupPublisher -Command $command)
            }
        }
    }

    $startupDirectories = @(
        [pscustomobject]@{ Scope = 'CurrentUser'; Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::Startup) }
        [pscustomobject]@{ Scope = 'AllUsers';    Path = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup') }
    )
    foreach ($directory in $startupDirectories) {
        if (-not $directory.Path -or -not (Test-Path -LiteralPath $directory.Path)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $directory.Path -Force -File -ErrorAction SilentlyContinue)) {
            $isDisabled = $file.Name.EndsWith('.disabled', [StringComparison]::OrdinalIgnoreCase)
            $displayName = $file.Name
            if ($isDisabled) { $displayName = $file.Name.Substring(0, $file.Name.Length - '.disabled'.Length) }
            $entries += [pscustomobject]@{
                Name         = $displayName
                Kind         = 'Folder'
                Enabled      = (-not $isDisabled)
                Scope        = $directory.Scope
                Command      = $file.FullName
                RunPath      = $null
                ApprovedPath = $null
                FilePath     = $file.FullName
                TaskFullPath = $null
                Publisher    = (Get-StartupPublisher -Command $file.FullName)
            }
        }
    }

    $startupTriggerTypes = @('MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger', 'MSFT_TaskRegistrationTrigger')
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $triggerTypes = Get-TaskTriggerTypeNames -Triggers $task.Triggers
        if (@($triggerTypes | Where-Object { $startupTriggerTypes -contains $_ }).Count -eq 0) { continue }

        $firstAction = @($task.Actions) | Select-Object -First 1
        $taskCommand = ''
        $taskPublisher = 'n/a'
        if ($firstAction) {
            $execute = $null
            if ($firstAction.PSObject.Properties['Execute']) { $execute = [string]$firstAction.Execute }
            $arguments = ''
            if ($firstAction.PSObject.Properties['Arguments']) { $arguments = [string]$firstAction.Arguments }
            $taskCommand = "$execute $arguments".Trim()
            if ($execute) {
                $taskPublisher = Get-StartupPublisher -Command $execute
            }
            elseif (-not $taskCommand) {
                $taskCommand = '(non-executable action: COM handler, email or message)'
            }
        }

        $entries += [pscustomobject]@{
            Name         = $task.TaskName
            Kind         = 'Task'
            Enabled      = ([string]$task.State -ne 'Disabled')
            Scope        = $task.TaskPath
            Command      = $taskCommand
            RunPath      = $null
            ApprovedPath = $null
            FilePath     = $null
            TaskFullPath = "$($task.TaskPath)$($task.TaskName)"
            Publisher    = $taskPublisher
        }
    }

    return @($entries)
}

function Show-StartupList {
    param([Parameter(Mandatory)][array]$Entries)

    if ($Entries.Count -eq 0) {
        Write-Host 'No startup entries found.'
        return
    }

    Write-Host ''
    Write-Host ('=== Startup entries ({0}) ===' -f $Entries.Count)
    foreach ($entry in $Entries) {
        $stateText = if ($entry.Enabled) { 'Enabled ' } else { 'Disabled' }
        Write-Host ('  [{0}] [{1,-8}] [{2,-20}] {3}' -f $stateText, $entry.Kind, $entry.Publisher, $entry.Name)
        if ($entry.Command) {
            Write-Host ('        {0}' -f $entry.Command)
        }
    }
    Write-Host ''
    Write-Host "Usage: .\optimize.ps1 -Mode Startup -StartupAction Disable -StartupName 'EntryName'"
}

function Set-StartupRegistryEntryState {
    param(
        [Parameter(Mandatory)][pscustomobject]$Entry,
        [Parameter(Mandatory)][bool]$Enable
    )

    if ($Entry.Enabled -eq $Enable) {
        Write-Log "Startup entry already $(if ($Enable) { 'enabled' } else { 'disabled' }): $($Entry.Name)"
        return
    }

    $currentBytes = $null
    $existed = $false
    $approvedItem = Get-ItemProperty -LiteralPath $Entry.ApprovedPath -ErrorAction SilentlyContinue
    if ($approvedItem -and $approvedItem.PSObject.Properties[$Entry.Name]) {
        $existed = $true
        $currentBytes = [byte[]]($approvedItem.PSObject.Properties[$Entry.Name].Value)
    }

    $known = @($script:State.StartupApproved) | Where-Object { $_.ApprovedPath -eq $Entry.ApprovedPath -and $_.Name -eq $Entry.Name }
    if (-not $known) {
        $script:State.StartupApproved = @($script:State.StartupApproved) + [pscustomobject]@{
            ApprovedPath = $Entry.ApprovedPath
            Name         = $Entry.Name
            Existed      = $existed
            Value        = $(if ($existed -and $null -ne $currentBytes) { [Convert]::ToBase64String($currentBytes) } else { $null })
        }
        Save-State
    }

    $newBytes = [byte[]]::new(12)
    if ($null -ne $currentBytes) {
        [Array]::Copy($currentBytes, $newBytes, [Math]::Min($currentBytes.Length, $newBytes.Length))
    }
    $newBytes[0] = $(if ($Enable) { [byte]2 } else { [byte]3 })

    if (-not (Test-Path -LiteralPath $Entry.ApprovedPath)) {
        New-Item -Path $Entry.ApprovedPath -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Entry.ApprovedPath -Name $Entry.Name -Value $newBytes -PropertyType Binary -Force | Out-Null

    $verifyItem = Get-ItemProperty -LiteralPath $Entry.ApprovedPath -ErrorAction Stop
    $verifyBytes = [byte[]]($verifyItem.PSObject.Properties[$Entry.Name].Value)
    $expectedByte = $(if ($Enable) { [byte]2 } else { [byte]3 })
    if ($verifyBytes.Length -lt 1 -or $verifyBytes[0] -ne $expectedByte) {
        throw "Verification failed: startup entry '$($Entry.Name)' state was not applied."
    }

    Write-Log "Startup entry $(if ($Enable) { 'enabled' } else { 'disabled' }): $($Entry.Name) [$($Entry.RunPath)]"
}

function Set-StartupFolderEntryState {
    param(
        [Parameter(Mandatory)][pscustomobject]$Entry,
        [Parameter(Mandatory)][bool]$Enable
    )

    if ($Entry.Enabled -eq $Enable) {
        Write-Log "Startup folder item already $(if ($Enable) { 'enabled' } else { 'disabled' }): $($Entry.Name)"
        return
    }

    $enabledPath = $Entry.FilePath
    if ($enabledPath.EndsWith('.disabled', [StringComparison]::OrdinalIgnoreCase)) {
        $enabledPath = $enabledPath.Substring(0, $enabledPath.Length - '.disabled'.Length)
    }
    $disabledPath = "$enabledPath.disabled"

    $known = @($script:State.StartupFolder) | Where-Object { $_.DisabledPath -eq $disabledPath }
    if (-not $known) {
        $script:State.StartupFolder = @($script:State.StartupFolder) + [pscustomobject]@{
            Name             = $Entry.Name
            EnabledPath      = $enabledPath
            DisabledPath     = $disabledPath
            WasEnabledBefore = $Entry.Enabled
        }
        Save-State
    }

    if ($Enable) {
        Rename-Item -LiteralPath $disabledPath -NewName (Split-Path $enabledPath -Leaf) -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $enabledPath -PathType Leaf)) {
            throw "Verification failed: '$enabledPath' was not restored."
        }
    }
    else {
        Rename-Item -LiteralPath $enabledPath -NewName ((Split-Path $enabledPath -Leaf) + '.disabled') -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $disabledPath -PathType Leaf)) {
            throw "Verification failed: '$disabledPath' was not created."
        }
    }

    Write-Log "Startup folder item $(if ($Enable) { 'enabled' } else { 'disabled' }): $($Entry.Name)"
}

function Restore-StartupChanges {
    $remainingApproved = @()
    foreach ($entry in @($script:State.StartupApproved)) {
        try {
            if ($entry.Existed) {
                $bytes = [Convert]::FromBase64String([string]$entry.Value)
                if (-not (Test-Path -LiteralPath $entry.ApprovedPath)) {
                    New-Item -Path $entry.ApprovedPath -Force | Out-Null
                }
                New-ItemProperty -LiteralPath $entry.ApprovedPath -Name $entry.Name -Value $bytes -PropertyType Binary -Force | Out-Null
                Write-Log "Startup approved state restored: $($entry.Name)"
            }
            else {
                if (Test-Path -LiteralPath $entry.ApprovedPath) {
                    $item = Get-ItemProperty -LiteralPath $entry.ApprovedPath -ErrorAction Stop
                    if ($item.PSObject.Properties[$entry.Name]) {
                        Remove-ItemProperty -LiteralPath $entry.ApprovedPath -Name $entry.Name -ErrorAction Stop
                        Write-Log "Startup approved value removed: $($entry.Name)"
                    }
                }
            }
        }
        catch {
            Write-Log "Could not restore startup entry $($entry.Name): $($_.Exception.Message)" 'WARN'
            $remainingApproved += $entry
        }
    }
    $script:State.StartupApproved = @($remainingApproved)

    $remainingFolder = @()
    foreach ($entry in @($script:State.StartupFolder)) {
        try {
            if ($entry.WasEnabledBefore) {
                if (Test-Path -LiteralPath $entry.DisabledPath -PathType Leaf) {
                    Rename-Item -LiteralPath $entry.DisabledPath -NewName (Split-Path $entry.EnabledPath -Leaf) -ErrorAction Stop
                    Write-Log "Startup folder item enabled again: $($entry.Name)"
                }
            }
            else {
                if (Test-Path -LiteralPath $entry.EnabledPath -PathType Leaf) {
                    Rename-Item -LiteralPath $entry.EnabledPath -NewName ((Split-Path $entry.EnabledPath -Leaf) + '.disabled') -ErrorAction Stop
                    Write-Log "Startup folder item disabled again: $($entry.Name)"
                }
            }
        }
        catch {
            Write-Log "Could not restore startup folder item $($entry.Name): $($_.Exception.Message)" 'WARN'
            $remainingFolder += $entry
        }
    }
    $script:State.StartupFolder = @($remainingFolder)
    Save-State
}

function Invoke-StartupMode {
    if ($StartupAction -eq 'List') {
        $entries = @(Get-StartupEntries)
        Show-StartupList -Entries $entries
        return
    }

    if ([string]::IsNullOrWhiteSpace($StartupName)) {
        throw "-StartupName is required for -StartupAction $StartupAction. Run '.\optimize.ps1 -Mode Startup -StartupAction List' to see entry names."
    }

    $enable = ($StartupAction -eq 'Enable')
    $entries = @(Get-StartupEntries)
    $targets = @($entries | Where-Object { $_.Name -eq $StartupName })
    if ($targets.Count -eq 0) {
        $escaped = [WildcardPattern]::Escape($StartupName)
        $targets = @($entries | Where-Object { $_.Name -like "*$escaped*" })
    }
    if ($targets.Count -eq 0) {
        throw "Startup entry not found: '$StartupName'. Run '.\optimize.ps1 -Mode Startup -StartupAction List' to see entry names."
    }
    if ($targets.Count -gt 1) {
        foreach ($match in $targets) {
            Write-Host ("  [{0}] {1} ({2})" -f $match.Kind, $match.Name, $match.Scope)
        }
        throw "More than one startup entry matches '$StartupName'. Refine -StartupName to match exactly one entry (see list above)."
    }

    $target = $targets[0]
    switch ($target.Kind) {
        'Registry' { Set-StartupRegistryEntryState -Entry $target -Enable $enable }
        'Folder'   { Set-StartupFolderEntryState -Entry $target -Enable $enable }
        'Task'     {
            if ($enable) { Enable-TaskSafe -FullPath $target.TaskFullPath }
            else { Disable-TaskSafe -FullPath $target.TaskFullPath }
        }
        default { throw "Unsupported startup entry kind: $($target.Kind)" }
    }
    Save-State
    Write-Log "Startup action $StartupAction completed for '$($target.Name)'."
}

# ---------------------------------------------------------------------------
# Components and repair
# ---------------------------------------------------------------------------

function Get-ComponentList {
    $components = @()

    $components += @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name  = $_.FeatureName
            Kind  = 'Feature'
            State = [string]$_.State
        }
    })

    try {
        $components += @(Get-WindowsCapability -Online -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name  = $_.Name
                Kind  = 'Capability'
                State = [string]$_.State
            }
        })
    }
    catch {
        Write-Log "Could not enumerate Windows capabilities: $($_.Exception.Message)" 'WARN'
    }

    return @($components)
}

function Show-ComponentsList {
    param(
        [Parameter(Mandatory)][array]$Components,
        [switch]$ShowAll
    )

    $features = @($Components | Where-Object { $_.Kind -eq 'Feature' })
    $capabilities = @($Components | Where-Object { $_.Kind -eq 'Capability' })
    if (-not $ShowAll) {
        $features = @($features | Where-Object { $_.State -eq 'Enabled' })
        $capabilities = @($capabilities | Where-Object { $_.State -eq 'Installed' })
    }

    Write-Host ''
    Write-Host ('=== Optional features ({0} shown) ===' -f $features.Count)
    foreach ($feature in @($features | Sort-Object Name)) {
        Write-Host ('  [{0,-9}] {1}' -f $feature.State, $feature.Name)
    }
    Write-Host ''
    Write-Host ('=== Capabilities ({0} shown) ===' -f $capabilities.Count)
    foreach ($capability in @($capabilities | Sort-Object Name)) {
        Write-Host ('  [{0,-11}] {1}' -f $capability.State, $capability.Name)
    }
    if (-not $ShowAll) {
        Write-Host 'Only enabled features and installed capabilities are shown. Use -ComponentShowAll to list everything.'
    }
    Write-Host "Usage: .\optimize.ps1 -Mode Components -ComponentAction Disable -ComponentName 'Name'"
}

function Set-ComponentState {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Enable
    )

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction SilentlyContinue
    if ($feature) {
        $isEnabled = ([string]$feature.State -eq 'Enabled')
        if ($isEnabled -eq $Enable) {
            Write-Log "Feature already $(if ($Enable) { 'enabled' } else { 'disabled' }): $Name"
            return
        }

        $known = @($script:State.Components) | Where-Object { $_.Name -eq $Name -and $_.Kind -eq 'Feature' }
        if (-not $known) {
            $script:State.Components = @($script:State.Components) + [pscustomobject]@{
                Name       = $Name
                Kind       = 'Feature'
                WasEnabled = $isEnabled
            }
            Save-State
        }

        if ($Enable) {
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart -ErrorAction Stop
        }
        else {
            $result = Disable-WindowsOptionalFeature -Online -FeatureName $Name -NoRestart -ErrorAction Stop
        }

        $check = Get-WindowsOptionalFeature -Online -FeatureName $Name -ErrorAction Stop
        $nowEnabled = ([string]$check.State -eq 'Enabled')
        if ($nowEnabled -ne $Enable) {
            throw "Verification failed: feature '$Name' is still $($check.State)."
        }
        Write-Log "Feature $(if ($Enable) { 'enabled' } else { 'disabled' }): $Name"
        if ($result.RestartNeeded) {
            Write-Log "Restart required to finish the change for feature '$Name'." 'WARN'
        }
        return
    }

    $capability = Get-WindowsCapability -Online -Name $Name -ErrorAction SilentlyContinue
    if ($capability) {
        $isInstalled = ([string]$capability.State -eq 'Installed')
        if ($isInstalled -eq $Enable) {
            Write-Log "Capability already $(if ($Enable) { 'installed' } else { 'removed' }): $Name"
            return
        }

        $known = @($script:State.Components) | Where-Object { $_.Name -eq $Name -and $_.Kind -eq 'Capability' }
        if (-not $known) {
            $script:State.Components = @($script:State.Components) + [pscustomobject]@{
                Name       = $Name
                Kind       = 'Capability'
                WasEnabled = $isInstalled
            }
            Save-State
        }

        if ($Enable) {
            Add-WindowsCapability -Online -Name $Name -ErrorAction Stop | Out-Null
        }
        else {
            Remove-WindowsCapability -Online -Name $Name -ErrorAction Stop | Out-Null
        }

        $check = Get-WindowsCapability -Online -Name $Name -ErrorAction Stop
        $nowInstalled = ([string]$check.State -eq 'Installed')
        if ($nowInstalled -ne $Enable) {
            throw "Verification failed: capability '$Name' is still $($check.State)."
        }
        Write-Log "Capability $(if ($Enable) { 'installed' } else { 'removed' }): $Name"
        if (-not $Enable) {
            Write-Log 'Note: reinstalling a capability later may require internet access or an installation source.'
        }
        return
    }

    throw "Component not found: '$Name'. Run '.\optimize.ps1 -Mode Components -ComponentShowAll' to see available names."
}

function Restore-Components {
    $remaining = @()
    foreach ($component in @($script:State.Components)) {
        try {
            if ($component.Kind -eq 'Feature') {
                if ($component.WasEnabled) {
                    Enable-WindowsOptionalFeature -Online -FeatureName $component.Name -All -NoRestart -ErrorAction Stop | Out-Null
                }
                else {
                    Disable-WindowsOptionalFeature -Online -FeatureName $component.Name -NoRestart -ErrorAction Stop | Out-Null
                }
                Write-Log "Feature state restored: $($component.Name)"
            }
            else {
                if ($component.WasEnabled) {
                    Add-WindowsCapability -Online -Name $component.Name -ErrorAction Stop | Out-Null
                }
                else {
                    Remove-WindowsCapability -Online -Name $component.Name -ErrorAction Stop | Out-Null
                }
                Write-Log "Capability state restored: $($component.Name)"
            }
        }
        catch {
            Write-Log "Could not restore component $($component.Name): $($_.Exception.Message)" 'WARN'
            $remaining += $component
        }
    }
    $script:State.Components = @($remaining)
    Save-State
}

function Invoke-ComponentsMode {
    if ($ComponentAction -eq 'List') {
        $components = @(Get-ComponentList)
        Show-ComponentsList -Components $components -ShowAll:$ComponentShowAll
        return
    }

    if ([string]::IsNullOrWhiteSpace($ComponentName)) {
        throw "-ComponentName is required for -ComponentAction $ComponentAction. Run '.\optimize.ps1 -Mode Components' to see component names."
    }

    Set-ComponentState -Name $ComponentName -Enable ($ComponentAction -eq 'Enable')
    Save-State
    Write-Log "Component action $ComponentAction completed for '$ComponentName'."
}

function Write-NativeCommandOutput {
    param([AllowNull()][array]$Lines)

    foreach ($line in @($Lines)) {
        $text = ([string]$line).TrimEnd()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        Write-Log $text
    }
}

function Invoke-RepairMode {
    Write-Log 'System file repair fixes corrupted Windows files; it cannot be rolled back (there is nothing harmful to undo).'

    switch ($RepairAction) {
        'Check' {
            Write-Log 'Running DISM CheckHealth (quick)...'
            $output = @(& dism.exe /Online /Cleanup-Image /CheckHealth)
            $exitCode = $LASTEXITCODE
            Write-NativeCommandOutput -Lines $output
            Write-Log "DISM CheckHealth exit code: $exitCode"
            if ($exitCode -ne 0) {
                Write-Log "DISM returned a non-zero exit code: $exitCode" 'WARN'
            }
            Write-Log "If the report says the component store is repairable, run: .\optimize.ps1 -Mode Repair -RepairAction Scan"
        }
        'Scan' {
            Write-Log 'Running DISM ScanHealth (can take several minutes)...'
            $output = @(& dism.exe /Online /Cleanup-Image /ScanHealth)
            $exitCode = $LASTEXITCODE
            Write-NativeCommandOutput -Lines $output
            Write-Log "DISM ScanHealth exit code: $exitCode"
            if ($exitCode -ne 0) {
                Write-Log "DISM returned a non-zero exit code: $exitCode" 'WARN'
            }
            Write-Log "If corruption was found, run: .\optimize.ps1 -Mode Repair -RepairAction Restore"
        }
        'Restore' {
            Write-Log 'Running DISM RestoreHealth (can take 10+ minutes)...'
            $output = @(& dism.exe /Online /Cleanup-Image /RestoreHealth)
            $exitCode = $LASTEXITCODE
            Write-NativeCommandOutput -Lines $output
            Write-Log "DISM RestoreHealth exit code: $exitCode"
            if ($exitCode -ne 0) {
                Write-Log "DISM returned a non-zero exit code: $exitCode" 'WARN'
            }

            Write-Log 'Running SFC scan (can take several minutes)...'
            $sfcOutput = @(& sfc.exe /scannow)
            $sfcExitCode = $LASTEXITCODE
            Write-NativeCommandOutput -Lines $sfcOutput
            Write-Log "SFC exit code: $sfcExitCode"
            Write-Log 'Repair pass finished. A restart is recommended.'
        }
    }
}

# ---------------------------------------------------------------------------
# Applied changes report
# ---------------------------------------------------------------------------

function New-AppliedChangesReport {
    $state = $script:State
    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        Steps = @($script:StepResults)
        Verification = @($script:VerifyResults)
        ReversibleChanges = [pscustomobject]@{
            RegistryValues = @($state.Registry | ForEach-Object { "$($_.Path)\$($_.Name)" })
            Services = @($state.Services | ForEach-Object { "$($_.Name) (was $($_.StartMode))" })
            Tasks = @($state.Tasks | ForEach-Object { $_.Path })
            PowerSettings = @($state.PowerSettings | ForEach-Object { "Setting $($_.Setting) in scheme $($_.Scheme) (AC was $($_.OriginalAc))" })
            OriginalPowerScheme = $state.OriginalPowerScheme
            CreatedPowerScheme = $state.CreatedPowerScheme
            HibernationWasEnabled = $state.HibernationWasEnabled
            TrimWasDisabled = $state.TrimWasDisabled
            MemoryCompressionWasEnabled = $state.MemoryCompressionWasEnabled
            DefenderScanCpuLoad = $state.DefenderScanCpuLoad
            DefenderExclusions = @($state.DefenderExclusions)
            NetChanges = @($state.NetChanges | ForEach-Object { "$($_.Kind) on $($_.Adapter) $($_.Keyword)".Trim() })
            StartupApproved = @($state.StartupApproved | ForEach-Object { $_.Name })
            StartupFolder = @($state.StartupFolder | ForEach-Object { $_.Name })
            Components = @($state.Components | ForEach-Object { "$($_.Name) [$($_.Kind)]" })
        }
        IrreversibleNotes = @(
            'Temp files and update caches deleted by Cleanup cannot be restored.',
            'Removed Appx packages, an uninstalled OneDrive client and winget-installed runtimes are not rolled back by this script.'
        )
        MeasurementGuidance = 'This script does not measure FPS or input latency and does not claim gains. To measure the real effect: capture frametimes with CapFrameX or PresentMon in a fixed game scene (60+ seconds) before and after changes, then compare average FPS and 1% lows.'
    }
}

function Show-AppliedChangesSummary {
    param([Parameter(Mandatory)][pscustomobject]$Report)

    $stepsOk = @($Report.Steps | Where-Object { $_.Status -eq 'OK' }).Count
    $stepsFailed = @($Report.Steps | Where-Object { $_.Status -ne 'OK' })
    $changes = $Report.ReversibleChanges

    Write-Host ''
    Write-Host '=== Applied changes summary ==='
    Write-Host ("Steps: {0} OK, {1} failed" -f $stepsOk, $stepsFailed.Count)
    foreach ($failed in $stepsFailed) {
        Write-Host ("  FAILED STEP: {0}" -f $failed.Step)
    }
    Write-Host ("Registry values: {0} | Services: {1} | Tasks: {2} | Power settings: {3}" -f $changes.RegistryValues.Count, $changes.Services.Count, $changes.Tasks.Count, $changes.PowerSettings.Count)
    Write-Host ("Startup changes: {0} | Components: {1} | Network changes: {2} | Defender exclusions: {3}" -f ($changes.StartupApproved.Count + $changes.StartupFolder.Count), $changes.Components.Count, $changes.NetChanges.Count, $changes.DefenderExclusions.Count)
    Write-Host 'All listed changes are recorded in state.json and can be undone via: .\optimize.ps1 -Mode Rollback'
}

function Save-AppliedChangesReport {
    param([Parameter(Mandatory)][pscustomobject]$Report)

    if (-not (Test-Path -LiteralPath $script:ReportsDir)) {
        New-Item -ItemType Directory -Path $script:ReportsDir -Force | Out-Null
    }
    $reportName = 'changes-{0}.json' -f (Get-Date).ToString('yyyyMMdd-HHmmss')
    $reportPath = Join-Path $script:ReportsDir $reportName
    $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding UTF8 -ErrorAction Stop
    return $reportPath
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$requiresElevation = $Mode -notin @('Report', 'Audit', 'WhatIf', 'Compare')
if ($Mode -eq 'Startup' -and $StartupAction -eq 'List') { $requiresElevation = $false }

if ($requiresElevation) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Apply, Rollback, Components and Repair require an elevated PowerShell session. Report, Audit, WhatIf and startup listing do not require administrator rights.'
    }

    if (-not (Test-Path -LiteralPath $script:StateDir)) {
        New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
    }
}

Write-Log "Started. Mode: $Mode"

if ($Preset -ne 'None') {
    $presetSkips = @()
    $presetOptIns = @()
    switch ($Preset) {
        'Minimal' {
            $presetSkips = @('SkipPower', 'SkipDevicePower', 'SkipNetwork', 'SkipNicTuning', 'SkipSystemServices', 'SkipMiscServices', 'SkipUpdaters', 'SkipTracing', 'SkipDefenderTuning', 'SkipEdgeTweaks', 'SkipVisualEffects', 'SkipAccessibility', 'SkipInterface', 'SkipCleanup', 'SkipRuntimes', 'SkipAppRemoval', 'SkipGraphics')
        }
        'Gaming' {
            $presetOptIns = @('DisableMouseAcceleration', 'DisableNagle', 'DisableSysMain')
        }
        'Full' {
            $presetOptIns = @('DisableMouseAcceleration', 'DisableNagle', 'DisableSysMain', 'DisableMemoryCompression', 'DisableSearchIndexing', 'DisableHibernation', 'DisableNotifications', 'TidyTaskbar', 'DisableLocation', 'DisableWirelessDisplay')
        }
    }
    foreach ($presetName in @($presetSkips + $presetOptIns)) {
        if (-not $PSBoundParameters.ContainsKey($presetName)) {
            Set-Variable -Name $presetName -Value $true -Scope Script
        }
    }
    Write-Log "Preset applied: $Preset. Parameters you passed explicitly take priority over the preset."
}

if ($Mode -eq 'Audit') {
    Write-AuditJsonReport
    return
}

if ($Mode -eq 'Report') {
    Show-SystemReport
    return
}

if ($Mode -eq 'Compare') {
    Invoke-CompareMode
    return
}

if ($Mode -eq 'WhatIf') {
    $script:State = New-State
}
else {
    $script:State = Get-State
}

if ($Mode -eq 'Startup') {
    Invoke-StartupMode
    return
}

if ($Mode -eq 'Components') {
    Invoke-ComponentsMode
    return
}

if ($Mode -eq 'Repair') {
    Invoke-RepairMode
    return
}

if ($Mode -eq 'Rollback') {
    $rollbackBackupPath = "$($script:StatePath).rollback.$([guid]::NewGuid().ToString('N')).bak"
    if (Test-Path -LiteralPath $script:StatePath) {
        Copy-Item -LiteralPath $script:StatePath -Destination $rollbackBackupPath -ErrorAction Stop
        Write-Log "Pre-rollback state backup created: $rollbackBackupPath"
    }

    Invoke-Step -Name 'Restore registry'          -Action { Restore-RegistryValues }
    Invoke-Step -Name 'Restore services'          -Action { Restore-Services }
    Invoke-Step -Name 'Restore power settings'    -Action { Restore-PowerSettings }
    Invoke-Step -Name 'Restore power plan'        -Action { Restore-PowerPlan }
    Invoke-Step -Name 'Restore memory compression'-Action { Restore-MemoryCompression }
    Invoke-Step -Name 'Restore hibernation'       -Action { Restore-Hibernation }
    Invoke-Step -Name 'Restore tasks'              -Action { Restore-Tasks }
    Invoke-Step -Name 'Restore startup entries'    -Action { Restore-StartupChanges }
    Invoke-Step -Name 'Restore components'         -Action { Restore-Components }
    Invoke-Step -Name 'Restore TRIM'               -Action { Restore-Trim }
    Invoke-Step -Name 'Restore network'            -Action { Restore-NetChanges }
    Invoke-Step -Name 'Restore Defender'           -Action { Restore-Defender }

    if ($script:RollbackHadWarnings) {
        Save-State
        Write-Log "Rollback was incomplete. Unrestored entries remain in state.json for a retry. Pre-rollback backup: $rollbackBackupPath" 'WARN'
    }
    else {
        if (Test-Path -LiteralPath $script:StatePath) {
            Remove-Item -LiteralPath $script:StatePath -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $rollbackBackupPath) {
            Remove-Item -LiteralPath $rollbackBackupPath -Force -ErrorAction SilentlyContinue
        }
        Write-Log 'Rollback finished successfully. Rollback state file removed.'
    }

    Write-Log 'Sign out or restart to apply restored settings.'
    Write-Log 'Cannot be undone: cleanup (temp files, update cache), removed apps, uninstalled OneDrive, installed runtimes.'
    return
}

$benchmarkBefore = $null
if ($Mode -eq 'Apply' -and -not $SkipBenchmark) {
    try {
        $benchmarkBefore = Get-BenchmarkSnapshot -Label 'Before'
        Write-Log 'Benchmark: baseline snapshot captured.'
    }
    catch {
        Write-Log "Benchmark: baseline snapshot failed: $($_.Exception.Message)" 'WARN'
    }
}

if (-not $SkipRestorePoint)  { Invoke-Step -Name 'Restore point'       -Action { New-SafetyRestorePoint } }
if (-not $SkipTelemetry)     { Invoke-Step -Name 'Telemetry'           -Action { Optimize-Telemetry }         -Verify { Test-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Expected 0 } }
if (-not $SkipBackgroundApps){ Invoke-Step -Name 'Background apps'     -Action { Optimize-BackgroundApps }    -Verify { Test-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsRunInBackground' -Expected 2 } }
if (-not $SkipPower)         { Invoke-Step -Name 'Power plan'          -Action { Enable-UltimatePerformance } -Verify { Test-PowerPlanApplied } }
if (-not $SkipDevicePower)   { Invoke-Step -Name 'Device power'        -Action { Optimize-DevicePower } }
if (-not $SkipNetwork)       { Invoke-Step -Name 'Network'             -Action { Optimize-Network }           -Verify { $v = Get-RegistryValueOrNull -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex'; ($null -ne $v) -and (($v -eq -1) -or ($v -eq 4294967295)) } }
if (-not $SkipUpdaters)      { Invoke-Step -Name 'Updater services'    -Action { Optimize-UpdaterServices } }
if (-not $SkipMiscServices)  { Invoke-Step -Name 'Misc services'      -Action { Optimize-MiscServices } }
if ($DisableLocation)        { Invoke-Step -Name 'Location service'    -Action { Optimize-LocationService } }
if ($DisableWirelessDisplay) { Invoke-Step -Name 'Wireless display'    -Action { Optimize-WirelessDisplay } }
if (-not $SkipTracing)       { Invoke-Step -Name 'Trace sessions'      -Action { Optimize-TracingSessions } }
if ($EnableGpuMsi)           { Invoke-Step -Name 'GPU MSI mode'        -Action { Optimize-GpuMsi } }
if ($DisableMouseAcceleration){ Invoke-Step -Name 'Mouse acceleration' -Action { Optimize-MouseAcceleration } -Verify { Test-MouseAccelerationDisabled } }
if ($DisableNagle)           { Invoke-Step -Name 'Nagle algorithm off' -Action { Optimize-NagleOff }          -Verify { Test-NagleDisabled } }
if ($DisableMemoryIntegrity) { Invoke-Step -Name 'Memory Integrity'    -Action { Optimize-MemoryIntegrity } }
if ($FixedPagefile)          { Invoke-Step -Name 'Paging file'         -Action { Optimize-Pagefile } }
if ($DisableSysMain)         { Invoke-Step -Name 'SysMain'             -Action { Optimize-SysMain }           -Verify { Test-SysMainDisabled } }
if ($DisableMemoryCompression){ Invoke-Step -Name 'Memory compression' -Action { Optimize-MemoryCompression } -Verify { Test-MemoryCompressionDisabled } }
if (-not $SkipGraphics)      { Invoke-Step -Name 'Graphics and Game Mode' -Action { Optimize-Graphics } }
if (-not $SkipGameDvr)       { Invoke-Step -Name 'Game DVR'            -Action { Optimize-GameDvr }           -Verify { Test-GameDvrDisabled } }
if (-not $SkipVisualEffects) { Invoke-Step -Name 'Visual effects'      -Action { Optimize-VisualEffects } }
if (-not $SkipAccessibility) { Invoke-Step -Name 'Accessibility keys' -Action { Optimize-Accessibility } }
if (-not $SkipSuggestions)   { Invoke-Step -Name 'Tips and ads'       -Action { Optimize-Suggestions } }
if (-not $SkipInterface)     { Invoke-Step -Name 'Widgets, clipboard'  -Action { Optimize-Interface } }
if (-not $SkipSystemServices){ Invoke-Step -Name 'System services'    -Action { Optimize-SystemServices } }
if ($DisableNotifications)   { Invoke-Step -Name 'Notifications'       -Action { Optimize-Notifications } }
if ($DisableHibernation)     { Invoke-Step -Name 'Hibernation'         -Action { Optimize-Hibernation } }
if ($TidyTaskbar)            { Invoke-Step -Name 'Taskbar layout'      -Action { Optimize-TaskbarLayout } }
if ($DisableSearchIndexing)  { Invoke-Step -Name 'Search indexing'     -Action { Optimize-SearchIndexing }    -Verify { $s = Get-Service -Name 'WSearch' -ErrorAction SilentlyContinue; (-not $s) -or ($s.StartType -eq 'Disabled') } }
if ($ManualUpdates)          { Invoke-Step -Name 'Manual updates'      -Action { Optimize-ManualUpdates }     -Verify { Test-RegistryDwordValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Expected 2 } }
if (-not $SkipDefenderTuning){ Invoke-Step -Name 'Defender tuning'    -Action { Optimize-Defender } }
if (-not $SkipEdgeTweaks)    { Invoke-Step -Name 'Edge policies'       -Action { Optimize-Edge } }
if ($RemoveOneDrive)         { Invoke-Step -Name 'OneDrive'            -Action { Remove-OneDriveClient } }
if ($RemoveApps -and -not $SkipAppRemoval) { Invoke-Step -Name 'App removal'       -Action { Optimize-AppRemoval } }
if ($InstallRuntimes -and -not $SkipRuntimes) { Invoke-Step -Name 'Runtimes (winget)' -Action { Optimize-Runtimes } }
if (-not $SkipNicTuning)     { Invoke-Step -Name 'Network adapters'    -Action { Optimize-NetworkAdapters } }
if ($RunCleanup -and -not $SkipCleanup) { Invoke-Step -Name 'Cleanup'             -Action { Optimize-Cleanup } }
if (-not $SkipDisk)          { Invoke-Step -Name 'Disk maintenance'    -Action { Optimize-Disk } }

if ($Mode -eq 'WhatIf') {
    if ($RestartExplorer) {
        Invoke-Step -Name 'Restart shell' -Action { Restart-ExplorerShell }
    }
    Write-Host ("Preview complete. {0} selected step(s); no system settings or rollback files were changed." -f $script:WhatIfStepCount)
    return
}

Save-State

if ($RestartExplorer) {
    Invoke-Step -Name 'Restart shell' -Action { Restart-ExplorerShell }
}

if ($Mode -eq 'Apply' -and -not $SkipBenchmark -and $benchmarkBefore) {
    try {
        $benchmarkAfter = Get-BenchmarkSnapshot -Label 'After'
        $benchmarkComparison = [pscustomobject]@{
            GeneratedAt = (Get-Date).ToString('o')
            Before      = $benchmarkBefore
            After       = $benchmarkAfter
            Comparisons = @(Compare-BenchmarkSnapshots -Before $benchmarkBefore -After $benchmarkAfter)
        }
        Show-BenchmarkComparison -Comparison $benchmarkComparison
        $benchmarkReportPath = Save-BenchmarkReport -Comparison $benchmarkComparison
        Write-Log "Benchmark comparison saved: $benchmarkReportPath"
    }
    catch {
        Write-Log "Benchmark: after-snapshot or comparison failed: $($_.Exception.Message)" 'WARN'
    }
}

if ($Mode -eq 'Apply' -and $script:VerifyResults.Count -gt 0) {
    $verifiedOk = @($script:VerifyResults | Where-Object { $_.Status -eq 'OK' }).Count
    $verifyFailed = @($script:VerifyResults | Where-Object { $_.Status -ne 'OK' })
    Write-Host ''
    Write-Host ("=== Verification: {0}/{1} checked step(s) confirmed ===" -f $verifiedOk, $script:VerifyResults.Count)
    foreach ($result in $verifyFailed) {
        Write-Host ("  NOT VERIFIED: {0} ({1})" -f $result.Step, $result.Status)
    }
    Write-Host 'Only steps with built-in checks are counted here; other steps are logged but not auto-verified.'
}

if ($Mode -eq 'Apply') {
    try {
        $changesReport = New-AppliedChangesReport
        Show-AppliedChangesSummary -Report $changesReport
        $changesReportPath = Save-AppliedChangesReport -Report $changesReport
        Write-Log "Applied changes report saved: $changesReportPath"
    }
    catch {
        Write-Log "Could not build the applied changes report: $($_.Exception.Message)" 'WARN'
    }

    Write-Host ''
    Write-Host '=== Measuring the real effect ==='
    Write-Host 'This script does not measure FPS or input latency and does not claim gains.'
    Write-Host 'To measure: capture frametimes with CapFrameX or PresentMon in the same game scene (60+ seconds) before and after changes; compare average FPS and 1% lows.'
}

Write-Log 'Done. Restart your PC to apply all changes.'
Write-Log "To undo: .\optimize.ps1 -Mode Rollback    (log: $script:LogPath)"