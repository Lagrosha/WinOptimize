# WinOptimize

**English** | [Русский](README.ru.md)

An evidence-based Windows optimization toolkit built as a single PowerShell script (`optimize.ps1`).
It audits, explains, optimizes — and can undo every change it makes.

> **Core rule:** no blind tweaks. Every optimization is measured, verified after application, and reversible.
>
> **In short:** audit → preview → apply → restart → measure → undo anytime.

## 1. Overview & Philosophy

WinOptimize is designed around three principles:

- **Diagnostics before changes.** The Audit engine collects a full, fact-based snapshot of the system (OS, CPU, GPU, RAM, disks, network, services, registry, power, startup, pending reboots) before anything is modified. Snapshot format: `SchemaVersion 11`.
- **Every change is reversible.** Before any value is modified, its original state is written to `state.json`. The Rollback mode restores the system exactly to what was recorded — no guessing, no "defaults".
- **No unverifiable claims.** The script never promises FPS or input-latency improvements. Instead it measures what it can (CPU load, memory, disk, ping) before and after, and tells you exactly how to measure gaming performance yourself with proper tools.

What it deliberately does **not** do: mass "debloating", undocumented registry magic, driver/firmware changes, or anything that cannot be rolled back automatically.

## 2. Key Features & Modules

### Audit & Rule Evaluator

A read-only deep audit with **19 automatic diagnostic rules**, each producing a finding with evidence, confidence notes, and a way to verify the fix:

| Area | Rules |
|---|---|
| System | `SYS-REBOOT-MARKER` |
| CPU / RAM | `CPU-HIGH-LOAD-SAMPLE`, `RAM-MEMORY-PRESSURE`, `RAM-XMP-DISABLED` |
| Disk | `DISK-LOW-FREE-SPACE`, `DISK-HEALTH`, `DISK-TRIM-DISABLED` |
| Network | `NET-ICMP-TIMEOUT`, `NET-WIFI-WEAK-SIGNAL` |
| Power | `PWR-PCIE-ASPM-ENABLED`, `PWR-USB-SELECTIVE-SUSPEND-ENABLED`, `PWR-CPU-BOOST-DISABLED` |
| Services | `SVC-DIAGTRACK-RUNNING`, `SVC-SYSMAIN-SSD` |
| Startup | `STARTUP-COUNT-HIGH` |
| GPU / Gaming | `GPU-NO-HIGH-PERF-APPS`, `GPU-DRIVER-OLD`, `GAME-MODE-DISABLED` |
| Security | `SEC-HVCI-ENABLED` |

All findings are informational; nothing is ever auto-fixed during an audit.

### Optimization Presets

Presets replace long lists of manual flags. Parameters you pass explicitly always override the preset.

| Preset | Contents |
|---|---|
| `Minimal` | Soft, safe tweaks only: telemetry, background apps, Game DVR, tips/ads, disk maintenance |
| `Gaming` | The full default step set + mouse acceleration off, `-DisableNagle`, SysMain |
| `Full` | Gaming + memory compression, search indexing, hibernation, notifications, taskbar layout, location, wireless display |

Irreversible operations (app removal, cleanup, OneDrive uninstall, runtime installation) are **never** included in any preset — they always require their explicit flags.

### Network Optimization

Optional `-DisableNagle` step: sets `TcpAckFrequency=1`, `TCPNoDelay=1`, `TcpDelAckTicks=0` on every active physical adapter. Original values are backed up for rollback, and the change is verified after application. The effect is measurable via the built-in ping/jitter benchmark.

### Reporting

- **JSON** audit report — the complete machine-readable snapshot.
- **HTML** audit report (`audit-*.html`) — same data in a clean, dark-themed, human-readable page.
- **Applied-changes report** (`changes-*.json`) — everything Apply changed, with original values and per-step results.
- **Console summaries** at the end of every run: benchmark diff, verification results, applied-changes overview.

### Benchmark & Tracking

- Every Apply run captures a metric snapshot (CPU load, RAM, disk free space, ping latency/loss, active power scheme) **before** the first change and **after** the last one, then prints a comparison with noise thresholds — small random fluctuations are reported as "no significant change", not as improvements.
- `-Mode Compare` compares the current system state against the saved baseline and shows the full history of all saved baselines.

### Verification

After each key step, Apply re-reads the setting and confirms the value actually took effect. **11 verified steps:** Telemetry, Background apps, Power plan, SysMain, Memory compression, Game DVR, Mouse acceleration, Nagle, Network throttling, Search indexing, Manual updates. Failures are logged as warnings and listed in the final summary.

## 3. Execution Modes

| Mode | Purpose | Admin required | Writes to disk |
|---|---|---|---|
| `Report` | Quick human-readable system overview in the console (default mode) | No | No |
| `Audit` | Full audit snapshot + rule evaluation, saves JSON + HTML | No | Reports folder only |
| `WhatIf` | Dry-run: shows exactly which steps *would* run, with descriptions | No | No |
| `Apply` | Applies the selected optimizations with backups, verification and benchmarking | **Yes** | Yes (state, log, reports) |
| `Compare` | Compares current metrics against the saved Apply baseline + history | No | No |
| `Rollback` | Restores every recorded original value from `state.json` | **Yes** | Yes |
| `Startup` | Lists startup entries (registry, folder, logon tasks) with publisher info; `-StartupAction Disable/Enable -StartupName X` manages them reversibly | Only for changes | Only for changes |
| `Components` | Lists/enables/disables Windows optional features and capabilities with rollback (`-ComponentAction`, `-ComponentName`) | **Yes** | Yes |
| `Repair` | DISM `CheckHealth` / `ScanHealth` / `RestoreHealth` (+ SFC) via `-RepairAction` | **Yes** | Log only |

## 4. Quick Start / Usage Examples

### After downloading

1. Get the files: `git clone https://github.com/Lagrosha/WinOptimize.git` — or download just `optimize.ps1` from this page.
2. Open **Windows PowerShell** (version 5.1+, built into Windows 10/11).
3. Go to the folder with the script: `cd C:\path\to\WinOptimize`.
4. If PowerShell blocks the script, allow local scripts for your user once: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` — or run it with `powershell -ExecutionPolicy Bypass -File .\optimize.ps1` instead.
5. First runs are safe and read-only: try `-Mode Report`, then `-Mode Audit`, then `-Mode WhatIf -Preset Gaming`. None of them change the system or require administrator rights.
6. Only when you are satisfied with the preview, open an **elevated** PowerShell (Run as administrator) and run Apply or Rollback.

### The typical workflow (what to run, when and why)

1. **Report** — `.\optimize.ps1` — a quick console overview of the system. Safe, changes nothing. *When: the very first launch.*
2. **Audit** — `.\optimize.ps1 -Mode Audit` — deep diagnostics with 19 rules; saves JSON + HTML reports. *When: right after Report, to see what is actually suboptimal.*
3. **WhatIf** — `.\optimize.ps1 -Mode WhatIf -Preset Gaming` — lists every step that would be applied, with plain descriptions. Changes nothing. *When: before any Apply run.*
4. **Apply** — `.\optimize.ps1 -Mode Apply -Preset Gaming` *(elevated)* — applies the preset with backups, per-step verification and a before/after benchmark. *When: the preview looks right to you.*
5. **Restart the PC** — many changes only take effect after a reboot.
6. **Compare** — `.\optimize.ps1 -Mode Compare` — compares current metrics with the baseline taken before Apply. *When: after the reboot, or any time later.*
7. **Audit again** — confirm the findings you cared about are gone.
8. **Rollback** — `.\optimize.ps1 -Mode Rollback` *(elevated)* — restores every recorded original value. *When: something feels wrong, or you simply want everything back.*

Any time, independently of the workflow:
- `Startup` / `Components` — manage autostart entries and Windows components.
- `Repair` — if you suspect corrupted system files (or an audit points at servicing issues).

```powershell
# Preview what would happen — nothing is changed
.\optimize.ps1 -Mode WhatIf -Preset Gaming

# Full read-only audit with 19 diagnostic rules (JSON + HTML report)
.\optimize.ps1 -Mode Audit

# Apply the Gaming preset (elevated PowerShell required)
.\optimize.ps1 -Mode Apply -Preset Gaming

# Compare current state with the baseline taken before Apply (e.g. after a reboot)
.\optimize.ps1 -Mode Compare

# Undo every recorded change
.\optimize.ps1 -Mode Rollback
```

More examples:

```powershell
# Manage startup entries
.\optimize.ps1 -Mode Startup
.\optimize.ps1 -Mode Startup -StartupAction Disable -StartupName 'OneDrive'

# Windows components
.\optimize.ps1 -Mode Components -ComponentShowAll
.\optimize.ps1 -Mode Components -ComponentAction Disable -ComponentName 'Printing-XPSServices-Features'

# System file repair (progressive levels)
.\optimize.ps1 -Mode Repair                          # quick check
.\optimize.ps1 -Mode Repair -RepairAction Restore    # full DISM + SFC pass
```

## 5. Safety, Reversibility & Storage Paths

### `%ProgramData%\WinOptimize\` (machine-wide, written only by changing modes)

| Path | Purpose |
|---|---|
| `state.json` | The rollback database: every original value before modification |
| `optimize.log` | Timestamped log of all Apply/Rollback operations |
| `benchmarks\benchmark-*.json` | Before/after metric snapshots used by Compare |
| `reports\changes-*.json` | Applied-changes reports |

### `%LOCALAPPDATA%\WinOptimize\Reports\` (per-user, written by Audit)

| Path | Purpose |
|---|---|
| `audit-*.json` | Full audit snapshot (schema v11) |
| `audit-*.html` | The same audit as a readable dark-themed page |

### How `state.json` guarantees a 1:1 rollback

1. **Before** a value is changed, its original data (registry value + type + existence flag, service start mode, task state, power indexes, startup bytes, component state, ...) is appended to `state.json` — which is saved **atomically** (temp file + `File.Replace`, so a crash can never corrupt it).
2. `Rollback` replays the recorded originals, entry by entry. Entries that fail to restore **stay in the file** so a later Rollback can retry them; a pre-rollback backup copy of the state is created automatically. The state file is deleted only when every entry was restored cleanly.
3. If `state.json` is unreadable or corrupted, the script **refuses to continue** rather than silently losing your rollback data.

Operations that are inherently irreversible (deleting temp files, removing Appx packages, uninstalling OneDrive, installing runtimes) are clearly listed in the log, in the final report, and are never part of a preset.

## Requirements

- Windows 10/11, Windows PowerShell 5.1+ (no PowerShell 7-only syntax is used).
- Elevated console only for `Apply`, `Rollback`, `Components`, `Repair` and startup changes.

## Measuring the real effect

WinOptimize does not measure FPS or input latency and does not claim gains. To measure the actual effect on games: capture frametimes with **CapFrameX** or **PresentMon** in the same game scene (60+ seconds) before and after applying changes, then compare average FPS and 1% lows.
