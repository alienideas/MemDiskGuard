#Requires -RunAsAdministrator
# Offline Memory & Disk Hijacking Spyware / Malware Scanner
# For Windows 10 & 11 - Fully Offline
# Detects processes causing high RAM (90%+) or 100% Disk usage, memory injection indicators, and common resource-hungry malware

$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "Memory & Disk Hijack Scanner - Windows 10/11"

function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Color "ERROR: Run this script as Administrator!" "Red"
    Write-Color "Right-click PowerShell → Run as administrator" "Yellow"
    pause
    exit
}

Clear-Host
Write-Color "==============================================================" "Cyan"
Write-Color "   MEMORY & DISK HIJACKING SPYWARE / MALWARE SCANNER" "Cyan"
Write-Color "          Windows 10 & 11 - Fully Offline" "Cyan"
Write-Color "==============================================================" "Cyan"
Write-Host ""
Write-Color "This tool looks for processes that may be:" "Yellow"
Write-Color "  • Consuming 90%+ RAM or causing high memory pressure" "Yellow"
Write-Color "  • Causing 100% Disk usage" "Yellow"
Write-Color "  • Injecting into other processes / memory hijacking" "Yellow"
Write-Color "  • Crypto miners, spyware, or resource-abusive malware" "Yellow"
Write-Host ""
Write-Color "WARNING: Heuristic only. False positives possible. Create a System Restore Point first!" "Magenta"
Write-Host ""

$continue = Read-Host "Continue with the scan? (Y/N)"
if ($continue -notmatch '^[Yy]') { exit }

# ==================== KNOWN BAD / MINER / MEMORY HOG NAMES ====================
$KnownBad = @(
    # Crypto miners
    "xmrig","minerd","cpuminer","nicehash","ethminer","claymore","phoenixminer",
    "nbminer","gminer","t-rex","lolminer","teamredminer","cryptonight","monero",
    "miner","coinminer","cryptominer","hashrate","stratum",
    # Common spyware / adware / hijackers
    "spyware","keylogger","logger","monitor","stealer","rat","backdoor",
    "searchprotect","conduit","genieo","dealply","babylon","yontoo","opencandy",
    "installcore","superfish","coupon","toolbar","websearch","optimizer","cleanerpro",
    "speedup","boost","driverupdater","pcoptimize","registryfix",
    # Generic suspicious
    "systemupdate","browserupdate","chromeupdate","softwareupdate","updater",
    "helper","assistant","servicehost","svch0st","lssas","csrsss","winlogon"
)

$SuspiciousPaths = @(
    "\\Temp\\","\\AppData\\Local\\Temp\\","\\AppData\\Roaming\\","\\AppData\\Local\\",
    "\\Users\\Public\\","\\ProgramData\\","\\Windows\\Temp\\","\\Downloads\\","\\Desktop\\"
)

$Findings = [System.Collections.Generic.List[object]]::new()
$IdCounter = 0

function Add-Finding {
    param(
        [string]$Type,
        [string]$Name,
        [string]$Path,
        [string]$Details,
        [string]$ActionTarget,
        [long]$MemoryMB = 0
    )
    $script:IdCounter++
    $script:Findings.Add([PSCustomObject]@{
        ID           = $script:IdCounter
        Type         = $Type
        Name         = $Name
        Path         = $Path
        Details      = $Details
        ActionTarget = $ActionTarget
        MemoryMB     = $MemoryMB
    })
}

# ==================== 1. SYSTEM MEMORY OVERVIEW ====================
Write-Color "`n[1/7] Checking overall system memory..." "Green"

$os = Get-CimInstance Win32_OperatingSystem
$totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
$freeRAM  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$usedRAM  = $totalRAM - $freeRAM
$pctUsed  = [math]::Round(($usedRAM / $totalRAM) * 100, 1)

Write-Color "  Total RAM : $totalRAM GB" "White"
Write-Color "  Used RAM  : $usedRAM GB  ($pctUsed %)" $(if ($pctUsed -ge 85) {"Red"} else {"Green"})
Write-Color "  Free RAM  : $freeRAM GB" "White"

if ($pctUsed -ge 90) {
    Write-Color "  >>> HIGH MEMORY PRESSURE DETECTED (>= 90%) <<<" "Red"
}

# ==================== 2. TOP MEMORY CONSUMERS ====================
Write-Color "`n[2/7] Analyzing top memory-consuming processes..." "Green"

$processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 0 } | 
    Sort-Object WorkingSet64 -Descending

$topN = $processes | Select-Object -First 25

foreach ($p in $topN) {
    $memMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
    $path  = $p.Path
    if (-not $path) { $path = "(path not available - may be protected)" }

    $isSus = $false
    $reasons = @()

    # High absolute memory
    if ($memMB -gt 800) {
        $isSus = $true
        $reasons += "High memory usage ($memMB MB)"
    }

    # Known bad names
    foreach ($bad in $KnownBad) {
        if ($p.ProcessName -match $bad -or ($path -and $path -match $bad)) {
            $isSus = $true
            $reasons += "Matches known miner/spyware pattern: $bad"
            break
        }
    }

    # Suspicious location
    if ($path) {
        foreach ($pat in $SuspiciousPaths) {
            if ($path -like "*$pat*") {
                $isSus = $true
                $reasons += "Running from suspicious folder"
                break
            }
        }
        # Outside normal locations
        if ($path -notmatch "System32|SysWOW64|Program Files|Windows\\") {
            $isSus = $true
            $reasons += "Unusual process location"
        }
    }

    # Very high thread count (possible injection / miner)
    if ($p.Threads.Count -gt 80) {
        $isSus = $true
        $reasons += "Unusually high thread count ($($p.Threads.Count))"
    }

    if ($isSus -or $memMB -gt 500) {
        $detail = ($reasons -join " | ")
        if (-not $detail) { $detail = "High memory consumer - review recommended" }
        Add-Finding -Type "High Memory Process" -Name $p.ProcessName -Path $path `
            -Details $detail -ActionTarget $p.Id -MemoryMB $memMB
    }
}

# ==================== 3. PROCESSES WITH POSSIBLE MEMORY INJECTION ====================
Write-Color "[3/7] Checking for possible memory injection / hijacking indicators..." "Green"

# Look for processes that have modules from unusual locations or many modules
foreach ($p in $processes | Select-Object -First 40) {
    try {
        $mods = $p.Modules
        if ($mods.Count -gt 120) {
            Add-Finding -Type "Possible Injection" -Name $p.ProcessName -Path $p.Path `
                -Details "Extremely high module count ($($mods.Count)) - possible DLL injection" `
                -ActionTarget $p.Id -MemoryMB ([math]::Round($p.WorkingSet64/1MB,1))
        }

        # Check for modules loaded from Temp / AppData
        $badMods = $mods | Where-Object {
            $_.FileName -match "\\Temp\\|\\AppData\\|\\Users\\Public\\" -and
            $_.FileName -match "\.dll$"
        }
        if ($badMods) {
            $modList = ($badMods | Select-Object -First 3 | ForEach-Object { Split-Path $_.FileName -Leaf }) -join ", "
            Add-Finding -Type "Suspicious Module" -Name $p.ProcessName -Path $p.Path `
                -Details "DLL(s) loaded from Temp/AppData: $modList" `
                -ActionTarget $p.Id -MemoryMB ([math]::Round($p.WorkingSet64/1MB,1))
        }
    } catch {}
}

# ==================== 4. DISK USAGE INDICATORS ====================
Write-Color "[4/7] Checking for high disk activity indicators..." "Green"

# Current disk queue (simple snapshot)
try {
    $disk = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'"
    if ($disk) {
        $queue = $disk.CurrentDiskQueueLength
        $busy  = $disk.PercentDiskTime
        Write-Color "  Disk Queue Length : $queue" $(if ($queue -gt 5) {"Red"} else {"Green"})
        Write-Color "  % Disk Time       : $busy %" $(if ($busy -gt 80) {"Red"} else {"Green"})

        if ($queue -gt 8 -or $busy -gt 90) {
            Write-Color "  >>> POSSIBLE HIGH DISK USAGE DETECTED <<<" "Red"
        }
    }
} catch {
    Write-Color "  (Could not read live disk counters)" "DarkGray"
}

# Processes known for high disk I/O or that often cause 100% disk
$diskHogs = @("SearchIndexer","MsMpEng","Antivirus","WmiPrvSE","System","Registry",
              "svchost","dllhost","RuntimeBroker","SearchApp","YourPhone","OneDrive")

# Flag non-Microsoft processes with high memory that could also hammer disk
foreach ($p in $processes | Where-Object { $_.WorkingSet64 -gt 200MB } | Select-Object -First 15) {
    $name = $p.ProcessName
    if ($name -match "SearchIndexer|MsMpEng|Antimalware|SmartScreen") { continue }  # known system

    $path = $p.Path
    $isSusDisk = $false
    $reason = ""

    foreach ($bad in $KnownBad) {
        if ($name -match $bad) {
            $isSusDisk = $true
            $reason = "Known bad name + high resources (possible disk + CPU miner/spyware)"
            break
        }
    }
    if ($path -and ($path -match "\\Temp\\|\\AppData\\|\\Public\\")) {
        $isSusDisk = $true
        $reason = "High-resource process from Temp/AppData (common for disk-abusive malware)"
    }

    if ($isSusDisk) {
        Add-Finding -Type "Possible Disk Hog" -Name $name -Path $path `
            -Details $reason -ActionTarget $p.Id -MemoryMB ([math]::Round($p.WorkingSet64/1MB,1))
    }
}

# ==================== 5. SCHEDULED TASKS & SERVICES THAT MAY CAUSE HIGH USAGE ====================
Write-Color "[5/7] Scanning Scheduled Tasks for resource-abusive entries..." "Green"

Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
    $task = $_
    $actions = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join " "
    $isSus = $false
    $reason = ""

    foreach ($bad in $KnownBad) {
        if ($task.TaskName -match $bad -or $actions -match $bad) {
            $isSus = $true
            $reason = "Matches miner/spyware pattern: $bad"
            break
        }
    }
    if (-not $isSus) {
        foreach ($pat in $SuspiciousPaths) {
            if ($actions -like "*$pat*") {
                $isSus = $true
                $reason = "Runs from suspicious location (can cause high CPU/Disk on schedule)"
                break
            }
        }
    }
    if ($isSus) {
        Add-Finding -Type "Suspicious Task" -Name $task.TaskName -Path $task.TaskPath `
            -Details "$reason | $actions" -ActionTarget $task.TaskName
    }
}

Write-Color "[6/7] Scanning Services..." "Green"

Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" } | ForEach-Object {
    $svc = $_
    $isSus = $false
    $reason = ""

    foreach ($bad in $KnownBad) {
        if ($svc.Name -match $bad -or $svc.DisplayName -match $bad -or $svc.PathName -match $bad) {
            $isSus = $true
            $reason = "Matches known bad pattern: $bad"
            break
        }
    }
    if (-not $isSus -and $svc.PathName) {
        foreach ($pat in $SuspiciousPaths) {
            if ($svc.PathName -like "*$pat*") {
                $isSus = $true
                $reason = "Service binary in suspicious folder"
                break
            }
        }
    }
    if ($isSus) {
        Add-Finding -Type "Suspicious Service" -Name $svc.Name -Path $svc.PathName `
            -Details "$reason | $($svc.DisplayName)" -ActionTarget $svc.Name
    }
}

# ==================== 7. REGISTRY RUN KEYS (startup memory hogs) ====================
Write-Color "[7/7] Checking startup Registry entries..." "Green"

$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($reg in $RegPaths) {
    if (Test-Path $reg) {
        $props = Get-ItemProperty $reg
        $props.PSObject.Properties | Where-Object {
            $_.Name -notin "PSPath","PSParentPath","PSChildName","PSDrive","PSProvider"
        } | ForEach-Object {
            $val = $_.Value
            $isSus = $false
            $reason = ""
            foreach ($bad in $KnownBad) {
                if ($_.Name -match $bad -or $val -match $bad) {
                    $isSus = $true
                    $reason = "Matches known pattern: $bad"
                    break
                }
            }
            if (-not $isSus) {
                foreach ($pat in $SuspiciousPaths) {
                    if ($val -like "*$pat*") {
                        $isSus = $true
                        $reason = "Starts from suspicious location (can cause high RAM/Disk at login)"
                        break
                    }
                }
            }
            if ($isSus) {
                Add-Finding -Type "Startup Registry" -Name $_.Name -Path $reg `
                    -Details "$reason | $val" -ActionTarget "$reg|$($_.Name)"
            }
        }
    }
}

# ==================== RESULTS ====================
Write-Host ""
Write-Color "==================== SCAN RESULTS ====================" "Cyan"
Write-Host ""

if ($Findings.Count -eq 0) {
    Write-Color "No strong indicators of memory/disk hijacking malware found." "Green"
    Write-Color "If you still have 90%+ RAM or 100% Disk:" "Yellow"
    Write-Color "  • Open Task Manager → Performance → open Resource Monitor" "Yellow"
    Write-Color "  • Check 'Disk' and 'Memory' tabs for the real culprit" "Yellow"
    Write-Color "  • Run Windows Memory Diagnostic or check for failing hardware" "Yellow"
    pause
    exit
}

Write-Color "Found $($Findings.Count) suspicious item(s) related to high memory / disk / possible hijacking:`n" "Yellow"

# Show summary table
$Findings | Sort-Object MemoryMB -Descending | Format-Table -Property ID, Type, Name, @{
    Label = "RAM (MB)"; Expression = { if ($_.MemoryMB) { $_.MemoryMB } else { "-" } }
}, Path -AutoSize -Wrap

Write-Host ""
Write-Color "Detailed view:" "Cyan"
foreach ($f in $Findings | Sort-Object MemoryMB -Descending) {
    Write-Color "--------------------------------------------------" "DarkGray"
    Write-Color "[$($f.ID)] $($f.Type)  -  $($f.Name)" "White"
    if ($f.MemoryMB -gt 0) { Write-Color "    Memory   : $($f.MemoryMB) MB" "Magenta" }
    Write-Color "    Path     : $($f.Path)" "Gray"
    Write-Color "    Details  : $($f.Details)" "Yellow"
}

Write-Host ""
Write-Color "==============================================================" "Cyan"
Write-Color "OPTIONS:" "White"
Write-Color "  • Enter numbers (e.g. 1,4,7) to kill/remove selected items" "White"
Write-Color "  • Type ALL to process everything listed" "White"
Write-Color "  • Type N or press Enter to exit without changes" "White"
Write-Color "==============================================================" "Cyan"
Write-Host ""

$choice = Read-Host "Your choice"

if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^[Nn]') {
    Write-Color "No changes made." "Yellow"
    exit
}

$toRemove = @()
if ($choice -match '^[Aa][Ll][Ll]$') {
    $toRemove = $Findings
} else {
    $ids = $choice -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    $toRemove = $Findings | Where-Object { $ids -contains $_.ID.ToString() }
}

if ($toRemove.Count -eq 0) {
    Write-Color "No valid items selected." "Yellow"
    exit
}

Write-Host ""
Write-Color "Selected for action:" "Yellow"
$toRemove | ForEach-Object { Write-Host "  [$($_.ID)] $($_.Type) - $($_.Name)" }
Write-Host ""
$confirm = Read-Host "Type YES to confirm (kills processes / removes entries)"

if ($confirm -ne "YES") {
    Write-Color "Cancelled." "Yellow"
    exit
}

Write-Host ""
Write-Color "Processing..." "Magenta"

foreach ($item in $toRemove) {
    Write-Host ""
    Write-Color "→ [$($item.ID)] $($item.Type) - $($item.Name)" "Cyan"
    try {
        switch -Wildcard ($item.Type) {
            "*Process*" {
                $pid = [int]$item.ActionTarget
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid -Force
                    Write-Color "  Process killed." "Green"
                    Start-Sleep -Milliseconds 800
                    if ($item.Path -and (Test-Path $item.Path) -and $item.Path -notmatch "System32|SysWOW64") {
                        try {
                            Remove-Item -Path $item.Path -Force -ErrorAction Stop
                            Write-Color "  File deleted: $($item.Path)" "Green"
                        } catch {
                            Write-Color "  Could not delete file (in use or protected): $($item.Path)" "Yellow"
                        }
                    }
                } else {
                    Write-Color "  Process already gone." "DarkGray"
                }
            }
            "*Module*" {
                $pid = [int]$item.ActionTarget
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                Write-Color "  Host process killed (injected modules removed from memory)." "Green"
            }
            "*Task*" {
                Unregister-ScheduledTask -TaskName $item.ActionTarget -Confirm:$false -ErrorAction Stop
                Write-Color "  Scheduled Task removed." "Green"
            }
            "*Service*" {
                Stop-Service -Name $item.ActionTarget -Force -ErrorAction SilentlyContinue
                Set-Service -Name $item.ActionTarget -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Color "  Service stopped and disabled." "Green"
            }
            "*Registry*" {
                $parts = $item.ActionTarget -split '\|'
                Remove-ItemProperty -Path $parts[0] -Name $parts[1] -Force -ErrorAction Stop
                Write-Color "  Registry startup entry removed." "Green"
            }
            default {
                Write-Color "  No automatic action defined for this type." "Yellow"
            }
        }
    } catch {
        Write-Color "  ERROR: $($_.Exception.Message)" "Red"
    }
}

Write-Host ""
Write-Color "==============================================================" "Cyan"
Write-Color "Done. Restart your PC and check Task Manager / Resource Monitor." "Green"
Write-Color "If high memory/disk persists, the cause may be hardware, drivers," "Yellow"
Write-Color "or a more advanced rootkit (consider offline Defender scan)." "Yellow"
Write-Color "==============================================================" "Cyan"
Write-Host ""
pause
