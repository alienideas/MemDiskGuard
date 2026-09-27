# MemDiskGuard

### Offline High RAM & 100% Disk Usage Malware Scanner for Windows 10/11

**Detect and remove spyware, crypto miners, and memory-hijacking malware that cause 90%+ RAM usage or 100% disk usage — completely offline.**

[![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-blue?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)](https://docs.microsoft.com/powershell)
[![Offline](https://img.shields.io/badge/Works-Fully%20Offline-success?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](#license)

---

## Why MemDiskGuard?

Many users face these common problems:

- **90%–100% RAM usage** right after startup or while opening normal apps  
- **100% Disk usage** that freezes the system  
- Sudden slowdowns caused by **hidden spyware**, **crypto miners**, or **memory-injecting malware**

Most antivirus tools need an internet connection for signature updates.  
**MemDiskGuard works 100% offline** and focuses specifically on resource-hijacking threats.

---

## Key Features

| Feature | Description |
|---------|-------------|
| **High RAM Detection** | Finds processes consuming large amounts of memory |
| **Memory Injection Check** | Detects possible DLL injection & process hijacking |
| **100% Disk Indicators** | Reads disk queue & flags suspicious high-I/O processes |
| **Crypto Miner Detection** | Built-in list of common miners (XMRig, Ethminer, etc.) |
| **Spyware & Adware Patterns** | Recognizes known resource-abusive spyware names |
| **Startup Persistence Scan** | Checks Registry Run keys, Scheduled Tasks & Services |
| **Interactive Cleanup** | Select individual items or remove all with confirmation |
| **Fully Offline** | No internet, no cloud, no telemetry |

---

## Quick Start

### 1. Download
Download `MemoryDiskSpywareScanner.ps1` from this repository.

### 2. Run as Administrator

```powershell
# Open PowerShell as Administrator, then:
cd "C:\Path\To\MemDiskGuard"
Set-ExecutionPolicy Bypass -Scope Process -Force
.\MemoryDiskSpywareScanner.ps1
```

### 3. Review & Clean
- The scanner lists suspicious items with memory usage (MB)
- Enter numbers (e.g. `1,3,5`) or type `ALL`
- Confirm with `YES` to kill processes / remove persistence

---

## What It Scans

- Top memory-consuming processes
- Processes with abnormal module counts (possible injection)
- DLLs loaded from Temp / AppData
- Current disk activity indicators
- Known miner & spyware process names
- Suspicious Scheduled Tasks
- Suspicious Windows Services
- Registry Run / RunOnce startup entries

---

## Example Use Cases

- PC becomes extremely slow after login
- Task Manager shows 90%+ memory usage with no obvious heavy apps
- Constant 100% disk activity
- Suspected crypto miner infection
- Want an offline second opinion after using Windows Defender

---

## Important Warnings

> **This is a heuristic tool, not a full antivirus.**

- False positives can occur (especially with legitimate high-RAM software)
- Always create a **System Restore Point** before removing items
- Review every finding carefully
- After cleaning, restart your PC and verify in Task Manager / Resource Monitor
- For stubborn infections, also run:
  ```powershell
  Start-MpWDOScan
  ```

---

## System Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or newer (included by default)
- Administrator privileges

---

## Related Tool

Looking for a general offline spyware scanner (Registry, Startup, Services, Processes)?  
Check the companion script: **Offline Spyware Scanner** (`SpywareScanner.ps1`) in this repository.

---

## Disclaimer

MemDiskGuard is provided **as-is** for educational and personal use.  
The author is not responsible for any data loss, system instability, or incorrect removals.  
Use at your own risk. Always keep real-time protection (Windows Defender or similar) enabled.

---

## License

MIT License – free to use, modify, and share.

---

## Keywords

`high ram usage windows 10`, `100% disk usage malware`, `spyware high memory`, `crypto miner detector offline`, `memory injection scanner`, `windows 11 slow startup malware`, `offline powershell malware scanner`, `remove memory hijacking malware`, `fix high cpu disk usage windows`

---

**Star this repository if MemDiskGuard helped you recover your system performance!**
