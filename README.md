
# Upgrade_Windows_with_Fixes.ps1

## Overview

This script prepares Windows 10 devices for upgrade to Windows 11 by validating and remediating WinRE and system reserved partitions, resolving upgrade blockers, and dynamically monitoring the upgrade process.\
It is intended to be deployed **as a Win32 app through Microsoft Intune**.

The script addresses common upgrade failures, including partition sizing issues, compatibility "red reasons," and blocking printer drivers, based on Microsoft's official guidance.

---

## Key Features

- Verifies and updates WinRE partition configuration for GPT and MBR disks.
- Resizes the recovery partition if insufficient free space exists.
- Updates the WinRE image to meet minimum version requirements:
  - Windows 11 version 21H2: WinRE must be ≥ 10.0.22000.2710
  - Windows 10 versions 21H2/22H2: WinRE must be ≥ 10.0.19041.3920
- Deletes unnecessary fonts and language folders, retaining only **en-US** by default (modify if required).
- Detects and removes unsigned Microsoft printer drivers that may block Windows 11 upgrades.
- Clears "red reasons" from the registry and re-runs the compatibility appraiser.
- Runs Disk Cleanup if free space is low.
- Launches the Windows 11 Installation Assistant using **ServiceUI.exe** (if logged-on users are detected).
- Dynamically monitors the upgrade process:
  - Switches from monitoring `Windows11InstallationAssistant.exe` to `windows10upgraderapp.exe`.
  - Implements CPU idle timeout detection to handle user reboot prompts.
- Extensive logging to both console and log files.

---

## Prerequisites

- **ServiceUI.exe** must be hosted by you in your own Azure Blob Storage account.
  - This script does not supply ServiceUI.exe.
  - You must update the `$serviceUIUrl` variable with your hosted download URL.
- Win32 app packaging and deployment via Microsoft Intune.

---

## Usage

Example command to run the script manually:

```powershell
powershell.exe -noprofile -executionpolicy bypass -file .\Upgrade_Windows_with_Fixes.ps1
```

In Intune (Win32 app), specify the install command:

```powershell
powershell.exe -noprofile -executionpolicy bypass -file Upgrade_Windows_with_Fixes.ps1
```

---

## Important Notes

- By default, **only the "en-US"** language folder is preserved when cleaning up the EFI boot partition.\
  If you use a different system locale, modify the script to preserve the appropriate language folder(s).
- Portions of this script — specifically the recovery partition resizing logic — are adapted from Microsoft’s published KB:
  - [KB5035679: Instructions to resize the recovery partition](https://support.microsoft.com/en-us/topic/kb5035679-instructions-to-run-a-script-to-resize-the-recovery-partition-to-install-a-winre-update-98502836-cb2c-4d9a-874c-23bcdf16cd45)
- This script is provided **"as is"** without any warranty. Test thoroughly before production use.

---

## Version History

| Version | Date           | Changes                                                                                             |
| ------- | -------------- | --------------------------------------------------------------------------------------------------- |
| 8.0     | July 19, 2024  | Added check for "red reasons" and Windows 11 upgrade.                                               |
| 9.0     | April 16, 2025 | Added removal of blocking Microsoft printer drivers, disk cleanup, and TPM/UEFI/Secure Boot checks. |
| 10.0    | April 25, 2025 | Improved logging; adjusted free space logic; increased upgrade wait time.                           |
| 11.0    | April 25, 2025 | Fixed bcdedit detection bug.                                                                        |
| 12.0    | April 28, 2025 | Extended font deletion; added ServiceUI support and download logic.                                 |
| 13.0    | April 29, 2025 | Improved abandoned process detection; added child process monitoring and CPU idle timeout logic. 
| 16.0    | April 29, 2025 | Removed Get-ChildProcess function due to unreliable results across systems
| 17.0    | April 29, 2025 | Total re-write of the resize-disk function
| 18.0    | April 30, 2025 | Added another process to monitor in attempt to accurately determine when the upgrade has completed. 

---

## Author

**John Marcum (PJM)**\
[Twitter/X: @MEM_MVP](https://x.com/MEM_MVP)
