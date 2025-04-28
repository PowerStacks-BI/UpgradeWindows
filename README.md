# Windows 11 Upgrade Script with Prechecks and Remediations
 
This PowerShell script is designed to be deployed as a Win32 app through Microsoft Intune. It upgrades eligible Windows 10 devices to Windows 11 while automatically addressing common upgrade blockers.
 
## Features
 
- Detects if the device meets Windows 11 upgrade requirements:
  - TPM 2.0
  - UEFI Boot
  - Secure Boot
- Deletes unnecessary font files from the System Reserved partition to resolve known upgrade issues.
- Cleans up unsigned Microsoft printer drivers.
- Detects and remediates known upgrade compatibility blocks ("Red Reasons").
- Automatically downloads and launches the Windows 11 Installation Assistant.
- Uses ServiceUI.exe to present upgrade prompts in the logged-on user's session (if a user is logged on).
- Waits for the upgrade assistant to complete with monitored timeout logic.
- Provides detailed logging to both console output and files.
 
## Deployment Requirements
 
- Windows 10 (preferably version 22H2).
- Devices must be managed through Intune.
- The script must be deployed as a **Win32 app** from Intune.
- The script must be executed in the **SYSTEM** context.
 
## How the Script Works
 
1. **Pre-Checks:**
   - Validates that TPM 2.0, UEFI boot, and Secure Boot are present and active.
   - Collects system and OS information for logging.
 
2. **Remediations:**
   - Deletes font files in the System Reserved partition to free space.
   - Removes unsigned Microsoft virtual printer drivers.
   - Clears upgrade compatibility blocks and reruns the appraiser process.
 
3. **Upgrade Execution:**
   - Downloads Windows11InstallationAssistant.exe if it is not already present.
   - Optionally downloads ServiceUI.exe to display upgrade prompts to logged-on users.
   - Detects and terminates any existing stuck upgrade assistant processes.
   - Launches the upgrade assistant and monitors its execution for up to two hours.
 
4. **Logging:**
   - Creates detailed logs in `C:\Windows\Logs\`.
   - Saves both a formatted event log and a full PowerShell transcript.
 
## Files Created
 
| Path | Purpose |
|:-----|:--------|
| `C:\Windows\Logs\Win11_Upgrade-*.log` | Main process log (event-style formatting) |
| `C:\Windows\Logs\Win11_Upgrade_Transcript-*.log` | Full PowerShell transcript |
| `C:\Temp\Win11` | Working directory for downloaded upgrade tools |
 
## Important Notes
 
- The script uses `taskkill.exe` to forcibly terminate any previously running instances of Windows11InstallationAssistant.exe if detected.
- If ServiceUI.exe is not available or no user is logged on, the upgrade runs silently without presenting a window.
- Timeout is set to 2 hours by default but can be adjusted in the script.
- All variables such as download URLs and arguments are located near the top of the script for easy modification.
- Windows Update readiness or driver compatibility checks outside of the scope of this script are not performed.
 
## License
 
This script is provided under the MIT License. Refer to the LICENSE file for details.
 
## Disclaimer
 
This script is provided as-is without warranty of any kind. It is recommended to test thoroughly in a controlled environment before production deployment.
