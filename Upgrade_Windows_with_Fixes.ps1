<#
.SYNOPSIS
Prepares Windows 10 devices for upgrade to Windows 11 by validating and remediating WinRE and system reserved partitions, resolving upgrade blockers, and monitoring the upgrade process. Dynamically tracks Windows11InstallationAssistant.exe and windows10upgraderapp.exe with CPU idle detection to manage reboot prompts.

.DESCRIPTION
This script performs the following **remediation tasks** to prepare devices for a Windows 11 upgrade:

- Verifies and updates WinRE partition configuration for GPT and MBR partition styles.
- Resizes the recovery partition if necessary.
- Updates the WinRE image to meet Windows 10 or Windows 11 version requirements.
- Deletes fonts and unnecessary language folders from the system reserved partition, preserving only "en-US" (modify if using a different locale).
- Detects and removes unsigned Microsoft printer drivers that may block upgrades.
- Clears compatibility "red reasons" from the registry and re-runs the compatibility appraiser.
- Runs Disk Cleanup to free up space if required.

It also performs **upgrade orchestration tasks**:

- Launches the Windows 11 Installation Assistant using ServiceUI.exe if users are logged on.
- Dynamically monitors the upgrade process, switching from Windows11InstallationAssistant.exe to windows10upgraderapp.exe.
- Detects low CPU activity to identify when the upgrade process is idle and waiting for user reboot confirmation.
- Requires hosting your own Azure Blob Storage URL for ServiceUI.exe (this script does not supply ServiceUI.exe).

This script incorporates enhancements based on the following Microsoft guidance:
- KB5035679: Instructions for resizing the recovery partition to install a WinRE update.
- KB5048239: Windows Recovery Environment update for Windows 10 version 21H2 and 22H2.
- Guidance for resolving "We couldn't update the system reserved partition" errors.

Minimum required WinRE versions:
- Windows 11, version 21H2: WinRE must be ≥ 10.0.22000.2710
- Windows 10, versions 21H2/22H2: WinRE must be ≥ 10.0.19041.3920

.PREREQUISITES
- Azure Blob Storage location to host ServiceUI.exe
- Deployment as an Intune Win32 app

########### LEGAL DISCLAIMER ###########
This script is provided "as is" without warranty of any kind, either express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement.
Use at your own risk. Thoroughly test before deploying in production environments.

.NOTES
Author: John Marcum (PJM)  
Date: July 19, 2024  
Contact: https://x.com/MEM_MVP

.VERSION HISTORY

8.0 – July 19, 2024
- Initial public release.
- Added logic to check for upgrade compatibility "red reasons" in the registry and re-run the compatibility appraiser.
- Introduced Windows 11 upgrade via Windows11InstallationAssistant.exe.

9.0 – April 16, 2025
- Added removal of unsigned Microsoft printer drivers that block Windows 11 upgrades.
- Implemented disk cleanup using CleanMgr to free up space if required.
- Added detection of TPM 2.0, UEFI boot mode, and Secure Boot status.

10.0 – April 25, 2025
- Improved logging format and added timestamps.
- Changed log function to always output to both screen and file.
- Introduced $MinRequiredFreeSpaceGB variable and lowered free space requirement from 40GB to 30GB.
- Increased upgrade monitoring timeout to 2 hours.

11.0 – April 25, 2025
- Fixed bug where bcdedit could not be called in certain contexts by explicitly invoking it with cmd.exe /c.

12.0 – April 28, 2025
- Enhanced Delete-Fonts function to also remove unused language folders from the EFI partition, leaving only en-US.
- Added support for using ServiceUI.exe to display upgrade dialogs to the user.
- Added logic to download ServiceUI.exe from a user-defined Azure Blob Storage URL.

13.0 – April 29, 2025
- Introduced detection of abandoned upgrade processes and improved process cleanup logic.
- Added new Get-ChildProcess function to trace Windows11InstallationAssistant.exe child processes.
- Switched upgrade monitoring to track windows10upgraderapp.exe once detected as a child.
- Implemented CPU idle timeout logic to exit gracefully if the process stalls at the reboot prompt.

14 and 15 were for internal testing only and not made public.

16.0 – April 29, 2025  
- Removed Get-ChildProcess function due to unreliable results across systems.  
- Switched upgrade monitoring to track windows10upgraderapp.exe directly, regardless of parent process.  
- Introduced 60-second delay after launching Windows11InstallationAssistant.exe before monitoring begins.  
- Improved Get-WinREInfo to more reliably detect recovery partition size and free space.  
- Removed redundant DisplayWinREStatus function and replaced all references with Get-WinREInfo.  
- Standardized logging under the Get-WinREInfo component for partition-related operations. 

17.0 – April 29, 2025  
- Total re-write of the resize-disk function. Previously we simply used Microsoft's code but it had issues so I started from scratch and made it work better.
- Added functions to backup and restore WinRE. Calling those functions when it makes sense.  

18.0 - April 30,2025
- Created function to monitor processes
- Added new process to monitor $WINDOWS.~BT\Sources\SetupHost

19 - April 30,2025
- Relaunch Script in 64-bit PowerShell (if currently running in 32-bit on x64 system)
- Skip the entire boot mode detection if we cannot find bcdedit.exe

20 - April 30, 2025
- Added support for placing serviceui.exe into the Win32 package

21 - May 1, 2025
- Removed the attempt(s) to detect sucess/failure of the upgrade. Doing so is just not reliable. Instead let the detection script figure it out after later!
- Added a 30 minute wait for the upgrade before exiting the script just to attempt to postpone the detection script for a while but not to exceed the reboot countdown. (45-60 is prob safe too)
- Fixed a bug in the red reason (compatibility) checker.
- Created new SleepNow function to sleep and log sleep time remaining periodically.
- Migrated some script variables to parameters:
    - $Win11WorkingDirectory
    - $ServiceUIPath (default is including serviceui.exe in the Win32 App)
    - $MinRequiredFreeSpaceGB
- Added creation of scheduled task to reclaim disk space at first login (If Win11)

22 - May 2, 2025
- Added support for preserving language files other than EN-US
- Several reports of missing WinRE.wim have come in from previous versions. This version attempts to correct that. 
- Added skipping risky operations if we have no WinRE backup.
- Log function now attempts to log line number of errors. 
- Stole, and implemented, some code from Gary to improve https://garytown.com/low-space-on-efi-system-partition-clean-up cleanp of the system reserved partition

25 - May 6, 2025
- Scheduled task creation error resolved
- Changed from waiting for specified number of minutes to reading the setupact.log to watch for 100%
- Resolved bug in serviceui.exe path

26 - May 6, 2025
- Resolved bug preventing Bitlocker from re-enabling.
- Unregister exsisting cleanup task if it exsists.
- Updated the Get-LastLines function to read locked files.

27 - May 15, 2025
- Changes to the Get-WinREInfo function to resolve issue causing it to always fail to find the partition info.

28 - May 16, 2025
- Assume failure on timeout and remove the scheduled task

29 - May 16, 2025
- Edit the scheduled task so that disk clean only runs if the OS is Windows 11

30 - May 29, 2025
- Simplified the "Clean-Drivers" function to make it unconditionally remove Microsoft XPS Document Writer and Microsoft Print to PDF
    printer drivers and reinstall them via Windows capabilities.

.EXAMPLE
To execute the script manually:

    powershell.exe -noprofile -executionpolicy bypass -file .\Upgrade_Windows_with_Fixes.ps1

In Intune (Win32 app), specify this as the install command:

    powershell.exe -noprofile -executionpolicy bypass -file Upgrade_Windows_with_Fixes.ps1

In Intune (Win32 app), specify this as the install command (if using a blob URL):

    powershell.exe -noprofile -executionpolicy bypass -file Upgrade_Windows_with_Fixes.ps1 -ServiceUIPath "https://yourstorage.blob.core.windows.net/tools/ServiceUI.exe"

#>

# ---------------------------------------------------------------------------------------------------
#  Begin Parameter Definitions (user-overridable)
# ---------------------------------------------------------------------------------------------------
param (
    [string]$Win11WorkingDirectory = "C:\Temp\Win11",
    # IMPORTANT: Set $ServiceUIPath to your own Azure Blob Storage URL containing ServiceUI.exe
    # OR
    # Place ServiceUI.exe in the root of your Win32 package and set this to: "$PSScriptRoot\ServiceUI.exe"
    # (This script does NOT host or provide ServiceUI.exe.)
    [string]$ServiceUIPath = "$PSScriptRoot\ServiceUI.exe",
    [int]$MinRequiredFreeSpaceGB = 30
)
# ---------------------------------------------------------------------------------------------------
#  End Parameter Definitions (user-overridable)
# ---------------------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------------------
# Relaunch Script in 64-bit PowerShell (if currently running in 32-bit on x64 system)
# ---------------------------------------------------------------------------------------------------
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
    Write-Host "Not on ARM64"
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {   

        
        # Relaunch as 64-bit
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        
        Write-Host "Relaunched as a 64-bit process"
        Exit $lastexitcode
    }
}


# ------------------------------------
# Begin Defining Script Variables
# ------------------------------------

# ------------------------------------
# Script Version Info
# ------------------------------------
[int]$ScriptVersion = 30


# ========================================
# Variables: Logging
# ========================================
$Now = Get-Date -Format MM-dd-yyyy-HH-mm-ss
$LogFile = "C:\Windows\Logs\Win11_Upgrade-$Now.log"
$TranscriptFile = "C:\Windows\Logs\Win11_Upgrade_Transcript-$Now.log"
Start-Transcript -Path $TranscriptFile
Write-Host "Starting upgrade using script version: $($ScriptVersion)"


# ========================================
# Variables: Script Configuration
# ========================================
$upgradeArgs = "/quietinstall /skipeula /auto upgrade /copylogs $Win11WorkingDirectory"


# ========================================
# Languages to keep (use RFC 5646 format)
# Use a comma seperated list if you need more languages
# ========================================
$PreserveLanguages = @('en-US')


# ========================================
# Variables: ServiceUI
# ========================================
$ServiceUIDestination = "$Win11WorkingDirectory\ServiceUI.exe"


# ========================================
# Variables: Used for the compat appraiser
# ========================================
$CompatAppraiserPath = 'C:\Windows\system32\CompatTelRunner.exe'
$RegistryPathAppCompat = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\'
$RegValueGStatus = 'GStatus'
$RegValueUpgEx = 'UpgEx'
$RegValueRedReason = 'RedReason'


# ========================================
# Variables: For idle process check (mostly unused since v21)
# ========================================
$monitoredExeName = "windows10upgraderapp.exe"
$monitoredProcName = [System.IO.Path]::GetFileNameWithoutExtension($monitoredExeName)
[int]$cpuIdleThresholdMinutes = 5
[int]$timeoutSeconds = 7200
[int][int]$checkIntervalSeconds = 15
$elapsedSeconds = 0
[int]$checkIntervalSeconds = 15
[int]$maxWaitSeconds = 7200  # 2 hours


# ========================================
# Variables: Default time (min) to sleep when calling sleepNow function
# ========================================
[int]$sleepTime = 30

# ------------------------------------
# End Defining Script Variables
# ------------------------------------

# Create the working directory if it doesn't exist
if (-not (Test-Path $Win11WorkingDirectory)) {
    mkdir $Win11WorkingDirectory
}
 

# Make sure that we are not already in Windows 11
$isWin11 = (Get-WmiObject Win32_OperatingSystem).Caption -Match "Windows 11"

if ($isWin11) {
    write-host "Windows 11"
    Stop-Transcript
    Exit 0
}
Else {
    write-host  "We are in Windows 10."
   
    # ------------------------------------
    # Begin Functions
    # ------------------------------------

    function LogMessage {
        <#
    .SYNOPSIS
    Writes a formatted log message to both the console and a persistent log file, including the line number.

    .DESCRIPTION
    Logs messages with timestamp, severity level (INFO, WARN, ERROR), component name, and the script line number.

    .PARAMETER Message
    The message text to log.

    .PARAMETER Component
    An optional label for the log source (e.g., a function name). Defaults to 'Script'.

    .PARAMETER Type
    1 = INFO, 2 = WARN, 3 = ERROR

    .OUTPUTS
    Writes to both screen and $LogFile
    #>

        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,

            [string]$Component = "Script",

            [ValidateSet('1', '2', '3')]
            [int]$Type = 1
        )

        $timeStamp = Get-Date -Format "HH:mm:ss"
        $dateStamp = Get-Date -Format "yyyy-MM-dd"
        $levelText = switch ($Type) {
            1 { "INFO" }
            2 { "WARN" }
            3 { "ERROR" }
        }

        # Try to get line number from call stack
        $callStack = Get-PSCallStack
        $caller = if ($callStack.Count -gt 1) { $callStack[1] } else { $null }
        $lineInfo = if ($caller) { "Line $($caller.ScriptLineNumber)" } else { "Line ?" }

        $formattedMessage = "[${dateStamp} ${timeStamp}] [$levelText] [$Component] [$lineInfo] $Message"

        # Output to console with color
        switch ($Type) {
            1 { Write-Host $formattedMessage -ForegroundColor Gray }
            2 { Write-Host $formattedMessage -ForegroundColor Yellow }
            3 { Write-Host $formattedMessage -ForegroundColor Red }
        }

        # Always write to file
        $formattedMessage | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

    
    function Clean-Drivers {
        <#
    .SYNOPSIS
    Removes Microsoft virtual printer drivers that can block Windows 11 upgrades.

    .DESCRIPTION
    Unconditionally removes Microsoft XPS Document Writer and Microsoft Print to PDF
    printer drivers and reinstalls them via Windows capabilities.
    #>

        $removedDrivers = @()
        $targets = @(
            "Microsoft XPS Document Writer",
            "Microsoft Print To PDF"
        )

        foreach ($targetDriver in $targets) {
            # Remove any printers using this driver
            $printersUsingDriver = Get-Printer | Where-Object { $_.DriverName -like "$targetDriver*" }

            foreach ($printer in $printersUsingDriver) {
                LogMessage -message (" -> Removing printer: $($printer.Name) (Driver: $($printer.DriverName))") -Type 1 -Component 'Clean-Drivers'
                try {
                    Remove-Printer -Name $printer.Name -ErrorAction Stop
                    LogMessage -message ("    Successfully removed printer: $($printer.Name)") -Type 1 -Component 'Clean-Drivers'
                }
                catch {
                    LogMessage -message ("    Failed to remove printer: $($printer.Name) — $_") -Type 2 -Component 'Clean-Drivers'
                }
            }

            # Remove the printer driver
            $driver = Get-PrinterDriver | Where-Object { $_.Name -like "$targetDriver*" }

            if ($driver) {
                LogMessage -message ("Removing driver: $($driver.Name)") -Type 1 -Component 'Clean-Drivers'
                try {
                    Remove-PrinterDriver -Name $driver.Name -ErrorAction Stop
                    LogMessage -message ("    Successfully removed driver: $($driver.Name)") -Type 1 -Component 'Clean-Drivers'
                    $removedDrivers += $driver.Name
                }
                catch {
                    LogMessage -message ("Failed to remove driver: $($driver.Name)") -Type 2 -Component 'Clean-Drivers'
                }
            }
            else {
                LogMessage -message ("Driver not found: $targetDriver") -Type 1 -Component 'Clean-Drivers'
            }
        }

        # Reinstall if any were removed
        if ($removedDrivers -match "Microsoft Print to PDF") {
            LogMessage -message ("Reinstalling Microsoft Print to PDF...") -Type 1 -Component 'Clean-Drivers'
            Add-WindowsCapability -Online -Name "Printing.PrintToPDF~~~~0.0.1.0" -ErrorAction SilentlyContinue
        }

        if ($removedDrivers -match "Microsoft XPS Document Writer") {
            LogMessage -message ("Reinstalling Microsoft XPS Document Writer...") -Type 1 -Component 'Clean-Drivers'
            Add-WindowsCapability -Online -Name "Printing.XPSServices~~~~0.0.1.0" -ErrorAction SilentlyContinue
        }

        if (-not $removedDrivers) {
            LogMessage -message ("No matching printer drivers found for removal.") -Type 1 -Component 'Clean-Drivers'
        }
    }
    function ExtractNumbers([string]$str) {
        <#
        .SYNOPSIS
        Extracts numeric characters from a string and returns them as a long integer.

        .DESCRIPTION
        This utility function removes all non-numeric characters from the input string 
        and returns the result as a 64-bit integer ([long]).

        Used to parse disk or partition numbers from formatted strings 
        (e.g., "harddisk0" → 0).

        .PARAMETER str
        The input string from which to extract numeric digits.

        .OUTPUTS
        System.Int64 (long)

        .EXAMPLE
        ExtractNumbers "harddisk1"  # Returns: 1
        #>
        $cleanString = $str -replace "[^0-9]"
        return [long]$cleanString
    }

    # Define function to check partition style
    Function Get-PartitionStyle {
        $disk = Get-Disk | Where-Object { $_.PartitionStyle -ne "RAW" -and $_.IsBoot -eq $true }
        if (!$disk) {
            LogMessage -Message ("Could not determine the boot disk. Ensure the system is properly configured.") -Type 2 -Component 'Get-PartitionStyle'
            return
        }
        return $disk.PartitionStyle
    }
    
    function IsProcessIdle {
        <#
        .SYNOPSIS
        Waits for a process to remain below 1% real-time CPU usage for a defined period.

        .DESCRIPTION
        Uses Get-Counter to poll the process’s % Processor Time every few seconds. If CPU usage stays
        under 1% for the full IdleMinutes threshold, or if the process exits, the function returns $true.
        If MaxWaitSeconds is reached first, the function returns $false.

        .PARAMETER ProcessName
        The name of the process to monitor (without ".exe").

        .PARAMETER ExpectedPathPart
        Optional. A partial string to match in the process path.

        .PARAMETER IdleMinutes
        The number of continuous minutes the process must remain under 1% CPU usage.

        .PARAMETER MaxWaitSeconds
        The maximum number of seconds to wait before timing out.

        .PARAMETER checkIntervalSeconds
        Interval between checks. Default: 15 seconds.

        .OUTPUTS
        [bool] - $true if idle threshold met or process exited; $false if timed out.

        .EXAMPLE
        if (IsProcessIdle -ProcessName "SetupHost" -ExpectedPathPart "\$WINDOWS.~BT\Sources") {
            LogMessage -message "SetupHost.exe confirmed idle"
        }
        #>

        param (
            [string]$ProcessName,
            [string]$ExpectedPathPart = $null,
            [int]$IdleMinutes = 5,
            [int]$MaxWaitSeconds = 7200,
            [int]$checkIntervalSeconds = 15
        )

        $idleSeconds = 0
        $waitSeconds = 0

        while ($waitSeconds -lt $MaxWaitSeconds) {
            $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Where-Object {
                if ($ExpectedPathPart) {
                    try { $_.Path -like "*$ExpectedPathPart*" } catch { $false }
                }
                else {
                    $true
                }
            }

            if (-not $process) {
                return $true  # Treat as idle if process exited
            }

            try {
                $counterPath = "\Process($ProcessName*)\% Processor Time"
                $cpuUsage = (Get-Counter -Counter $counterPath -ErrorAction Stop).CounterSamples.CookedValue
                $cpuAvg = [math]::Round(($cpuUsage | Measure-Object -Average).Average, 2)

                if ($cpuAvg -lt 1) {
                    $idleSeconds += $checkIntervalSeconds
                    if ($idleSeconds -ge ($IdleMinutes * 60)) {
                        return $true
                    }
                }
                else {
                    $idleSeconds = 0
                }
            }
            catch {
                # Handle cases where Get-Counter fails (e.g., instance not found)
                LogMessage -message "Failed to sample CPU for $($ProcessName): $($_.Exception.Message)" -Type 3 -Component 'Upgrade'
                $idleSeconds = 0
            }

            Start-Sleep -Seconds $checkIntervalSeconds
            $waitSeconds += $checkIntervalSeconds
        }

        LogMessage -message "$ProcessName did not become idle in time. Max wait of $($MaxWaitSeconds / 60) minutes exceeded." -Type 3 -Component 'Upgrade'
        return $false
    }


    function SleepNow {
        <#
    .SYNOPSIS
    Pauses script execution for a specified number of minutes with periodic logging.

    .DESCRIPTION
    This function puts the script to sleep for a given number of minutes. During the sleep,
    it logs a message every 60 seconds showing the remaining time, and then logs a final 
    message when the wait period is over.

    .PARAMETER Length
    The number of minutes to sleep.

    .OUTPUTS
    None. This function is used for timing and logging purposes only.

    .EXAMPLE
    SleepNow -Length 15
    Logs a message every minute for 15 minutes, then logs "Time to wake up sleepy head!".
    #>

        param (
            [Parameter(Mandatory = $true)]
            [int]$Length  # Length in minutes
        )

        $totalSeconds = $Length * 60
        $remaining = $totalSeconds

        while ($remaining -gt 0) {
            Start-Sleep -Seconds 60
            $remaining -= 60

            if ($remaining -gt 0) {
                $minutes = [int]($remaining / 60)
                $seconds = $remaining % 60
                LogMessage -message ("Sleeping for another $minutes min and $seconds second") -Component 'SleepNow'
            }
        }

        LogMessage -message ("Time to wake up sleepy head!") -Component 'SleepNow'
    }


    function DisplayPartitionInfo([string[]]$partitionPath) {
        <#
        .SYNOPSIS
        Retrieves and logs partition size and free space for a given partition path.

        .DESCRIPTION
        Uses WMI (Win32_Volume) to find the volume associated with the provided device path(s).
        Logs total capacity and available free space, and returns both values as a two-element array.

        Used during WinRE analysis or resizing to understand disk layout and available space.

        .PARAMETER partitionPath
        An array of partition access paths (e.g., {"\\?\Volume{...}\"}).

        .OUTPUTS
        System.Object[]
        Returns an array: [TotalSize (bytes), FreeSpace (bytes)]

        .EXAMPLE
        DisplayPartitionInfo "\\?\Volume{abc123}\"
        # Logs and returns: 500107862016, 120034467840
        #>
        $volume = Get-WmiObject -Class Win32_Volume | Where-Object { $partitionPath -contains $_.DeviceID }
        LogMessage -message ("  Partition capacity: " + $volume.Capacity) -Type 1 -Component 'DisplayPartitionInfo'
        LogMessage -message ("  Partition free space: " + $volume.FreeSpace) -Type 1 -Component 'DisplayPartitionInfo'
        return $volume.Capacity, $volume.FreeSpace
    } 
    
    function Backup-WinRE {
        <#
    .SYNOPSIS
    Backs up WinRE.wim and ReAgent.xml to C:\WinRE_Backup.

    .DESCRIPTION
    Copies both the recovery image (WinRE.wim) and configuration file (ReAgent.xml)
    to C:\WinRE_Backup. Logs actions and returns $true if both backups succeed.

    .OUTPUTS
    [bool] - $true if both files were backed up, otherwise $false.
    #>

        $sourceWim = "$env:SystemRoot\System32\Recovery\WinRE.wim"
        $sourceXml = "$env:SystemRoot\System32\Recovery\ReAgent.xml"
        $backupFolder = "C:\WinRE_Backup"
        $backupWim = Join-Path $backupFolder "WinRE.wim"
        $backupXml = Join-Path $backupFolder "ReAgent.xml"

        if (!(Test-Path $backupFolder)) {
            New-Item -Path $backupFolder -ItemType Directory | Out-Null
        }

        $success = $true

        if (Test-Path $sourceWim) {
            try {
                Copy-Item -Path $sourceWim -Destination $backupWim -Force
                LogMessage -message "Backed up WinRE.wim to $backupWim" -Component 'Backup-WinRE'
            }
            catch {
                LogMessage -message "Failed to back up WinRE.wim: $($_.Exception.Message)" -Type 3 -Component 'Backup-WinRE'
                $success = $false
            }
        }
        else {
            LogMessage -message "No WinRE.wim found at $sourceWim to back up" -Type 2 -Component 'Backup-WinRE'
            $success = $false
        }

        if (Test-Path $sourceXml) {
            try {
                Copy-Item -Path $sourceXml -Destination $backupXml -Force
                LogMessage -message "Backed up ReAgent.xml to $backupXml" -Component 'Backup-WinRE'
            }
            catch {
                LogMessage -message "Failed to back up ReAgent.xml: $($_.Exception.Message)" -Type 3 -Component 'Backup-WinRE'
                $success = $false
            }
        }
        else {
            LogMessage -message "No ReAgent.xml found at $sourceXml to back up" -Type 2 -Component 'Backup-WinRE'
            # not fatal, continue
        }

        return $success
    }

    function Restore-WinRE {
        <#
    .SYNOPSIS
    Restores the WinRE.wim and ReAgent.xml files from backup if they were previously saved.

    .DESCRIPTION
    Copies the backed-up WinRE image and configuration file from C:\WinRE_Backup to their original system locations
    in C:\Windows\System32\Recovery. Re-registers the WinRE image using ReAgentC.

    .OUTPUTS
    [bool] - $true if restore and re-registration were successful, otherwise $false.
    #>

        $backupFolder = "C:\WinRE_Backup"
        $backupWim = Join-Path $backupFolder "WinRE.wim"
        $backupXml = Join-Path $backupFolder "ReAgent.xml"
        $recoveryFolder = "$env:SystemRoot\System32\Recovery"
        $targetWim = Join-Path $recoveryFolder "WinRE.wim"
        $targetXml = Join-Path $recoveryFolder "ReAgent.xml"

        $restoreSuccess = $true

        # --- Restore WinRE.wim ---
        if (-not (Test-Path $targetWim) -and (Test-Path $backupWim)) {
            try {
                Copy-Item -Path $backupWim -Destination $targetWim -Force
                LogMessage -message "Restored WinRE.wim to $targetWim" -Component 'Restore-WinRE'
            }
            catch {
                LogMessage -message "Failed to restore WinRE.wim: $($_.Exception.Message)" -Type 3 -Component 'Restore-WinRE'
                $restoreSuccess = $false
            }
        }
        elseif (-not (Test-Path $backupWim)) {
            LogMessage -message "Backup WinRE.wim not found at $backupWim" -Type 3 -Component 'Restore-WinRE'
            $restoreSuccess = $false
        }
        else {
            LogMessage -message "WinRE.wim already exists at $targetWim — no restore needed." -Component 'Restore-WinRE'
        }

        # --- Restore ReAgent.xml ---
        if (-not (Test-Path $targetXml) -and (Test-Path $backupXml)) {
            try {
                Copy-Item -Path $backupXml -Destination $targetXml -Force
                LogMessage -message "Restored ReAgent.xml to $targetXml" -Component 'Restore-WinRE'
            }
            catch {
                LogMessage -message "Failed to restore ReAgent.xml: $($_.Exception.Message)" -Type 2 -Component 'Restore-WinRE'
                # not fatal
            }
        }
        elseif (Test-Path $targetXml) {
            LogMessage -message "ReAgent.xml already exists at $targetXml — no restore needed." -Component 'Restore-WinRE'
        }

        # --- Re-register WinRE image if WIM is now present ---
        if (Test-Path $targetWim) {
            try {
                $output = ReAgentC.exe /setreimage /path $recoveryFolder /target $env:SystemRoot 2>&1
                if ($LASTEXITCODE -eq 0) {
                    LogMessage -message "ReAgentC /setreimage successful. Output:`n$($output -join "`n")" -Component 'Restore-WinRE'
                }
                else {
                    LogMessage -message "ReAgentC /setreimage failed. Output:`n$($output -join "`n")" -Type 3 -Component 'Restore-WinRE'
                    $restoreSuccess = $false
                }
            }
            catch {
                LogMessage -message "Exception occurred during ReAgentC /setreimage: $($_.Exception.Message)" -Type 3 -Component 'Restore-WinRE'
                $restoreSuccess = $false
            }
        }
        else {
            LogMessage -message "WinRE.wim is still missing at $targetWim. Cannot re-register." -Type 3 -Component 'Restore-WinRE'
            $restoreSuccess = $false
        }

        return $restoreSuccess
    }

    
    function Get-WinREInfo {
        <#
        .SYNOPSIS
        Retrieves Windows Recovery Environment (WinRE) configuration details.
    
        .DESCRIPTION
        This function checks whether WinRE is enabled, and gathers details about the WinRE partition,
        such as its disk/partition number, size, and free space. It prefers using the structured
        ReAgent.xml file for disk and partition info, falling back to parsing reagentc output if needed.
    
        .EXAMPLE
        Get-WinREInfo
    
        .NOTES
        Author: Your Name
        #>
    
        LogMessage -message ("Retrieving current WinRE Info") -Type 1 -Component 'Get-WinREInfo'
    
        try {
            $WinreInfo = reagentc /info
            $WinreInfoLines = $WinreInfo -split "`r?`n"
    
            foreach ($line in $WinreInfoLines) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    LogMessage -message $line
                }
            }
    
            $statusLine = $WinreInfoLines | Where-Object { $_ -match "Windows RE status" }
            $RecoveryPartitionStatus = $statusLine -replace '.*:\s*', ''
    
            if ($RecoveryPartitionStatus -eq 'Enabled') {
                LogMessage -message ("Recovery Agent is enabled") -Type 1 -Component 'Get-WinREInfo'
                $WinREImagepath = "$env:SystemRoot\System32\Recovery\WinRE.wim"
                $OSPartitionObject = Get-Partition -DriveLetter ($env:SystemDrive).Substring(0, 1)
                $WinREImageLocationDisk = $OSPartitionObject.DiskNumber
                $WinREImageLocationPartition = $OSPartitionObject.PartitionNumber
    
                # Try XML first
                [xml]$ReAgentXML = Get-Content "$env:SystemRoot\System32\Recovery\ReAgent.xml" -ErrorAction Stop
                $winreLocation = $ReAgentXML.ReAgentConfig.WinreLocation
    
                $RecoveryDiskNumber = $null
                $RecoveryPartitionNumber = $null
    
                if ($winreLocation -and $winreLocation.DiskId -ne $null -and $winreLocation.PartitionId -ne $null) {
                    $RecoveryDiskNumber = [int]$winreLocation.DiskId
                    $RecoveryPartitionNumber = [int]$winreLocation.PartitionId
                    LogMessage -message ("Retrieved disk/partition from ReAgent.xml: Disk $RecoveryDiskNumber, Partition $RecoveryPartitionNumber") -Type 1 -Component 'Get-WinREInfo'
                }
                else {
                    # Fallback: parse reagentc output
                    $ReAgentCCurrentDrive = $WinreInfoLines | Where-Object { $_ -match "Recovery image location" } | ForEach-Object { $_ -replace '.*:\s*', '' } | ForEach-Object { $_.Trim() -replace '\0', '' }
                    $recoveryPathInfo = $ReAgentCCurrentDrive -replace '\\\?\\GLOBALROOT\\device\\', ''
    
                    if ($recoveryPathInfo -match '(?i)harddisk(\d+).*partition(\d+)') {
                        $RecoveryDiskNumber = [int]$matches[1]
                        $RecoveryPartitionNumber = [int]$matches[2]
                        LogMessage -message ("Extracted disk/partition from reagentc output: Disk $RecoveryDiskNumber, Partition $RecoveryPartitionNumber") -Type 1 -Component 'Get-WinREInfo'
                    }
                    else {
                        LogMessage -message ("Unable to extract disk and partition number from either XML or reagentc output.") -Type 2 -Component 'Get-WinREInfo'
                        return @([PSCustomObject]@{ WinREStatus = "Disabled"; ImagePath = $null })
                    }
                }
    
                $RecoveryPartition = Get-Partition -DiskNumber $RecoveryDiskNumber -PartitionNumber $RecoveryPartitionNumber -ErrorAction SilentlyContinue
                if (-not $RecoveryPartition) {
                    LogMessage -message ("Recovery partition not found.") -Type 2 -Component 'Get-WinREInfo'
                    return @([PSCustomObject]@{ WinREStatus = "Disabled"; ImagePath = $null })
                }
    
                $diskInfo = Get-Disk -Number $RecoveryDiskNumber
                $PartitionStyle = $diskInfo.PartitionStyle
                $LastPartitionNumber = (Get-Partition -DiskNumber $RecoveryDiskNumber | Sort-Object Offset | Select-Object -Last 1).PartitionNumber
    
                try {
                    $SupportedSize = Get-PartitionSupportedSize -DiskNumber $RecoveryDiskNumber -PartitionNumber $RecoveryPartitionNumber
                    $RecoveryPartitionSize = [math]::Round($RecoveryPartition.Size / 1MB, 2)
                    $RecoveryPartitionFreeMB = [math]::Round(($SupportedSize.SizeMax - $RecoveryPartition.Size) / 1MB, 2)
                    $RecoveryPartitionFreeGB = [math]::Round(($SupportedSize.SizeMax - $RecoveryPartition.Size) / 1GB, 2)
                }
                catch {
                    LogMessage -message ("PartitionSupportedSize not available. Defaulting free space to 0.") -Type 2 -Component 'Get-WinREInfo'
                    $RecoveryPartitionSize = [math]::Round($RecoveryPartition.Size / 1MB, 2)
                    $RecoveryPartitionFreeMB = 0
                    $RecoveryPartitionFreeGB = 0
                }
    
                $OSIsLast = ($OSPartitionObject.PartitionNumber -eq $LastPartitionNumber)
                $RecoveryIsLastPartition = ($RecoveryPartitionNumber -eq $LastPartitionNumber)
    
                LogMessage -message ("Recovery partition size: $($RecoveryPartitionSize) MB") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("Recovery partition free space: $($RecoveryPartitionFreeMB) MB") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("Recovery is last partition? $($RecoveryIsLastPartition)") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("OS is last partition? $($OSIsLast)") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("Partition Style: $($PartitionStyle)") -Type 1 -Component 'Get-WinREInfo'
    
                return @([PSCustomObject]@{
                        WinREStatus          = "Enabled"
                        ImagePath            = $WinREImagepath
                        DiskNumber           = $WinREImageLocationDisk
                        WinREImageLocation   = $WinREImageLocationPartition
                        PartitionStyle       = $PartitionStyle
                        LastPartition        = $LastPartitionNumber
                        OSIsLast             = $OSIsLast
                        winREPartitionSizeMB = $RecoveryPartitionSize
                        winREPartitionFree   = $RecoveryPartitionFreeGB
                        winREPartitionFreeMB = $RecoveryPartitionFreeMB
                        winREIsLast          = $RecoveryIsLastPartition
                        DiskIndex            = $WinREImageLocationDisk
                        OSPartition          = $OSPartitionObject.PartitionNumber
                        winREPartitionNumber = $RecoveryPartitionNumber
                    })
            }
            else {
                LogMessage -message ("Recovery Agent is NOT enabled.") -Type 2 -Component 'Get-WinREInfo'
                return @([PSCustomObject]@{ WinREStatus = "Disabled"; ImagePath = $null })
            }
        }
        catch {
            LogMessage -message ("Failed to retrieve WinRE information: $($_.Exception.Message)") -Type 3 -Component 'Get-WinREInfo'
            return @([PSCustomObject]@{ WinREStatus = "Error"; ImagePath = $null })
        }
    }    

  
    function Disable-WinRE {
        <#
    .SYNOPSIS
    Disables Windows Recovery Environment (WinRE).

    .DESCRIPTION
    Uses ReAgentC.exe /disable. Returns $true if WinRE is successfully disabled or already disabled.
    Returns $false on failure, and logs all actions.

    .OUTPUTS
    [bool]

    .EXAMPLE
    if (-not (Disable-WinRE)) {
        Write-Host "Failed to disable WinRE"
    }
    #>
        try {
            $output = ReAgentC.exe /disable 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -eq 0) {
                LogMessage -message "WinRE disabled successfully." -Type 1 -Component 'Disable-WinRE'
                return $true
            }
            elseif ($exitCode -eq 2) {
                LogMessage -message "WinRE was already disabled." -Type 1 -Component 'Disable-WinRE'
                return $true
            }
            else {
                LogMessage -message "Failed to disable WinRE. Exit code: $exitCode. Output: $($output -join "`n")" -Type 3 -Component 'Disable-WinRE'
                return $false
            }
        }
        catch {
            LogMessage -message "Exception occurred disabling WinRE: $($_.Exception.Message)" -Type 3 -Component 'Disable-WinRE'
            return $false
        }
    }

    function Enable-WinRE {
        <#
    .SYNOPSIS
    Enables the Windows Recovery Environment (WinRE) using ReAgentC.

    .DESCRIPTION
    Validates that WinRE.wim exists before running ReAgentC.exe /enable.
    Logs all output and confirms enablement by checking ReAgentC return code and running Get-WinREInfo afterward.

    .OUTPUTS
    [bool] - $true if WinRE was successfully enabled, otherwise $false.
    #>

        try {
            $reInfo = Get-WinREInfo
            if (-not $reInfo) {
                LogMessage -message "Enable-WinRE: Unable to retrieve WinRE info (Get-WinREInfo returned null)." -Type 3 -Component 'Enable-WinRE'
                return $false
            }

            $reImage = $reInfo.ImagePath
            if (-not $reImage -or -not (Test-Path $reImage)) {
                LogMessage -message "Cannot enable WinRE — WinRE.wim is missing at: $reImage" -Type 3 -Component 'Enable-WinRE'
                return $false
            }

            $output = ReAgentC.exe /enable 2>&1
            $exitCode = $LASTEXITCODE

            if ($exitCode -eq 0) {
                LogMessage -message "Enabled WinRE successfully. Output:`n$($output -join "`n")" -Type 1 -Component 'Enable-WinRE'

                # Re-check status to confirm
                $newStatus = Get-WinREInfo
                if ($newStatus -and $newStatus.WinREStatus -eq 'Enabled') {
                    return $true
                }
                else {
                    LogMessage -message "ReAgentC returned success, but WinREStatus is still not enabled." -Type 3 -Component 'Enable-WinRE'
                    return $false
                }
            }
            else {
                LogMessage -message "Failed to enable WinRE. Exit code: $exitCode. Output:`n$($output -join "`n")" -Type 3 -Component 'Enable-WinRE'
                return $false
            }
        }
        catch {
            LogMessage -message "Exception occurred enabling WinRE: $($_.Exception.Message)" -Type 3 -Component 'Enable-WinRE'
            return $false
        }
    }
    


    function Get-KeyPath {
        <#
        .SYNOPSIS
        Reads and returns all values from a specified registry key path under HKEY_LOCAL_MACHINE.

        .DESCRIPTION
        This function opens the specified HKLM registry key, enumerates its values, and returns them as 
        custom PowerShell objects including the value name, data, and type. Errors are logged but do not stop execution.

        .PARAMETER Path
        The full registry path (starting with HKLM:) to the key you want to inspect.

        .OUTPUTS
        [PSCustomObject] - One or more objects representing registry values with Name, Value, and Type.

        .EXAMPLE
        Get-KeyPath -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators"
        #>
        param(
            [Parameter(ValueFromPipeline = $true)]
            [string]$Path
        )

        process {
            try {
                $regPath = $Path -replace '^HKLM:', ''
                $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                    [Microsoft.Win32.RegistryHive]::LocalMachine,
                    [Microsoft.Win32.RegistryView]::Default
                )
                $subKey = $regKey.OpenSubKey($regPath)

                if ($subKey) {
                    foreach ($name in $subKey.GetValueNames()) {
                        LogMessage -message ("Found registry value: $name at $Path") -Component 'Get-KeyPath'
                        [pscustomobject]@{
                            Path  = $Path
                            Name  = $name
                            Value = $subKey.GetValue($name)
                            Type  = $subKey.GetValueKind($name)
                        }
                    }
                    $subKey.Close()
                }
            }
            catch {
                LogMessage -message ("Failed to read key: $Path - $($_.Exception.Message)") -Type 2 -Component 'Get-KeyPath'
            }
        }
    }

    function Get-LoggedOnUser {
        <#
        .SYNOPSIS
        Retrieves the usernames of all currently logged-on users.

        .DESCRIPTION
        This function queries all instances of explorer.exe processes via WMI and retrieves the user accounts 
        that own those processes. It returns a unique list of usernames associated with active desktop sessions.

        .OUTPUTS
        [string[]] - An array of usernames.

        .EXAMPLE
        Get-LoggedOnUser
        Returns: user1, user2
        #>
        try {
            $usernames = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" |
                ForEach-Object { $_.GetOwner() } |
                Select-Object -Unique -ExpandProperty User
            return $usernames
        }
        catch {
            return @()
        }
    }    
    
    function Delete-Fonts { 
        <#
    .SYNOPSIS
    Deletes font files, non-English language folders, and select vendor firmware files from the EFI system partition to free space.

    .DESCRIPTION
    This function mounts the system reserved EFI partition using the first available drive letter, 
    then removes all font files from the Fonts directory. It also deletes any language-specific 
    folders except for those specified in $PreserveLanguages, and removes leftover firmware update directories
    from vendors like HP. These actions help free up space required for Windows feature updates,
    particularly to resolve the "We couldn't update the system reserved partition" error.

    .REFERENCE
    https://support.microsoft.com/en-us/topic/-we-couldn-t-update-system-reserved-partition-error-installing-windows-10-46865f3f-37bb-4c51-c69f-07271b6672ac
    https://garytown.com/low-space-on-efi-system-partition-clean-up

    .EXAMPLE
    Delete-Fonts
    #>

        try {
            $Letter = ls function:[d-z]: -n | Where-Object { !(Test-Path $_) } | Select-Object -First 1
            if (-not $Letter) {
                LogMessage -Message ("No available drive letter found. Exiting.") -Type 3 -Component "Delete-Fonts"
                return
            }

            LogMessage -Message ("Using drive letter: $Letter. Mounting system reserved partition.") -Type 1 -Component "Delete-Fonts"

            $mountOutput = & cmd /c "mountvol $Letter /s 2>&1"
            if (-not [string]::IsNullOrWhiteSpace($mountOutput)) {
                LogMessage -Message ("Failed to mount volume. Error: $mountOutput") -Type 3 -Component "Delete-Fonts"
                return
            }

            $SizeBefore = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "$Letter" } | Select-Object -ExpandProperty FreeSpace
            $mbBefore = [math]::Round($SizeBefore / 1MB)
            LogMessage -Message ("Free space before deletions: $($mbBefore)MB") -Type 1 -Component "Delete-Fonts"

            try {
                Get-Item "$($Letter)\EFI\Microsoft\Boot\Fonts\*.*" -ErrorAction Stop | Remove-Item -Force
                LogMessage -Message "Fonts deleted successfully." -Type 1 -Component "Delete-Fonts"
            }
            catch {
                LogMessage -Message "Failed to delete fonts. Error: $_" -Type 3 -Component "Delete-Fonts"
                return
            }

            try {
                $bootLangFolders = Get-ChildItem "$($Letter)\EFI\Microsoft\Boot" -Directory -ErrorAction Stop
                foreach ($folder in $bootLangFolders) {
                    if ($folder.Name -match '^[a-z]{2}-[A-Z]{2}$') {
                        if ($PreserveLanguages -contains $folder.Name) {
                            LogMessage -Message "Preserved language folder: $($folder.Name)" -Type 1 -Component "Delete-Fonts"
                        }
                        else {
                            Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                            LogMessage -Message "Deleted language folder: $($folder.Name)" -Type 1 -Component "Delete-Fonts"
                        }
                    }
                    else {
                        LogMessage -Message "Skipped folder (not a language folder): $($folder.Name)" -Type 1 -Component "Delete-Fonts"
                    }
                }
            }
            catch {
                LogMessage -Message "Failed to delete language folders. Error: $_" -Type 3 -Component "Delete-Fonts"
                return
            }

            # Additional cleanup based on Garytown article
            $vendorPaths = @(
                "$($Letter):\EFI\HP\BIOS\Previous",
                "$($Letter):\EFI\HP\BIOS\Current",
                "$($Letter):\EFI\HP\DEVFW",
                "$($Letter):\EFI\Lenovo\fw",
                "$($Letter):\EFI\Dell\BIOS",
                "$($Letter):\EFI\ASUS\fw"
            )

            foreach ($path in $vendorPaths) {
                if (Test-Path $path) {
                    try {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                        LogMessage -Message "Deleted vendor firmware folder: $path" -Type 1 -Component "Delete-Fonts"
                    }
                    catch {
                        LogMessage -Message "Failed to delete vendor path $path. Error: $_" -Type 2 -Component "Delete-Fonts"
                    }
                }
            }

            $SizeAfter = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "$Letter" } | Select-Object -ExpandProperty FreeSpace
            $mbAfter = [math]::Round($SizeAfter / 1MB)
            LogMessage -Message ("Free space after deletions: $($mbAfter)MB") -Type 1 -Component "Delete-Fonts"

            # Unmount the EFI partition
            & cmd /c "mountvol $Letter /d"
            LogMessage -Message "Successfully dismounted volume and completed deletions." -Type 1 -Component "Delete-Fonts"

            return $true
        }
        catch {
            LogMessage -Message "Exception occurred during font deletion: $($_.Exception.Message)" -Type 3 -Component "Delete-Fonts"
            return $false
        }
    }


    function Resize-Disk {
        <#
        .SYNOPSIS
        Resizes the Windows Recovery (WinRE) partition to ensure sufficient free space for updates.

        .DESCRIPTION
        This function verifies and expands the WinRE partition if it has less than 400 MB of free space.
        It retrieves detailed disk and partition information, checks if adjacent unallocated space is available,
        and if not, attempts to shrink the OS partition to make room. The function also handles BitLocker 
        suspension, disables and re-enables WinRE, deletes and recreates the recovery partition, and formats it appropriately.

        It includes fallback logic to detect free space using Get-Volume, and avoids resizing if the required conditions aren't met.
        Backups of the WinRE.wim file are performed prior to deletion.

        .EXAMPLE
        Resize-Disk
        This will attempt to resize the recovery partition if needed, making the device compatible with future Windows updates.
        #>
        LogMessage -message ("Starting Resize-Disk operation") -Type 1 -Component 'Resize-Disk'

        # Get OS partition
        $OSDrive = $env:SystemDrive.Substring(0, 1)
        $OSPartition = Get-Partition -DriveLetter $OSDrive
        $OSPartition
        if (-not $OSPartition) {
            LogMessage -message ("ERROR: Could not retrieve OS partition info.") -Type 3 -Component 'Resize-Disk'
            return
        }

        # Call the function to get WinRE info
        $WinREInfo = Get-WinREInfo
        if (-not $WinREInfo) {
            LogMessage -message ("ERROR: WinRE info could not be retrieved.") -Type 3 -Component 'Resize-Disk'
            return
        } 
        $OSDiskIndex = $WinREInfo.DiskNumber
        $WinREPartitionIndex = $WinREInfo.winREPartitionNumber

        $WinREPartition = Get-Partition -DiskNumber $OSDiskIndex -PartitionNumber $WinREPartitionIndex -ErrorAction SilentlyContinue
        if (-not $WinREPartition) {
            LogMessage -message ("ERROR: WinRE partition not found.") -Type 3 -Component 'Resize-Disk'
            return
        }

        $diskInfo = Get-Disk -Number $OSDiskIndex -ErrorAction SilentlyContinue
        if (-not $diskInfo) {
            LogMessage -message ("ERROR: OS disk not found.") -Type 3 -Component 'Resize-Disk'
            return
        }
        $diskType = $diskInfo.PartitionStyle

        LogMessage -message ("OS Disk: $OSDiskIndex") -Component 'Resize-Disk'
        LogMessage -message ("OS Partition: $($OSPartition.PartitionNumber)") -Component 'Resize-Disk'
        LogMessage -message ("WinRE Partition: $WinREPartitionIndex") -Component 'Resize-Disk'
        LogMessage -message ("Disk Partition Style: $diskType") -Component 'Resize-Disk'

        $WinREPartitionSizeMB = $WinREInfo.winREPartitionSizeMB
        $WinREPartitionFreeMB = $WinREInfo.winREPartitionFreeMB

        if ($WinREPartitionFreeMB -eq 0) {
            try {
                $vol = Get-Volume -FileSystemLabel 'Recovery' -ErrorAction SilentlyContinue
                if ($vol) {
                    $WinREPartitionFreeMB = [math]::Round($vol.SizeRemaining / 1MB, 2)
                    LogMessage -message ("Fallback: Detected $WinREPartitionFreeMB MB free using Get-Volume.") -Component 'Resize-Disk'
                }
                else {
                    LogMessage -message ("No Recovery volume mounted. Cannot determine free space via Get-Volume.") -Type 2 -Component 'Resize-Disk'
                }
            }
            catch {
                LogMessage -message ("Error in fallback free space check: $_") -Type 2 -Component 'Resize-Disk'
            }
        }

        LogMessage -message ("WinRE Partition Size: $WinREPartitionSizeMB MB") -Component 'Resize-Disk'
        LogMessage -message ("WinRE Partition Free Space: $WinREPartitionFreeMB MB") -Component 'Resize-Disk'

        if ($WinREPartitionFreeMB -ge 400) {
            LogMessage -message ("WinRE partition already has >= 400MB free space. Skipping resize.") -Component 'Resize-Disk'
            return
        }

        $OSPartitionEnd = $OSPartition.Offset + $OSPartition.Size
        $UnallocatedSpace = $WinREPartition.Offset - $OSPartitionEnd

        if ($UnallocatedSpace -ge 400MB) {
            LogMessage -message ("Detected $([math]::Round($UnallocatedSpace/1MB))MB unallocated space between OS and WinRE partitions.") -Component 'Resize-Disk'
            LogMessage -message ("WinRE can be extended without shrinking OS.") -Component 'Resize-Disk'
            $NeedShrink = $false
        }
        else {
            $shrinkSize = 400MB - $UnallocatedSpace
            $targetOSSize = $OSPartition.Size - $shrinkSize
            $SupportedSize = Get-PartitionSupportedSize -DriveLetter $OSDrive
            if ($targetOSSize -lt $SupportedSize.SizeMin) {
                LogMessage -message ("ERROR: Shrinking OS would violate minimum size. Cannot proceed.") -Type 3 -Component 'Resize-Disk'
                return
            }
            $NeedShrink = $true
        }

        # Suspend BitLocker before any disk changes
        $bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($bitlocker -and $bitlocker.ProtectionStatus -eq 'On') {
            LogMessage -message ("Suspending BitLocker to modify WinRE.") -Component 'Resize-Disk'
            Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 0
        }

        # Backup WinRE BEFORE modifying partitions
        LogMessage -message ("Backing up current WinRE contents...") -Component 'Resize-Disk'
        if (-not (Backup-WinRE)) {
            LogMessage -message ("WARNING: WinRE backup failed or skipped.") -Type 2 -Component 'Resize-Disk'
            return
        }

        # Now it's safe to resize
        if ($NeedShrink) {
            LogMessage -message ("Shrinking OS partition by 400MB...") -Component 'Resize-Disk'
            Resize-Partition -DriveLetter $OSDrive -Size $targetOSSize -ErrorAction Stop
            Start-Sleep -Seconds 5
        }


        # Call the function to disable WinRE
        LogMessage -message ("Disabling WinRE...") -Component 'Resize-Disk'
        Disable-WinRE

        LogMessage -message ("Deleting old WinRE partition...") -Component 'Resize-Disk'
        Remove-Partition -DiskNumber $OSDiskIndex -PartitionNumber $WinREPartitionIndex -Confirm:$false
        Start-Sleep -Seconds 5

        LogMessage -message ("Creating new WinRE partition...") -Component 'Resize-Disk'
        if ($diskType -ieq 'GPT') {
            $partition = New-Partition -DiskNumber $OSDiskIndex -Size 750MB -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
        }
        else {
            $partition = New-Partition -DiskNumber $OSDiskIndex -Size 750MB -MbrType 0x27
        }
        Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'Recovery' -Confirm:$false

        # Call the function to enable WinRE
        LogMessage -message ("Re-enabling WinRE...") -Component 'Resize-Disk'
        if (-not (Enable-WinRE)) {
            LogMessage -message ("WinRE enable failed. Attempting to restore from backup...") -Type 2 -Component 'Resize-Disk'
            if (Restore-WinRE) {
                Enable-WinRE | Out-Null
            }
            else {
                LogMessage -message ("ERROR: WinRE restore failed. Manual intervention may be required.") -Type 3 -Component 'Resize-Disk'
            }
        }

        # Re-enable Bitlocker
        $bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($bitlocker.ProtectionStatus -eq 'Off' -and $bitlocker.VolumeStatus -eq 'FullyEncrypted') {
            LogMessage -message ("Resuming BitLocker protection.") -Component 'Resize-Disk'
            Resume-BitLocker -MountPoint $env:SystemDrive
        }

        LogMessage -message ("Resize operation complete.") -Component 'Resize-Disk'
    }  
        

    function Get-LastLines {

        <#
            .SYNOPSIS
            Reads the last N lines of a text file, even if it is locked by another process.

            .DESCRIPTION
            The Get-LastLines function reads the final N lines of a specified file, including log files that are actively in use or locked for writing.
            It uses low-level Win32 API calls to safely access locked files with read and write sharing permissions, emulating behavior similar to CMTrace.
            If the current PowerShell version does not support this access method, it falls back to a standard .NET stream reader.

            The function also supports optional live tailing using the -Follow switch, continuously monitoring the file for new lines.
            A timeout value can be specified with -Timeout to limit how long the function will monitor the file.

            Lines are returned through the -ProcessLine script block, which is executed for each line found.

            .EXAMPLE
            Get-LastLines -Path "C:\Logs\setupact.log" -LineCount 1000 -ProcessLine {
                if ($_ -match "Overall progress: \[100%\]") {
                    Write-Host "Upgrade reached 100%"
                }
            }

            .EXAMPLE
            Get-LastLines -Path "C:\Logs\setupact.log" -LineCount 500 -Follow -Timeout (New-TimeSpan -Minutes 30) -ProcessLine {
                if ($_ -match "ERROR") {
                    Write-Host "Error found: $_"
                }
            }
        #>
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [int]$LineCount = 1000,

            [ScriptBlock]$ProcessLine = {
                param($line)
                Write-Host $line
            },

            [switch]$Follow,

            [TimeSpan]$Timeout
        )

        $psMajorVersion = $PSVersionTable.PSVersion.Major
        if ($psMajorVersion -lt 5) {
            Write-Warning "PowerShell version too old for low-level file access. Using fallback method."
            return ($null -ne (Fallback-LastLines -Path $Path -LineCount $LineCount | Where-Object { & $ProcessLine $_ }))
        }

        try {
            Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class FileAccessHelper {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    public static FileStream OpenFile(string path) {
        const uint GENERIC_READ = 0x80000000;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint OPEN_EXISTING = 3;

        SafeFileHandle handle = CreateFile(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

        if (handle.IsInvalid) {
            throw new IOException("Unable to open file", Marshal.GetLastWin32Error());
        }

        return new FileStream(handle, FileAccess.Read);
    }
}
"@ -ErrorAction Stop

            $stream = [FileAccessHelper]::OpenFile($Path)
            $reader = New-Object System.IO.StreamReader($stream)

            try {
                $lines = New-Object System.Collections.Generic.List[string]

                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    $lines.Add($line)
                    if ($lines.Count -gt $LineCount) {
                        $lines.RemoveAt(0)
                    }
                }

                foreach ($line in $lines) {
                    if (& $ProcessLine $line) { return $true }
                }

                if ($Follow) {
                    $startTime = Get-Date
                    while ($true) {
                        Start-Sleep -Milliseconds 500
                        while (-not $reader.EndOfStream) {
                            $line = $reader.ReadLine()
                            if (& $ProcessLine $line) { return $true }
                        }
                        if ($Timeout -and ((Get-Date) - $startTime -gt $Timeout)) {
                            break
                        }
                    }
                }
                return $false
            }
            finally {
                $reader.Close()
            }
        }
        catch {
            Write-Warning "Failed to read from locked file using advanced method. Falling back."
            return ($null -ne (Fallback-LastLines -Path $Path -LineCount $LineCount | Where-Object { & $ProcessLine $_ }))
        }
    }

    function Fallback-LastLines {
        param (
            [string]$Path,
            [int]$LineCount = 1000
        )

        $lines = New-Object System.Collections.Generic.List[string]
        try {
            $reader = [System.IO.File]::OpenText($Path)
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                $lines.Add($line)
                if ($lines.Count -gt $LineCount) {
                    $lines.RemoveAt(0)
                }
            }
            $reader.Close()
        }
        catch {
            Write-Warning "Fallback method also failed: $_"
        }
        return $lines
    }

    # ------------------------------------
    # End Functions
    # ------------------------------------

    # ------------------------------------
    # Main execution
    # ------------------------------------

    # Clear the error
    $Error.Clear()

    # ------------------------------------
    # Examining the system to collect required info 
    # for the execution
    # Need to check WinRE status, collect OS and WinRE
    # partition info
    # ------------------------------------
    LogMessage -message ("Start time: $([DateTime]::Now)") -Type 1 -Component "Script"
    LogMessage -message ("Examining the system...") -Type 1 -Component "Script"

    
    ### BEGIN - Checking for the most basic requirements ####
    LogMessage -message ("Check for the most basic requirements before doing anything else") -Type 1 -Component 'Script' 
    # Checks TPM 2.0, UEFI Boot, Secure Boot
    LogMessage -message ("Checking for TPM 2.0, UEFI Boot, Secure Boot") -Type 1 -Component 'Script'
    $failures = @()

    # --- TPM 2.0 Check ---
    try {
        LogMessage -message ("Checking for TPM 2.0") -Type 1 -Component 'Script'
        $tpm = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm

        if (-not $tpm) {
            LogMessage -message ("TPM is not present or could not be queried") -Type 3 -Component 'TPM'
            $failures += "TPM is not present or could not be queried"
        }
        elseif ($tpm.SpecVersion -notmatch "2\.0") {
            LogMessage -message ("TPM version is not 2.0 (found: $($tpm.SpecVersion))") -Type 3 -Component 'TPM'
            $failures += "TPM version is not 2.0 (found: $($tpm.SpecVersion))"
        }
    }
    catch {
        LogMessage -message "TPM check failed: $($_.Exception.Message)" -Type 3 -Component 'TPM'
        $failures += "TPM check failed: $($_.Exception.Message)"
    }

    # --- UEFI Boot Mode Check ---
    if (Test-Path "$env:windir\System32\bcdedit.exe") {
        try {
            LogMessage -message ("Checking for UEFI Boot") -Component 'Boot Mode Check'
            $bcdOutput = & "$env:windir\System32\bcdedit.exe" 2>$null
            $bootMode = $bcdOutput | Select-String "path.*efi"
            if (-not $bootMode) {
                LogMessage -message ("System is booted in Legacy BIOS mode (not UEFI)") -Type 2 -Component 'Boot Mode Check'
                $failures += "System is booted in Legacy BIOS mode (not UEFI)"
            }
            else {
                LogMessage -message ("System is booted in UEFI mode") -Component 'Boot Mode Check'
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            if ($errorMessage -like "*The term 'bcdedit'*") {
                LogMessage -message ("WARNING: bcdedit.exe not found. Skipping boot mode check.") -Type 2 -Component 'Boot Mode Check'
                # Do not add this to $failures, just warn and continue
            }
            else {
                LogMessage -message ("Boot mode detection failed. Error: $errorMessage") -Type 3 -Component 'Boot Mode Check'
                $failures += "Boot mode detection failed: $errorMessage"
            }
        }
    }
    else {
        LogMessage -message ("WARNING: bcdedit.exe not found. Skipping boot mode check.") -Type 2 -Component 'Boot Mode Check'
    }
    
    # --- Secure Boot Check ---
    try {
        if (Confirm-SecureBootUEFI) {
            LogMessage -message ("All Good") -Type 1 -Component 'Confirm-SecureBootUEFI'
            # All good
        }
        else {
            LogMessage -message ("Secure Boot is disabled") -Type 3 -Component 'Confirm-SecureBootUEFI'
            $failures += "Secure Boot is disabled"
        }
    }
    catch {
        LogMessage -message ("Secure Boot not supported (likely Legacy BIOS mode)") -Type 3 -Component 'Confirm-SecureBootUEFI'
        $failures += "Secure Boot not supported (likely Legacy BIOS mode)"
    }

    ### EXIT If We Failed Any Hard Checks! ####
    if ($failures.Count -ge 1) {
        Logmessage -message ("Device does NOT meet Windows 11 upgrade requirements:") -Type 3 -Component 'Compatibility'
        $failures | ForEach-Object { Write-Output " - $_" }
        try { Stop-Transcript } catch {}
        exit 1    
    }
    ### END - Checking for the most basic requirements ####
    
    ### We Didn't Fail Any Hard Checks So We Will Continue The Upgrade Process! ####
    else {
        # Get system info
        $CSInfo = (Get-Computerinfo)
        $OS = $CSInfo.OSName
        $OSDisplayVersion = $CSInfo.OSDisplayVersion
        $Manufacturer = $CSInfo.CsManufacturer
        $Model = $CSInfo.CsModel
        $Type = $CSInfo.CsPCSystemType
        LogMessage -message ("We are working on a $($Manufacturer) $($Model) running $($OS) $($OSDisplayVersion). The system type is $($Type).") -Type 1 -Component 'ComputerInfo'

        ### BEGIN -  Delete the fonts to resolve "We couldn't update the system reserved partition" error. ####
        $partitionStyle = Get-PartitionStyle
        LogMessage -message ("The partition type is $($partitionStyle).") -Type 1 -Component 'Get-PartitionStyle'
        switch ($partitionStyle) {
            "GPT" {
                LogMessage -message  ("Partition style is: $partitionStyle. Delete Fonts.") -Type 2 -Component 'Get-PartitionStyle'     
                $Status = Delete-Fonts
                LogMessage -message  ("Font delete returned: $($Status)") -Type 1 -Component 'Delete-Fonts'   
            }

            "MBR" {        
                LogMessage -message  "Error: Unsupported partition style: $partitionStyle" -Type 3 -Component 'Get-PartitionStyle'        
            }
            default {
                LogMessage -message  "Error: Unsupported partition style: $partitionStyle" -Type 3 -Component 'Get-PartitionStyle'
            }
        }
        ### END -  Delete the fonts to resolve "We couldn't update the system reserved partition" error. ####


        ### BEGIN - Working On WinRE ####
        # Get WinRE partition info
        $InitialWinREStatus = Get-WinREInfo

        if ($InitialWinREStatus -and $InitialWinREStatus.Count -ge 1) {
            $WinREStatus = $InitialWinREStatus[0]

            if ($WinREStatus.WinREStatus -eq 'Enabled') {
                LogMessage -message "WinRE Enabled" -Type 1 -Component 'Get-WinREInfo' 

                # Get system directory and ReAgent.xml path
                $system32Path = [System.Environment]::SystemDirectory
                LogMessage -message "System directory: $system32Path" -Type 1 -Component 'Get-WinREInfo'
                $ReAgentXmlPath = "$system32Path\Recovery\ReAgent.xml"
                LogMessage -message "ReAgent xml: $ReAgentXmlPath" -Type 1 -Component 'Get-WinREInfo'

                if (-not (Test-Path $ReAgentXmlPath)) {
                    LogMessage -message "ReAgent.xml not found. Creating a new one..." -Type 2 -Component 'Get-WinREInfo'

                    # Create minimal structure for ReAgent.xml
                    $xml = New-Object System.Xml.XmlDocument
                    $declaration = $xml.CreateXmlDeclaration("1.0", "utf-8", $null)
                    $xml.AppendChild($declaration)

                    $root = $xml.CreateElement("WindowsRE")
                    $root.SetAttribute("version", "2.0")
                    $xml.AppendChild($root)

                    $nodeNames = @("ImageLocation", "PBRImageLocation", "PBRCustomImageLocation", "DownlevelWinreLocation")
                    foreach ($nodeName in $nodeNames) {
                        $node = $xml.CreateElement($nodeName)
                        $node.SetAttribute("path", "")
                        $node.SetAttribute("offset", "0")
                        $node.SetAttribute("guid", "{00000000-0000-0000-0000-000000000000}")
                        $node.SetAttribute("id", "0")
                        $root.AppendChild($node)
                    }

                    $xml.Save($ReAgentXmlPath)
                    LogMessage -message "Created and saved new ReAgent.xml at $ReAgentXmlPath." -Type 1 -Component 'Get-WinREInfo'
                }
                else {
                    LogMessage -message "ReAgent.xml found." -Type 1 -Component 'Get-WinREInfo'
                    LogMessage -message "We found the XML so let's read it just for fun. We might use this info one day, just not today. - PJM" -Type 1 -Component 'Get-WinREInfo'
                    $WinREDetails = Get-WinREInfo
                    $WinREDetails
                }

                LogMessage -message "Done." -Type 1 -Component 'Get-WinREInfo'

                # Attempt to back up WinRE before doing anything risky
                if (-not (Backup-WinRE)) {
                    LogMessage -message "We don't have a backup so we will skip this risky operation." -Type 2 -Component 'Backup-WinRE'
                    return
                }

                # Get RE version info for update decisions
                $WindowsRELocation = $WinREStatus.ImagePath
                $WindowsRELocationTrimmed = $WindowsRELocation.Trim()
                $DismImageFileArg = "/ImageFile:$WindowsRELocationTrimmed"

                LogMessage -message "WinRELocation: $WindowsRELocation"
                LogMessage -message "WinRELocationTrimmed: $WindowsRELocationTrimmed"
                LogMessage -message "DismImageFileArg: $DismImageFileArg"

                try {
                    $Output = Dism /Get-ImageInfo $DismImageFileArg /index:1 2>&1
                    if (-not $Output -or $Output.Count -eq 0 -or ($Output -join "`n") -match "Error") {
                        throw "DISM command failed or returned no output.`nOutput:`n$($Output -join "`n")"
                    }

                    $reVersion = ($Output | Select-String -Pattern '^Version\s+:\s+').ToString().Split(":")[1].Trim()
                    $spBuild = ($Output | Select-String -Pattern 'ServicePack Build').ToString().Split(":")[1].Trim()
                    $spLevel = ($Output | Select-String -Pattern 'ServicePack Level').ToString().Split(":")[1].Trim()

                    LogMessage -message "Version: $reVersion"
                    LogMessage -message "ServicePack Build: $spBuild"
                    LogMessage -message "ServicePack Level: $spLevel"

                    $spBuildInt = [int]$spBuild
                    $reVersionInt = [Version]$reVersion
                    LogMessage -message "ServicePack Build (Integer): $spBuildInt"
                }
                catch {
                    LogMessage -message "DISM failed: $($_.Exception.Message)" -Type 2
                    if (-not (Test-Path "$env:SystemRoot\System32\Recovery\WinRE.wim")) {
                        if (Restore-WinRE) {
                            LogMessage -message "WinRE.wim restored. You may retry the operation if needed." -Type 1
                        }
                        else {
                            LogMessage -message "Restore failed. Skipping WinRE operations." -Type 2
                        }
                    }
                    return
                }

                # Resize the partition if needed
                LogMessage -message "Running the Microsoft disk resize script." -Type 1 -Component 'Resize-Disk'
                try {
                    Resize-Disk
                }
                catch {
                    LogMessage -message "Resize-Disk failed: $($_.Exception.Message)" -Type 3 -Component 'Resize-Disk'
                    return
                }

                # Determine whether WinRE update is required
                if ($OS -contains "Windows 10") {
                    if ($reVersionInt) {
                        if ([version]$reVersionInt -ge [version]'10.0.19041.5025') {
                            LogMessage -message "WinRE version $reVersion is greater than or equal to 10.0.19041.5025. No update required."
                            return
                        }
                        elseif ($OSDisplayVersion -eq '22H2') {
                            $Download = 'C:\downloadedupdate\WinREUpdate.cab'
                            $doUpdate = $true

                            if (!(Test-Path 'C:\mount')) { New-Item -Path 'C:\mount' -ItemType Directory | Out-Null }
                            if (!(Test-Path 'C:\downloadedupdate')) { New-Item -Path 'C:\downloadedupdate' -ItemType Directory | Out-Null }

                            if (!(Test-Path $Download)) {
                                try {
                                    Invoke-WebRequest 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/crup/2024/10/windows10.0-kb5044615-x64_4b85450447ef0e6750ea0c0b576c6ba6605d2e4c.cab' -OutFile $Download
                                }
                                catch {
                                    LogMessage -message "Failed to download WinRE update: $($_.Exception.Message)" -Type 3
                                    return
                                }
                            }
                        }
                    }
                    else {
                        LogMessage -message "Old version of Windows 10 needs to be updated. No action taken."
                        return
                    }
                }

                # Perform update if necessary
                if ($doUpdate) {
                    LogMessage -message "WinRE requires an update."

                    if (Test-Path $Download) {
                        LogMessage -message "We have an update to install."

                        ReAgentC.exe /mountre /path C:\mount
                        Dism /Add-Package /Image:C:\mount\ /PackagePath:$Download
                        Dism /Image:C:\mount /Cleanup-Image /StartComponentCleanup /ResetBase
                        ReAgentC.exe /unmountre /path C:\mount /commit

                        try {
                            if (-not (Test-Path "$env:SystemRoot\System32\Recovery\WinRE.wim")) {
                                if (-not (Restore-WinRE)) {
                                    LogMessage -message "Restore failed. Cannot re-enable WinRE." -Type 3
                                    return
                                }
                            }
                            LogMessage -message 'Re-registering WinRE after update (Disable/Enable).'
                            Disable-WinRE
                            Enable-WinRE
                        }
                        catch {
                            LogMessage -message "Enable-WinRE failed: $($_.Exception.Message)" -Type 2
                        }
                    }
                    else {
                        LogMessage -message "Expected update file not found: $Download" -Type 3
                    }
                }                
            }
            else {
                LogMessage -message "WinREStatus object is null or invalid. Skipping WinRE operations." -Type 2 -Component 'Get-WinREInfo'               
            }
        }
        else {
            LogMessage -message "Get-WinREInfo returned null or empty. Skipping WinRE operations." -Type 2 -Component 'Get-WinREInfo'         
        }
        ### END - Working On WinRE ####
        

        ### BEGIN - Cleanup unsigned Microsoft print drivers ####
        LogMessage -message ('BEGIN - Cleanup unsigned Microsoft print drivers') -Component 'Clean-Drivers'
        Clean-Drivers
        ### END - Cleanup unsigned Microsoft print drivers ####

        ### BEGIN - Run the disk cleanup wizard ####
        $Freespace = (Get-WmiObject win32_logicaldisk -filter "DeviceID='C:'" | Select Freespace).FreeSpace / 1GB
        LogMessage -message ("Freespace before cleanup: $($FreeSpace) GB") -Component 'Disk-Cleanup'
        IF ($FreeSpace -le $MinRequiredFreeSpaceGB) {
            $Flags = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags1234 -ErrorAction SilentlyContinue
            if ($Flags) {
                LogMessage -message ('Found flags value') -Component 'Disk-Cleanup'
                Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags1234 | Remove-ItemProperty -Name StateFlags1234 -Force -ErrorAction SilentlyContinue
            }
            else {
                LogMessage -message ('No flag values found') -Component 'Disk-Cleanup'
            }

            LogMessage -message ('Enabling cleanup options.') -Component 'Disk-Cleanup'
            Get-ChildItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches' | New-ItemProperty -Name StateFlags1234 -Value 2 -PropertyType DWORD -Force
            LogMessage -message ('CleanMgr Starting') -Component 'Disk-Cleanup'

            Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1234' -WindowStyle Hidden -Wait

            LogMessage -message ('Cleanup complete') -Component 'Disk-Cleanup'
            $Freespace = (Get-WmiObject win32_logicaldisk -filter "DeviceID='C:'" | select Freespace).FreeSpace / 1GB
            LogMessage -message ("Freespace after cleanup: $($FreeSpace) GB") -Component 'Disk-Cleanup'     

        }
        Else {
            LogMessage -message ("Free space is good with: $($FreeSpace) GB") -Component 'Disk-Cleanup'
        }
        ### END - Run the disk cleanup wizard ####
    
        ### BEGIN - Appraiser  ###
        LogMessage -message ('Detecting Red reasons, clear them, re-run appraiser')

        # --- Get and evaluate GStatus ---
        LogMessage -message ('Getting G Status Paths')
        $GStatusArray = New-Object System.Collections.ArrayList
        $GStatusPaths = Get-ChildItem -Recurse $RegistryPathAppCompat |
            Get-KeyPath |
            Where-Object Name -eq $RegValueGStatus |
            Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue

        foreach ($Path in $GStatusPaths) {
            LogMessage -message ("Checking path: $Path") -Component 'Appraiser'
            $value = Get-ItemPropertyValue -Path $Path -Name $RegValueGStatus -ErrorAction SilentlyContinue
            if ($null -ne $value) { [void]$GStatusArray.Add($value.ToString()) }
        }

        # --- Get and evaluate UpgEx ---
        LogMessage -message ('Getting Upg Ex Paths') -Component 'Appraiser' 
        $UpgExArray = New-Object System.Collections.ArrayList
        $UpgExPaths = Get-ChildItem -Recurse $RegistryPathAppCompat |
            Get-KeyPath |
            Where-Object Name -eq $RegValueUpgEx |
            Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue

        foreach ($Path in $UpgExPaths) {
            LogMessage -message ("Checking path: $Path") -Component 'Appraiser'
            $value = Get-ItemPropertyValue -Path $Path -Name $RegValueUpgEx -ErrorAction SilentlyContinue
            if ($null -ne $value) { [void]$UpgExArray.Add($value) }
        }

        # --- Log collected values ---
        LogMessage -message ("Collected GStatus values: $($GStatusArray -join ', ')") -Component 'Appraiser'
        LogMessage -message ("Collected UpgEx values: $($UpgExArray -join ', ')") -Component 'Appraiser'

        # --- Determine upgrade blocker state ---
        $hasBlockers = $false
        if ($GStatusArray | Where-Object { $_ -ne '2' }) {
            LogMessage -message "GStatus indicates safeguard hold (not all values are '2')" -Component 'Appraiser'
            $hasBlockers = $true
        }
        if ($UpgExArray | Where-Object { $_ -eq 'Red' }) {
            LogMessage -message "UpgEx indicates ineligibility (found 'Red')" -Component 'Appraiser'
            $hasBlockers = $true
        }

        if ($hasBlockers) {
            LogMessage -message "Blockers found. Running the appraiser." -Component 'Appraiser'

            $Red = $true
            $RedValues = @()
            $RedPaths = Get-ChildItem -Recurse $RegistryPathAppCompat |
                Get-KeyPath |
                Where-Object Name -eq $RegValueRedReason |
                Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue

            foreach ($Path in $RedPaths) {
                LogMessage -message ("Found red path: $($Path) Delete it!") -Component 'Appraiser'
                Remove-Item -Path $Path -ErrorAction SilentlyContinue
            }

            $Markers = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CompatMarkers\' |
                Select-Object -ExpandProperty Name 
            foreach ($Marker in $Markers) {
                LogMessage -message ("Found marker: $($Marker). Delete it!") -Component 'Appraiser'
                Remove-Item -Path "Registry:$Marker" -ErrorAction SilentlyContinue
            }

            $Caches = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\WuCache\' |
                Select-Object -ExpandProperty Name 
            foreach ($Cache in $Caches) {
                LogMessage -message ("Found cache: $($Cache). Delete it!") -Component 'Appraiser'
                Remove-Item -Path "Registry::$Cache" -ErrorAction SilentlyContinue
            }

            LogMessage -message ("Appraiser path: $CompatAppraiserPath") -Component 'Appraiser'
            if (Test-Path $CompatAppraiserPath) {
                LogMessage -message ('Running compatibility appraisers...') -Component 'Appraiser'

                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:appraiser.dll -f:DoScheduledTelemetryRun' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:appraiser.dll -f:UpdateAvStatus' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:devinv.dll -f:CreateDeviceInventory' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:pcasvc.dll -f:QueryEncapsulationSettings' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:invagent.dll -f:RunUpdate' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:aemarebackup.dll -f:BackupMareData' -WindowStyle Hidden -Wait -PassThru

                # --- Retest for blockers ---
                LogMessage -message ('Retest for upgrade blockers') -Component 'Appraiser'
                $GStatusArray = New-Object System.Collections.ArrayList
                $GStatusPaths = Get-ChildItem -Recurse $RegistryPathAppCompat |
                    Get-KeyPath |
                    Where-Object Name -eq $RegValueGStatus |
                    Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue

                foreach ($Path in $GStatusPaths) {
                    LogMessage -message ("Found new GStatus entry: $($Path)") -Component 'Appraiser'
                    $value = Get-ItemPropertyValue -Path $Path -Name $RegValueGStatus -ErrorAction SilentlyContinue
                    if ($null -ne $value) { [void]$GStatusArray.Add($value.ToString()) }
                }

                $UpgExArray = New-Object System.Collections.ArrayList
                $UpgExPaths = Get-ChildItem -Recurse $RegistryPathAppCompat |
                    Get-KeyPath |
                    Where-Object Name -eq $RegValueUpgEx |
                    Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue

                foreach ($Path in $UpgExPaths) {
                    LogMessage -message ("Found new UpgEx entry: $($Path)") -Component 'Appraiser'
                    $value = Get-ItemPropertyValue -Path $Path -Name $RegValueUpgEx -ErrorAction SilentlyContinue
                    if ($null -ne $value) { [void]$UpgExArray.Add($value) }
                }

                $hasBlockers = $false
                if ($GStatusArray | Where-Object { $_ -ne '2' }) {
                    LogMessage -message "GStatus still indicates safeguard hold." -Component 'Appraiser'
                    $hasBlockers = $true
                }
                if ($UpgExArray | Where-Object { $_ -ne 'Green' }) {
                    LogMessage -message "UpgEx still indicates ineligibility." -Component 'Appraiser'
                    $hasBlockers = $true
                }

                if ($hasBlockers) {
                    LogMessage -message 'ERROR: Found new upgrade blockers!' -Component 'Appraiser' -Type 3
                }
                else {
                    LogMessage -message 'Resolved' -Component 'Appraiser'
                }
            }
            else {
                LogMessage -message ("ERROR: Appraiser not found at path: $CompatAppraiserPath") -Component 'Appraiser' -Type 3
            }
        }
        else {
            LogMessage -message "No blockers found. Skip running the appraiser." -Component 'Appraiser'
        }
        LogMessage -message ('END - Detecting Red reasons, clear them, re-run appraiser') -Component 'Appraiser'
        ### END - Appraiser  ###

 

        ### Begin - Windows 11 Upgrade ####
        LogMessage -message ("Starting the Windows 11 Upgrade") -Component 'Script'

        # Check and clean up any existing Windows11InstallationAssistant process
        $existingUpgradeProcess = Get-Process -Name "Windows11InstallationAssistant" -ErrorAction SilentlyContinue
        if ($existingUpgradeProcess) {
            LogMessage -message ("WARNING: Windows11InstallationAssistant.exe already running (PID $($existingUpgradeProcess.Id)). Attempting to terminate...") -Type 2 -Component 'Upgrade'
            try {
                $existingUpgradeProcess | Stop-Process -Force -ErrorAction Stop
                LogMessage -message ("Successfully terminated existing Windows11InstallationAssistant.exe.") -Type 2 -Component 'Upgrade'
            }
            catch {
                LogMessage -message ("Failed to terminate existing Windows11InstallationAssistant.exe. Error: $_") -Type 3 -Component 'Upgrade'
                Stop-Transcript
                throw "Cannot proceed while Windows11InstallationAssistant.exe is still running."
            }
        }
        else {
            LogMessage -message ("No existing Windows11InstallationAssistant.exe processes found.") -Component 'Upgrade'
            LogMessage -message ("It is safe to start Windows11InstallationAssistant.exe.") -Component 'Upgrade'
        }
 
        # Check and clean up any existing windows10upgraderapp.exe processes
        $existingUpgradeProcess = Get-Process -Name "windows10upgraderapp" -ErrorAction SilentlyContinue
        if ($existingUpgradeProcess) {
            LogMessage -message ("WARNING: windows10upgraderapp.exe already running (PID $($existingUpgradeProcess.Id)). Attempting to terminate...") -Type 2 -Component 'Upgrade'
            try {
                $existingUpgradeProcess | Stop-Process -Force -ErrorAction Stop
                LogMessage -message ("Successfully terminated existing windows10upgraderapp.exe.") -Type 2 -Component 'Upgrade'
            }
            catch {
                LogMessage -message ("Failed to terminate existing windows10upgraderapp.exe. Error: $_") -Type 3 -Component 'Upgrade'
                Stop-Transcript
                throw "Cannot proceed while windows10upgraderapp.exe is still running."
            }
        }
        else {
            LogMessage -message ("No existing windows10upgraderapp.exe processes found.") -Component 'Upgrade'
            LogMessage -message ("It is safe to start windows10upgraderapp.exe.") -Component 'Upgrade'
        }                 
    

        # ========================================
        # Initialize WebClient
        # ========================================
        # Creates a reusable WebClient object for downloading files from remote URLs.
        # This should only be created once and reused as needed throughout the script.
        # NOTE: Proxy settings, headers, or timeout settings can be configured here if required.

        $webClient = New-Object System.Net.WebClient

        # END: Initialize WebClient

        # ========================================
        # ServiceUI.exe Handling
        # ========================================
        # Supports both:
        # - Local file (bundled in package)
        # - HTTPS URL (downloaded)

        $loggedOnUsers = Get-LoggedOnUser

        if ($loggedOnUsers.Count -gt 0) {
            LogMessage -message ("Detected logged-on users: $($loggedOnUsers -join ', ')") -Component 'Script'

            if ($ServiceUIPath -like 'https://*') {
                try {
                    LogMessage -message ("Downloading ServiceUI.exe from $ServiceUIPath ...") -Component 'Script'
                    $webClient.DownloadFile($ServiceUIPath, $ServiceUIDestination)
                    LogMessage -message ("Successfully downloaded ServiceUI.exe.") -Component 'Script'
                    LogMessage -message ("ServiceUI.exe saved to $ServiceUIDestination ...") -Component 'Script'
                }
                catch {
                    LogMessage -message ("Failed to download ServiceUI.exe. Error: $_") -Type 3 -Component 'Script'
                }
            }
            elseif (Test-Path $ServiceUIPath) {
                try {
                    LogMessage -message ("Copying ServiceUI.exe from local package to working directory...") -Component 'Script'
                    Copy-Item -Path $ServiceUIPath -Destination $ServiceUIDestination -Force
                    LogMessage -message ("Successfully copied ServiceUI.exe.") -Component 'Script'
                }
                catch {
                    LogMessage -message ("Failed to copy local ServiceUI.exe. Error: $_") -Type 3 -Component 'Script'
                }
            }
            else {
                LogMessage -message ("ServiceUI.exe not found at specified path: $ServiceUIPath") -Type 2 -Component 'Script'
            }
        }
        else {
            LogMessage -message ("No logged-on users detected. Skipping ServiceUI.exe handling.") -Component 'Script'
        }
        # END: ServiceUI.exe Handling

        
        # Set the URL to download the Windows 11 Installation Assistant file from
        $Windows11InstallationAssistantUrl = 'https://go.microsoft.com/fwlink/?linkid=2171764'   
 
        # Set the file path for the downloaded Windows 11 Installation Assistant file
        $Windows11InstallationAssistantPath = "$($Win11WorkingDirectory)\Windows11InstallationAssistant.exe"

        # Download the Windows 11 Installation Assistant if it hasn't been previously downloaded
        if (-not (Test-Path $Windows11InstallationAssistantPath)) {
            try {
                LogMessage -message ("Downloading the Windows 11 Installation Assistant to $Windows11InstallationAssistantPath...") -Component 'Script'
                $webClient.DownloadFile($Windows11InstallationAssistantUrl, $Windows11InstallationAssistantPath)
                LogMessage -message ("Successfully downloaded Windows 11 Installation Assistant.") -Component 'Script'
            }
            catch {
                LogMessage -message ("Failed to download Windows 11 Installation Assistant. Error: $_") -Type 3 -Component 'Script'
                try { Stop-Transcript } catch {}
                throw "Cannot proceed without Windows 11 Installation Assistant."
            }
        }
        else {
            LogMessage -message ("Found previously downloaded Windows 11 Installation Assistant in $Windows11InstallationAssistantPath ....") -Component 'Script'
        } 

        # Prestage regkeys for the disk cleanup wizard to run after first login to Windows 11
        LogMessage -message ("Prestage regkeys for the disk cleanup wizard to run after first login to Windows 11") -Component 'ScheduledTask'
        Get-ChildItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches' |
            ForEach-Object {
                New-ItemProperty -Path $_.PsPath -Name StateFlags1234 -Value 2 -PropertyType DWORD -Force
            }
    
        # Create scheduled task to reclaim disk space at first login.
        $taskName = "OneTimeCleanMgrAfterWin11Upgrade"
        $scriptPath = "$($Win11WorkingDirectory)\$taskName.ps1"

        # Check for, and remove, exsisting scheduled task
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }

        # Build the actual script content separately (easy to maintain)
        $taskScript = @"
if ((Get-WmiObject Win32_OperatingSystem).Caption -Match "Windows 11"){
Start-Process CleanMgr.exe -ArgumentList '/sagerun:1234' -WindowStyle Hidden -Wait
}
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:\$false
"@


        # Write it to disk
        Set-Content -Path $scriptPath -Value $taskScript -Encoding UTF8

        # Define the task settings
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $trigger.ExecutionTimeLimit = "PT1H" 
        $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Priority 1
        $settings.MultipleInstances = 'IgnoreNew'
        $settings.WakeToRun = $true
        $settings.Enabled = $true

        # Register the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal

        # Enable task history
        schtasks /Change /TN "$TaskName" /ENABLE


        #  Start Windows 11 Installation Assistant with or without ServiceUI        
        try {
            if ($loggedOnUsers.Count -gt 0 -and (Test-Path $ServiceUIDestination)) {
                LogMessage -message ("ServiceUI.exe found at: $ServiceUIDestination")
                LogMessage -message ("Starting Windows11InstallationAssistant.exe through ServiceUI.exe (visible to user)...") -Component 'Upgrade'
                $proc = Start-Process -FilePath $ServiceUIDestination -ArgumentList "-process:explorer.exe `"$Windows11InstallationAssistantPath`" $upgradeArgs" -PassThru
            }
            else {
                LogMessage -message ("ServiceUI.exe not found at: $ServiceUIDestination")
                LogMessage -message ("Starting Windows11InstallationAssistant.exe directly (Failed to detect logged on user or path to serviceui.exe)...") -Component 'Upgrade'
                $proc = Start-Process -FilePath $Windows11InstallationAssistantPath -ArgumentList $upgradeArgs -PassThru
            }

            LogMessage -message ("Started Windows11InstallationAssistant.exe with process id $($proc.Id).") -Component 'Upgrade'

            # Wait for setupact.log to appear
            $setupactLogPath = 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log'
            $maxDuration = New-TimeSpan -Hours 2
            $startTime = Get-Date

            LogMessage -message ("Started monitoring the upgrade process at $startTime")
            LogMessage -message ("Will wait for $maxDuration")

            while (-not (Test-Path $setupactLogPath)) {
                LogMessage -message ("Waiting for $setupactLogPath to appear...") -Type 1 -Component 'Upgrade'
                Start-Sleep -Seconds 30
                if ((Get-Date) - $startTime -gt $maxDuration) {
                    throw "Timeout waiting for setupact.log to appear."
                }
            }

            LogMessage -message ("Found the setupact.log")
            LogMessage -message ("Monitoring for 'Overall progress: [100%]'...") -Type 1 -Component 'Upgrade'

            $result = Get-LastLines -Path $setupactLogPath -LineCount 1000 -Follow -Timeout $maxDuration -ProcessLine {
                param($line)
                if ($line -match "Overall progress: \[100%\]") {
                    LogMessage -message ("Detected 100% upgrade progress!") -Type 1 -Component 'Upgrade'
                    return $true
                }
                return $false
            }

            if (-not $result) {
                LogMessage -message ("Timeout waiting for 100% line in setupact.log") -Type 3 -Component 'Upgrade'
                LogMessage -message ("Assume failure.") -Type 2 -Component 'Upgrade'
                
                
                LogMessage -message ("Removing the scheduled task to preserve logs.") -Type 1 -Component 'Upgrade'
                # Check for, and remove, exsisting scheduled task
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($task) {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                }
                
                try { Stop-Transcript } catch {}
                exit 1
            }

        }
        catch {
            LogMessage -message ("Upgrade monitoring failed: $_") -Type 3 -Component 'Upgrade'
            try { Stop-Transcript } catch {}
            Write-Host "Failed to complete upgrade process."
            exit 1
        }
    }
}
Stop-Transcript
Exit 0

