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
    [string]$ServiceUIPath = "https://st398314intune01.blob.core.windows.net/serviceui/ServiceUI.exe",
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
[int]$ScriptVersion = 21.2


# ========================================
# Variables: Logging
# ========================================
$Now = Get-Date -Format MM-dd-yyyy-HH-mm-ss
$LogFile = "C:\Windows\Logs\Win11_Upgrade-$Now.log"
$DriverLog = "C:\Windows\Logs\UnsignedPrinterDrivers.csv"
$TranscriptFile = "C:\Windows\Logs\Win11_Upgrade_Transcript-$Now.log"
Start-Transcript -Path $TranscriptFile
Write-Host "Starting upgrade using script version: $($ScriptVersion)"


# ========================================
# Variables: Script Configuration
# ========================================
$upgradeArgs = "/quietinstall /skipeula /auto upgrade /copylogs $Win11WorkingDirectory"


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
# Variables: Default time (min) to sleep when caling sleepNow
# ========================================
[int]$sleepTime = 30

# ------------------------------------
# End Defining Script Variables
# ------------------------------------

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
        Writes a formatted log message to both the console and a persistent log file.

        .DESCRIPTION
        This function logs messages with a timestamp, severity level (INFO, WARN, ERROR), and an optional component label. 
        It outputs messages to the console using color-coding and always appends the same message to the global log file defined by $LogFile.

        .PARAMETER Message
        The message text to log. Required.

        .PARAMETER Component
        An optional label identifying the component or function emitting the log message. Defaults to 'Script'.

        .PARAMETER Type
        An integer indicating the severity level:
        1 = INFO (gray), 2 = WARN (yellow), 3 = ERROR (red). Defaults to 1.

        .EXAMPLE
        LogMessage -Message "Starting WinRE analysis" -Component "Get-WinREInfo"

        .EXAMPLE
        LogMessage -Message "Failed to detect UEFI mode" -Component "BootCheck" -Type 3

        .NOTES
        Output is written to both the screen and to $LogFile.
        #>
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,

            [string]$Component = "Script",

            [ValidateSet('1', '2', '3')]
            [int]$Type = 1  # 1=Normal, 2=Warning, 3=Error
        )

        $timeStamp = Get-Date -Format "HH:mm:ss"
        $dateStamp = Get-Date -Format "yyyy-MM-dd"
        $levelText = switch ($Type) {
            1 { "INFO" }
            2 { "WARN" }
            3 { "ERROR" }
        }

        $formattedMessage = "[${dateStamp} ${timeStamp}] [$levelText] [$Component] $Message"

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
        Detects and removes unsigned Microsoft printer drivers that may block Windows 11 upgrades.

        .DESCRIPTION
        This function scans all installed printer drivers, identifies those published by Microsoft that are unsigned, 
        and removes them along with any associated printers. It then reinstalls built-in Microsoft virtual printers 
        (such as Microsoft Print to PDF and XPS Document Writer) if they were removed. 

        Unsigned drivers are logged to a CSV file for reference.

        .OUTPUTS
        None. Writes log entries and exports a CSV of unsigned drivers to $driverLog.

        .NOTES
        This remediation targets known upgrade blocks related to legacy unsigned Microsoft print drivers 
        (e.g., Type 3 kernel-mode drivers).
        #>
        Write-Host "Scanning installed printer drivers..."
        $unsignedDrivers = @()
        $removedDrivers = @()
        Get-PrinterDriver | ForEach-Object {
            $driver = $_
            $driverName = $driver.Name

            # Get detailed info from Win32_PrinterDriver
            $wmiDriver = Get-WmiObject -Query "SELECT * FROM Win32_PrinterDriver WHERE Name = '$driverName'" -ErrorAction SilentlyContinue

            if ($wmiDriver -and $wmiDriver.DriverPath -and (Test-Path $wmiDriver.DriverPath)) {
                $sig = Get-AuthenticodeSignature -FilePath $wmiDriver.DriverPath

                if ($sig.Status -ne 'Valid' -and $driver.Publisher -like '*Microsoft*') {
                    LogMessage -message ("Unsigned Microsoft driver found: $driverName")
                    $unsignedDrivers += [PSCustomObject]@{
                        DriverName      = $driverName
                        DriverPath      = $wmiDriver.DriverPath
                        SignatureStatus = $sig.Status
                        Publisher       = $driver.Publisher
                    }
                }
            }
        }

        # Log results
        if ($unsignedDrivers.Count -gt 0) {
            $unsignedDrivers | Export-Csv -Path $driverLog -NoTypeInformation
            LogMessage -message ("Logged unsigned drivers to $driverLog") -Type 1 -Component 'Clean-Drivers'

            # Remove associated printers first
            LogMessage -message ("Removing printers using unsigned drivers...") -Type 1 -Component 'Clean-Drivers'
            Get-Printer | Where-Object { $_.DriverName -in $unsignedDrivers.DriverName } | ForEach-Object {
                LogMessage -message (" - > Removing printer: $($_.Name)") -Type 1 -Component 'Clean-Drivers'
                Remove-Printer -Name $_.Name -ErrorAction SilentlyContinue
            }

            # Remove the unsigned drivers
            LogMessage -message ("Removing unsigned Microsoft printer drivers...") -Type 1 -Component 'Clean-Drivers'
            foreach ($driver in $unsignedDrivers) {
                LogMessage -message ("  -> Removing driver: $($driver.DriverName)") -Type 1 -Component 'Clean-Drivers'
                Remove-PrinterDriver -Name $driver.DriverName -ErrorAction SilentlyContinue
                $removedDrivers += $driver.DriverName
            }

            # Conditionally reinstall Microsoft virtual printers if removed
            if ($removedDrivers -match "Microsoft Print to PDF") {
                LogMessage -message ("Reinstalling Microsoft Print to PDF...") -Type 1 -Component 'Clean-Drivers'
                Add-WindowsCapability -Online -Name "Printing.PrintToPDF~~~~0.0.1.0" -ErrorAction SilentlyContinue
            }

            if ($removedDrivers -match "Microsoft XPS Document Writer") {
                LogMessage -message ("Reinstalling Microsoft XPS Document Writer...") -Type 1 -Component 'Clean-Drivers'
                Add-WindowsCapability -Online -Name "Printing.XPSServices~~~~0.0.1.0" -ErrorAction SilentlyContinue
            }
        }
        else {
            LogMessage -message ("No unsigned Microsoft printer drivers found.") -Type 1 -Component 'Clean-Drivers'
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
        Backs up the existing WinRE.wim file to a safe location before performing partition modifications.

        .DESCRIPTION
        Copies the WinRE image from the default system recovery path (C:\Windows\System32\Recovery\WinRE.wim)
        to a predefined backup directory (C:\WinRE_Backup). Ensures the backup folder exists and logs success or failure.

        This function is called before any operation that may delete or modify the WinRE partition, such as resizing.

        .OUTPUTS
        Boolean
        Returns $true if the backup was successful, otherwise $false.

        .EXAMPLE
        Backup-WinRE
        # Attempts to copy WinRE.wim to C:\WinRE_Backup and logs the result.
        #>
        $sourcePath = "$env:SystemRoot\System32\Recovery\WinRE.wim"
        $backupPath = "C:\winre_backup\WinRE.wim"

        LogMessage -message ("Backing up WinRE from $sourcePath to $backupPath") -Component 'Backup-WinRE'

        if (Test-Path $sourcePath) {
            try {
                Copy-Item -Path $sourcePath -Destination $backupPath -Force
                LogMessage -message ("Backed up WinRE.wim to $backupPath") -Component 'Backup-WinRE'
                return $true  
            }
            catch {
                LogMessage -message ("Failed to back up WinRE.wim: $($_.Exception.Message)") -Type 3 -Component 'Backup-WinRE'
                return $false
            }
        }
        else {
            LogMessage -message ("No WinRE.wim found at $sourcePath to back up") -Type 2 -Component 'Backup-WinRE'
            return $false
        }
    }

    function Restore-WinRE {
        <#
        .SYNOPSIS
        Restores the WinRE.wim file from backup if it was previously saved.

        .DESCRIPTION
        Copies the backed-up WinRE image from C:\WinRE_Backup\WinRE.wim to the system recovery location at
        C:\Windows\System32\Recovery\WinRE.wim. This is used to recover WinRE functionality if it was lost
        or corrupted during disk partitioning or upgrade remediation operations.

        Checks for the existence of the backup file and logs the outcome of the restore process.

        .OUTPUTS
        Boolean
        Returns $true if the restore was successful, otherwise $false.

        .EXAMPLE
        Restore-WinRE
        # Restores WinRE.wim from backup if needed and logs the operation.
        #>
        $backupFile = "C:\WinRE_Backup\WinRE.wim"
        $targetPath = "$env:SystemRoot\System32\Recovery"

        if (Test-Path $backupFile) {
            Copy-Item -Path $backupFile -Destination (Join-Path $targetPath "WinRE.wim") -Force
            LogMessage -message ("Restored WinRE.wim to $targetPath") -Component 'Restore-WinRE'

            # Re-register WinRE image
            reagentc /setreimage /path $targetPath /target $env:SystemRoot | Out-Null
            LogMessage -message ("ReAgentc /setreimage executed.") -Component 'Restore-WinRE'
        }
        else {
            LogMessage -message ("ERROR: Cannot restore WinRE. Backup not found at $backupFile") -Type 3 -Component 'Restore-WinRE'
        }
    }
    
    function Get-WinREInfo {
        <#
        .SYNOPSIS
        Retrieves detailed information about the current WinRE (Windows Recovery Environment) partition.

        .DESCRIPTION
        This function gathers partition and disk layout information related to WinRE. It checks if the recovery agent is enabled,
        parses the disk and partition number from `reagentc /info`, retrieves partition layout using PowerShell disk utilities,
        and calculates available space using `Get-PartitionSupportedSize`.

        The returned object contains useful WinRE metadata such as disk number, partition number, partition style, size,
        free space, and position in the partition table.

        If WinRE is disabled, missing, or incorrectly configured, the function returns $null and logs the issue.

        .OUTPUTS
        [PSCustomObject] with the following properties:
        - ImagePath
        - DiskNumber
        - WinREImageLocation
        - PartitionStyle
        - LastPartition
        - OSIsLast
        - winREPartitionSizeMB
        - winREPartitionFree
        - winREPartitionFreeMB
        - winREIsLast
        - DiskIndex
        - OSPartition
        - winREPartitionNumber

        .EXAMPLE
        $info = Get-WinREInfo
        if ($info) { Write-Host "WinRE partition size: $($info.winREPartitionSizeMB) MB" }
        #>
   
        LogMessage -message ("Retrieving current WinRE Info") -Type 1 -Component 'Get-WinREInfo'

        try {
            $WinreInfo = reagentc /info
            $RecoveryPartitionStatus = $WinreInfo.split("`n")[3].split(' ')[-1]

            if ($RecoveryPartitionStatus -eq 'Enabled') {
                LogMessage -message ("Recovery Agent is enabled") -Type 1 -Component 'Get-WinREInfo'

                [xml]$ReAgentXML = Get-Content "$env:SystemRoot\System32\Recovery\ReAgent.xml" -ErrorAction Stop

                # Continue with analysis regardless of GUID
                $WinREImagepath = "$env:SystemRoot\System32\Recovery\WinRE.wim"

                $OSPartitionObject = Get-Partition -DriveLetter ($env:SystemDrive).Substring(0, 1)
                $WinREImageLocationDisk = $OSPartitionObject.DiskNumber
                $WinREImageLocationPartition = $OSPartitionObject.PartitionNumber

                # Parse output for actual WinRE partition path
                $ReAgentCCurrentDrive = $WinreInfo.split("`n")[4].Substring(31).Trim() -replace '\0', ''
                $recoveryPathInfo = $ReAgentCCurrentDrive -replace '\\\?\\GLOBALROOT\\device\\', ''

                if ($recoveryPathInfo -match 'harddisk(\d+).*partition(\d+)') {
                    $RecoveryDiskNumber = [int]$matches[1]
                    $RecoveryPartitionNumber = [int]$matches[2]
                }
                else {
                    LogMessage -message ("Unable to extract disk and partition number from ReAgentC output.") -Type 2 -Component 'Get-WinREInfo'
                    return $null
                }

                $RecoveryPartition = Get-Partition -DiskNumber $RecoveryDiskNumber -PartitionNumber $RecoveryPartitionNumber -ErrorAction SilentlyContinue
                if (-not $RecoveryPartition) {
                    LogMessage -message ("Recovery partition not found.") -Type 2 -Component 'Get-WinREInfo'
                    return $null
                }

                $diskInfo = Get-Disk -Number $RecoveryDiskNumber
                $PartitionStyle = $diskInfo.PartitionStyle
                $LastPartitionNumber = (Get-Partition -DiskNumber $RecoveryDiskNumber | Sort-Object Offset | Select-Object -Last 1).PartitionNumber

                # Try Get-PartitionSupportedSize
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

                # Logging
                LogMessage -message ("Recovery partition size: $($RecoveryPartitionSize) MB") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("Recovery partition free space: $($RecoveryPartitionFreeMB) MB") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("Recovery is last partition? $($RecoveryIsLastPartition)") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("OS is last partition? $($OSIsLast)") -Type 1 -Component 'Get-WinREInfo'
                LogMessage -message ("Partition Style: $($PartitionStyle)") -Type 1 -Component 'Get-WinREInfo'

                return [PSCustomObject]@{
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
                }
            }
            else {
                LogMessage -message ("Recovery Agent is NOT enabled.") -Type 2 -Component 'Get-WinREInfo'
                return $null
            }
        }
        catch {
            LogMessage -message ("Failed to retrieve WinRE information: $($_.Exception.Message)") -Type 3 -Component 'Get-WinREInfo'
            return $null
        }
    }
  
    function Disable-WinRE {
        <#
        .SYNOPSIS
        Disables the Windows Recovery Environment (WinRE) using reagentc.

        .DESCRIPTION
        Uses the reagentc.exe command-line tool to disable WinRE. Interprets common return conditions to determine
        if the disable operation succeeded, failed, or was unnecessary (already disabled).

        Logs status and returns `$true` if WinRE was successfully disabled or already disabled.
        Returns `$false` if the operation failed.

        .OUTPUTS
        [bool] - $true if WinRE was disabled or already disabled, otherwise $false.

        .EXAMPLE
        if (-not (Disable-WinRE)) {
            Write-Host "Failed to disable WinRE"
        }
        #>
        $DisableRE = ReAgentc.exe /disable
        if ($LASTEXITCODE -eq 2 -or ($LASTEXITCODE -eq 0 -and ($DisableRE) -and ($DisableRE[0] -notmatch ".*\d+.*"))) {
            LogMessage -message ("Disabled WinRE") -Type 1 -Component 'Disable-WinRE'      
            return $true
        }
        else {
            LogMessage -message ("Disabling WinRE failed") -Type 1 -Component 'Disable-WinRE'
            return $false
        }
    }
 
    function Enable-WinRE {
        <#
        .SYNOPSIS
        Enables the Windows Recovery Environment (WinRE) using reagentc.

        .DESCRIPTION
        Uses the reagentc.exe tool to re-enable WinRE after modifications. Validates success by checking the exit code
        and parsing the output. Logs the result and returns a boolean indicating success or failure.

        .OUTPUTS
        [bool] - $true if WinRE was successfully enabled, otherwise $false.

        .EXAMPLE
        if (-not (Enable-WinRE)) {
            LogMessage -message "Unable to re-enable WinRE." -Type 3
        }
        #>
        $EnableRE = ReAgentc.exe /enable
        if ($LASTEXITCODE -eq 0 -and ($EnableRE[0] -notmatch ".*\d+.*")) {
            LogMessage -Message ('Enabled WinRE') -Type 1 -Component 'Enable-WinRE'
            return $true
        }
        else {
            LogMessage -Message ('Enabling failed') -Type 3 -Component 'Enable-WinRE'
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
        Deletes font files and non-English language folders from the EFI system partition to free space.

        .DESCRIPTION
        This function mounts the system reserved EFI partition using the first available drive letter, 
        then removes all font files from the Fonts directory. It also deletes any language-specific 
        folders except for "en-US". These actions help free up space required for Windows feature updates,
        particularly to resolve the "We couldn't update the system reserved partition" error.

        The function logs the free space before and after the operation, and ensures the volume is dismounted after changes.

        .Reference
        https://support.microsoft.com/en-us/topic/-we-couldn-t-update-system-reserved-partition-error-installing-windows-10-46865f3f-37bb-4c51-c69f-07271b6672ac

        .EXAMPLE
        Delete-Fonts
        This will delete font files and extra language folders from the EFI partition and log the changes.
        #>
        try {
            # Dynamically find the first available drive letter
            $Letter = ls function:[d-z]: -n | Where-Object { !(Test-Path $_) } | Select-Object -First 1
            if (-not $Letter) {
                LogMessage -Message ("No available drive letter found. Exiting.") -Type 3 -Component "Delete-Fonts"
                return
            }

            LogMessage -Message ("Using drive letter: $Letter. Mounting system reserved partition.") -Type 1 -Component "Delete-Fonts"

            # Mount the system reserved partition
            $mountOutput = & cmd /c "mountvol $Letter /s 2>&1"
            if (-not [string]::IsNullOrWhiteSpace($mountOutput)) {
                LogMessage -Message ("Failed to mount volume. Error: $mountOutput") -Type 3 -Component "Delete-Fonts"
                return
            }

            # Log free space before deletion
            $SizeBefore = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "$Letter" } | Select-Object -ExpandProperty FreeSpace
            $mbBefore = [math]::Round($SizeBefore / 1MB)
            LogMessage -Message ("Free space before deletions: $($mbBefore)MB") -Type 1 -Component "Delete-Fonts"

            # Remove font files
            try {
                Get-Item "$($Letter)\EFI\Microsoft\Boot\Fonts\*.*" -ErrorAction Stop | Remove-Item -Force
                LogMessage -Message "Fonts deleted successfully." -Type 1 -Component "Delete-Fonts"
            }
            catch {
                LogMessage -Message "Failed to delete fonts. Error: $_" -Type 3 -Component "Delete-Fonts"
                return
            }

            # Remove extra language folders except en-US
            try {
                $bootLangFolders = Get-ChildItem "$($Letter)\EFI\Microsoft\Boot" -Directory -ErrorAction Stop

                foreach ($folder in $bootLangFolders) {
                    # Only consider folders that match a language tag pattern like "xx-XX"
                    if ($folder.Name -match '^[a-z]{2}-[A-Z]{2}$' -and $folder.Name -ne 'en-US') {
                        Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                        LogMessage -Message "Deleted language folder: $($folder.Name)" -Type 1 -Component "Delete-Fonts"
                    }
                    else {
                        LogMessage -Message "Skipped folder (not a language folder or is en-US): $($folder.Name)" -Type 1 -Component "Delete-Fonts"
                    }
                }
            }
            catch {
                LogMessage -Message "Failed to delete language folders. Error: $_" -Type 3 -Component "Delete-Fonts"
                return
            }


            # Log free space after deletions
            $SizeAfter = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "$Letter" } | Select-Object -ExpandProperty FreeSpace
            $mbAfter = [math]::Round($SizeAfter / 1MB)
            LogMessage -Message "Free space after deletions: $($mbAfter)MB" -Type 1 -Component "Delete-Fonts"

            # Dismount the volume
            $dismountOutput = & cmd /c "mountvol $Letter /d 2>&1"
            if (-not [string]::IsNullOrWhiteSpace($dismountOutput)) {
                LogMessage -Message "Failed to dismount volume. Error: $dismountOutput" -Type 3 -Component "Delete-Fonts"
                return
            }

            LogMessage -Message "Successfully dismounted volume and completed deletions." -Type 1 -Component "Delete-Fonts"

        }
        catch {
            LogMessage -Message "An unexpected error occurred: $_" -Type 3 -Component "Delete-Fonts"
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

        # Call the function to re-enable Bitlocker
        if ($bitlocker -and $bitlocker.ProtectionStatus -eq 'On') {
            LogMessage -message ("Resuming BitLocker protection.") -Component 'Resize-Disk'
            Resume-BitLocker -MountPoint $env:SystemDrive
        }

        LogMessage -message ("Resize operation complete.") -Component 'Resize-Disk'
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

    # Check for the most basic requirements before doing anything else
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

    # --- Final Evaluation ---
    if ($failures.Count -ge 1) {
        Logmessage -message ("Device does NOT meet Windows 11 upgrade requirements:") -Type 3 -Component 'Compatibility'
        $failures | ForEach-Object { Write-Output " - $_" }
        try { Stop-Transcript } catch {}
        exit 1    
    }
    else {
        # Get system info
        $CSInfo = (Get-Computerinfo)
        $OS = $CSInfo.OSName
        $OSDisplayVersion = $CSInfo.OSDisplayVersion
        $Manufacturer = $CSInfo.CsManufacturer
        $Model = $CSInfo.CsModel
        $Type = $CSInfo.CsPCSystemType
        LogMessage -message ("We are working on a $($Manufacturer) $($Model) running $($OS) $($OSDisplayVersion). The system type is $($Type).") -Type 1 -Component 'ComputerInfo'

        # Delete the fonts to resolve "We couldn't update the system reserved partition" error.
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


        # Now let's work on WinRE
        # Get WinRE partition info
        $InitialWinREStatus = Get-WinREInfo
        $WinREStatus = $InitialWinREStatus[0]
        $WinRELocation = $InitialWinREStatus[1]
        if ($WinREStatus) {
            LogMessage -message ("WinRE Enabled") -Type 1 -Component 'Get-WinREInfo'  

            # Get System directory and ReAgent xml file
            $system32Path = [System.Environment]::SystemDirectory
            LogMessage -message ("System directory: " + $system32Path) -Type 1 -Component 'Get-WinREInfo'
            $ReAgentXmlPath = [System.Environment]::SystemDirectory + "\Recovery\ReAgent.xml"
            LogMessage -message ("ReAgent xml: " + $ReAgentXmlPath) -Type 1 -Component 'Get-WinREInfo'
            if (-Not (Test-Path $ReAgentXmlPath)) {
                LogMessage -message ("Error: ReAgent.xml cannot be found") -Type 2 -Component 'Get-WinREInfo'
                LogMessage -message ("ReAgent.xml not found. Creating a new one...") -Type 2 -Component 'Get-WinREInfo'

                # Create XML structure
                $xml = New-Object System.Xml.XmlDocument
                $declaration = $xml.CreateXmlDeclaration("1.0", "utf-8", $null)
                $xml.AppendChild($declaration)

                # Create root node
                $root = $xml.CreateElement("WindowsRE")
                $root.SetAttribute("version", "2.0")  # Ensuring structure consistency
                $xml.AppendChild($root)

                # Create required nodes
                $nodeNames = @("ImageLocation", "PBRImageLocation", "PBRCustomImageLocation", "DownlevelWinreLocation")
    
                foreach ($nodeName in $nodeNames) {
                    $node = $xml.CreateElement($nodeName)
                    $node.SetAttribute("path", "")
                    $node.SetAttribute("offset", "0")
                    $node.SetAttribute("guid", "{00000000-0000-0000-0000-000000000000}")
                    $node.SetAttribute("id", "0")
                    $root.AppendChild($node)
                }

                # Save new XML file
                $xml.Save($ReAgentXmlPath)
                LogMessage -message ("Created and saved new ReAgent.xml at $ReAgentXmlPath.") -Type 1 -Component 'Get-WinREInfo'
            }
            else {
                LogMessage -message ("ReAgent.xml found.") -Type 1 -Component 'Get-WinREInfo'
                # We found the XML so let's read it just for fun. We might use this info one day, just not today. - PJM
                LogMessage -Message 'We found the XML so let us read it just for fun. We might use this info one day, just not today. - PJM' -Type 1 -Component 'Get-WinREInfo'
                $WinREDetails = Get-WinREInfo
                $WinREDetails
            }                      
            LogMessage -message ("Done.") -Type 1 -Component 'Get-WinREInfo'
   
            # Get the RE version info since we are already getting other WinRE info.
            # This is used for the updates not the resize.
            $WindowsRELocation = $WinREStatus.ImagePath
            $WindowsRELocationTrimmed = $WindowsRELocation.Trim()
            $DismImageFileArg = "/ImageFile:$WindowsRELocationTrimmed"
            LogMessage -message ("WinRELOcation: $WindowsRELocation")
            LogMessage -message ("WinRELOcation: $WindowsRELocationTrimmed")
            LogMessage -message ("WinRELOcation: $DismImageFileArg")   
            
            
            
            # Use Select-String to find the specific lines for Version, ServicePack Build, and ServicePack Level
            $reVersion = ($output | Select-String -Pattern '^Version\s+:\s+').ToString().Split(":")[1].Trim()
            $spBuild = ($output | Select-String -Pattern 'ServicePack Build').ToString().Split(":")[1].Trim()
            $spLevel = ($output | Select-String -Pattern 'ServicePack Level').ToString().Split(":")[1].Trim()
            # Output the extracted values
            "Version: $reVersion"
            "ServicePack Build: $spBuild"
            "ServicePack Level: $spLevel"
            # Extract the ServicePack Build and convert it to an integer
            $spBuild = ($output | Select-String -Pattern 'ServicePack Build').ToString().Split(":")[1].Trim()
            $spBuildInt = [int]$spBuild
            "ServicePack Build (Integer): $spBuildInt"
            $reVersionInt = [Version]$reVersion

            # Run the Microsoft function that checks and resizes the disk
            # See this: https://support.microsoft.com/en-us/topic/kb5035679-instructions-to-run-a-script-to-resize-the-recovery-partition-to-install-a-winre-update-98502836-cb2c-4d9a-874c-23bcdf16cd45
            LogMessage -message ("Running the Microsoft disk resize script.") -Type 1 -Component 'Resize-Disk'
            Resize-Disk

            # Update WinRE if needed  
            if ($OS -contains "Windows 10") {
                if ($reVersionInt) {
                    if ($reVersionInt -ge 10.0.19041.5025) {
                        LogMessage -message ("WinRE version $($reVersion) is greater than or equal to 10.0.19041.5025. No update required.")
                        Return
                    }
                    else {
                        if ($OSDisplayVersion -eq '22H2' ) {
                            $Download = 'c:\downloadedupdate\WinREUpdate.cab'  
                            $doUpdate = $True
                            # Make the mount dir
                            if (!(Test-Path 'c:\mount')) {
                                md 'c:\mount'
                            }

                            # Make the download dir
                            if (!(Test-Path 'c:\downloadedupdate')) {
                                md 'c:\downloadedupdate'
                            }
 
                            # Download the update
                            Invoke-WebRequest 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/crup/2024/10/windows10.0-kb5044615-x64_4b85450447ef0e6750ea0c0b576c6ba6605d2e4c.cab' -OutFile $Download
                        }
                    }
                }
                else {
                    LogMessage -message ("Old version of Windows 10 needs to be updated. No action taken.")
                    Return
                }
            }
 
            # We determined that we need to do an update. Now Let's check the partition space.
            If ($doUpdate) {
                LogMessage -message ("WinRE requires an update.")

                # Make sure we have the update before we make any changes!
                If (test-path 'c:\downloadedupdate\WinREUpdate.cab') {
                    LogMessage -message ("We have an update to install.") 

                    # If we made it this far we will install the update
                    # Update the image
                    ReAgentC.exe /mountre /path c:\mount
                    # Dism /Add-Package /Image:C:\mount\ /PackagePath:"c:\downloadedupdate\update.msu" or 

                    Dism /Add-Package /Image:C:\mount\ /PackagePath:"c:\downloadedupdate\WinREUpdate.cab"
                    Dism /image:C:\mount /cleanup-image /StartComponentCleanup /ResetBase
                    ReAgentC.exe /unmountre /path c:\mount /commit

                    # If bitlocker is enabled:
                    $Volumes = Get-BitLockerVolume
                    if (($Volumes.MountPoint -eq 'C:') -and ($volumes.VolumeStatus -eq 'FullyEncrypted')) {
                        LogMessage -message ('Bitlocker is enabled. Disable/Enable WinRE')
                        Disable-WinRE
                        Enable-WinRE      
                    }
                }
            }

        }
        else {
            LogMessage -message ('WARNING: Unable to get WinRE status. Skip working on WinRE!') -Type 3 
        }
    
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
    
        ### BEGIN - Detecting Red reasons, clear them, re-run appraiser  ###
        LogMessage -message ('Detecting Red reasons, clear them, re-run appraiser')

        LogMessage -message ('Getting G Status Paths')
        $GStatusPaths = Get-ChildItem -Recurse $RegistryPathAppCompat | Get-KeyPath | Where-Object Name -eq $RegValueGStatus | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
        if ($GStatusPaths) {
            LogMessage -message ('Found G Status Paths') -Component 'Appraiser'
            $GStatusArray = New-Object System.Collections.ArrayList
            foreach ($Path in $GStatusPaths) {
                LogMessage -message ("Checking path: $Path") -Component 'Appraiser'
                $GStatusArray.Add((Get-ItemPropertyValue -Path $Path -Name $RegValueGStatus))        
            }
        }

        LogMessage -message ('Getting Upg Ex Paths') -Component 'Appraiser' 
        $UpgExPaths = Get-ChildItem -Recurse $RegistryPathAppCompat | Get-KeyPath | Where-Object Name -eq $RegValueUpgEx | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
        if ($UpgExPaths) {
            LogMessage -message ('Found Upg Ex Paths') -Component 'Appraiser'
            $UpgExArray = New-Object System.Collections.ArrayList
            foreach ($Path in $UpgExPaths) {
                LogMessage -message ("Checking path: $Path") -Component 'Appraiser'
                $UpgExArray.Add((Get-ItemPropertyValue -Path $Path -Name $RegValueUpgEx))  
            }
        }

        # If any key is not good delete them all and run the appraiser
        if ($UpgExArray -contains 'Red' -or $GStatusArray -eq $null -or $GStatusArray.Count -eq 0 -or $GStatusArray -notcontains '2' -or ($GStatusArray -contains '2' -and $GStatusArray -ne '2')) {
            $Red = $true
            $RedValues = @() # Added to track removals but not implemented yet - PJM
            $RedPaths = Get-ChildItem -Recurse $RegistryPathAppCompat | Get-KeyPath | Where-Object Name -eq $RegValueRedReason | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue

            # Delete all the redreasons
            foreach ($Path in $RedPaths) {
                LogMessage -message ('Found red reasons. Delete them!') -Component 'Appraiser'
                Remove-Item -Path $Path -ErrorAction SilentlyContinue
            }

            # Delete other indicators:
            $Markers = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CompatMarkers\' | Select-Object -ExpandProperty Name 
            foreach ($Marker in $Markers) {
                LogMessage -message ('Found markers. Delete them!') -Component 'Appraiser'
                Remove-Item -Path "Registry::$Marker" -ErrorAction SilentlyContinue
            }

            $Caches = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\WuCache\' | Select-Object -ExpandProperty Name 
            foreach ($Cache in $Caches) {
                LogMessage -message ('Found caches. Delete them!') -Component 'Appraiser'
                Remove-Item -Path "Registry::$Cache" -ErrorAction SilentlyContinue
            }

            LogMessage -message ("Appraiser path: $CompatAppraiserPath") -Component 'Appraiser'
            if (Test-Path $CompatAppraiserPath) {
                LogMessage -message ('Running compatibility appraisers...') -Component 'Appraiser'
                
                # Force the compatibility appraiser to run:
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:appraiser.dll -f:DoScheduledTelemetryRun' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:appraiser.dll -f:UpdateAvStatus' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:devinv.dll -f:CreateDeviceInventory' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:pcasvc.dll -f:QueryEncapsulationSettings' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:invagent.dll -f:RunUpdate' -WindowStyle Hidden -Wait -PassThru
                Start-Process -FilePath $CompatAppraiserPath -ArgumentList '-m:aemarebackup.dll -f:BackupMareData' -WindowStyle Hidden -Wait -PassThru

                # Retest for bad things:
                LogMessage -message ('Retest for upgrade blockers') -Component 'Appraiser'
                $GStatusPaths = Get-ChildItem -Recurse $RegistryPathAppCompat | Get-KeyPath | Where-Object Name -eq $RegValueGStatus | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
                if ($GStatusPaths) {
                    $GStatusArray = New-Object System.Collections.ArrayList
                    foreach ($Path in $GStatusPaths) {
                        $GStatusArray.Add((Get-ItemPropertyValue -Path $Path -Name $RegValueGStatus))        
                    }
                }

                $UpgExPaths = Get-ChildItem -Recurse $RegistryPathAppCompat | Get-KeyPath | Where-Object Name -eq $RegValueUpgEx | Select-Object -ExpandProperty Path -ErrorAction SilentlyContinue
                if ($UpgExPaths) {
                    $UpgExArray = New-Object System.Collections.ArrayList
                    foreach ($Path in $UpgExPaths) {
                        $UpgExArray.Add((Get-ItemPropertyValue -Path $Path -Name $RegValueUpgEx))      
                    }
                }

                if ($UpgExArray -contains 'Red' -or $GStatusArray -eq $null -or $GStatusArray.Count -eq 0 -or $GStatusArray -notcontains '2' -or ($GStatusArray -contains '2' -and $GStatusArray -ne '2')) {
                    LogMessage -message ('ERROR: Found new upgrade blockers!') -Component 'Appraiser'               
                }
                else {
                    LogMessage -message ('Resolved') -Component 'Appraiser'
                }
            }
            else {
                LogMessage -message ("ERROR: Appraiser not found at path: $CompatAppraiserPath") -Component 'Appraiser'
            }

            LogMessage -message ('END - Detecting Red reasons, clear them, re-run appraiser') -Component 'Appraiser'
            ### END - Detecting Red reasons, clear them, re-run appraiser  ###
        }  

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
    
        # Create the directory if it doesn't exist
        if (-not (Test-Path $Win11WorkingDirectory)) {
            mkdir $Win11WorkingDirectory
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
                    LogMessage -message ("Downloading ServiceUI.exe from $ServiceUIPath...") -Component 'Script'
                    $webClient.DownloadFile($ServiceUIPath, $ServiceUIDestination)
                    LogMessage -message ("Successfully downloaded ServiceUI.exe.") -Component 'Script'
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
            LogMessage -message ("Found previously downloaded Windows 11 Installation Assistant.") -Component 'Script'
        } 

        # Prestage regkeys for the disk cleanup wizard to run after first login to Windows 11
        LogMessage -message ("Prestage regkeys for the disk cleanup wizard to run after first login to Windows 11") -Component 'ScheduledTask'
        Get-ChildItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches' |
            ForEach-Object {
                New-ItemProperty -Path $_.PsPath -Name StateFlags1234 -Value 2 -PropertyType DWORD -Force
            }
    
        # Create scheduled task to reclaim disk space at first login.
        $taskName = "OneTimeCleanMgrAfterWin11Upgrade"
        $scriptPath = "C:\Windows\Temp\$taskName.ps1"

        # Build the actual script content separately (easy to indent and maintain)
        $taskScript = @"
Start-Process CleanMgr.exe -ArgumentList '/sagerun:1234' -WindowStyle Hidden -Wait
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:\$false
"@

        # Write it to disk
        Set-Content -Path $scriptPath -Value $taskScript -Encoding UTF8

        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Limited

        # Register the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force


        #  Start Windows 11 Installation Assistant with or without ServiceUI        
        try {
            if ($loggedOnUsers.Count -gt 0 -and (Test-Path $serviceUIPath)) {
                # Logged-on users detected and ServiceUI exists
                LogMessage -message ("Starting Windows11InstallationAssistant.exe through ServiceUI.exe (visible to user)...") -Component 'Upgrade'
                $proc = Start-Process -FilePath $serviceUIPath -ArgumentList "-process:explorer.exe `"$Windows11InstallationAssistantPath`" $upgradeArgs" -PassThru                
            }
            else {
                # No users detected or ServiceUI missing - run directly
                LogMessage -message ("Starting Windows11InstallationAssistant.exe directly (Failed to detect logged on user or path to serviceui.exe)...") -Component 'Upgrade'
                $proc = Start-Process -FilePath $Windows11InstallationAssistantPath -ArgumentList $upgradeArgs -PassThru               
            }
            LogMessage -message ("Started Windows11InstallationAssistant.exe with process id $($proc.Id).") -Component 'Upgrade'
            SleepNow -Length $sleepTime
        }
        catch {
            LogMessage -message ("Failed to start Windows11InstallationAssistant.exe. Error: $_") -Type 3 -Component 'Upgrade'
            try { Stop-Transcript } catch {}
            throw "Failed to start upgrade process."
        }     
        
    }
}
Stop-Transcript

