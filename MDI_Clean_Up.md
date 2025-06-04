# 🧹 MDI Cleanup Script (Azure ATP Sensor Removal)

This script performs a complete cleanup of the **Azure Advanced Threat Protection Sensor** from a Windows system.  
It includes:
- Backup of relevant registry entries
- Deletion of related Windows services
- Cleanup of cache folders and installation directory

> **Author:** MSlab  
> **Date:** 2024-10-28  
> **Version:** 1.0  
> **Permissions Required:** Administrator  

---

## 📁 Section 1: Backup Registry Entries

The following block exports all registry keys that might contain traces of the MDI Sensor based on previously discovered GUIDs.

```powershell
# Define backup folder path
$backupPath = "C:\Temp\MdiSensorBackup"

# Ensure the backup directory exists
if (!(Test-Path $backupPath)) {
    New-Item -ItemType Directory -Path $backupPath | Out-Null
}

# Registry paths commonly used by Windows Installer
$registryPaths = @(
    "HKLM:\SOFTWARE\Classes\Installer\Products\",
    "HKLM:\SOFTWARE\Classes\Installer\Features\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
    "HKLM:\SOFTWARE\Classes\Installer\Dependencies\"
)

# Loop through each discovered GUID
foreach ($guid in $guids) {
    foreach ($regPath in $registryPaths) {
        $fullKey = "$regPath$guid"

        if (Test-Path $fullKey) {
            # Prepare filename for .reg file (replace backslashes/colons to safe name)
            $safeName = ($regPath -replace "[:\\]", "_") + $guid + ".reg"
            $backupFile = Join-Path $backupPath $safeName

            # Export the registry key using reg.exe
            $exportCommand = "reg export `"$($fullKey -replace 'HKLM:', 'HKLM')`" `"$backupFile`" /y"
            cmd.exe /c $exportCommand

            # Confirm export status
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Backed up: $fullKey -> $backupFile"
            } else {
                Write-Warning "⚠️ Failed to back up: $fullKey"
            }
        } else {
            Write-Host "⏭️ Key not found: $fullKey"
        }
    }
}
````

---

## 🧼 Section 2: Full MDI Cleanup Script

> **Script Name:** `Remove-MdiSensor.ps1`
> This script removes all traces of the MDI Sensor including services, registry keys, cache, and installation files.

<details>
<summary>Click to expand full script</summary>

```powershell
<#
.SYNOPSIS
    This PowerShell script fully removes all traces of the "Azure Advanced Threat Protection Sensor" from a Windows system.

.DESCRIPTION
    The script performs the following tasks:
    - Stops and deletes the related Windows services (`aatpsensor`, `aatpsensorupdater`)
    - Searches the registry for GUIDs associated with the sensor
    - Deletes registry entries and Package Cache folders matching those GUIDs
    - Deletes the sensor installation folder from "C:\Program Files"
    - Logs all actions and results for auditing

.PARAMETER searchTerm
    The display name of the target application in the registry (e.g., "Azure Advanced Threat Protection Sensor").

.PARAMETER logFile
    The path to a log file used to record all operations.

.NOTES
    Version   : 1.0
    Author    : MSlab
    Date      : 2024-10-28
    Requires  : Administrator privileges

.EXAMPLE
    1. Open PowerShell as Administrator.
    2. Navigate to the script's directory.
    3. Run the script using:
        .\Remove-MdiSensor.ps1

    You will be prompted for:
    - Confirmation to stop and delete related services
    - Confirmation to delete registry keys and cache folders
    - Confirmation to delete the installation folder

    A log file will be created at the script's location: MdiServiceDeletionLog.txt
#>

#---------------------- Function Definitions ----------------------#

# Logs messages with a timestamp to the log file
function Write-Log {
    ...
}

# Stops and deletes a Windows service by name, logging the result
function Delete-Service {
    ...
}

# Deletes registry keys related to the provided GUID
function Delete-RegistryKeys {
    ...
}

# Deletes cache folder for a specific GUID under ProgramData
function Delete-CacheFolder {
    ...
}

# Deletes the sensor's installation folder
function Delete-InstallFolder {
    ...
}

# Searches the registry for GUIDs associated with the sensor by display name
function Find-GUIDs {
    ...
}

#---------------------- Main Script Logic ----------------------#

# Define search term and log file path
$searchTerm = "Azure Advanced Threat Protection Sensor"
$logFile = Join-Path $PSScriptRoot "MdiServiceDeletionLog.txt"

Write-Log "Script started." -logFile $logFile

# Step 1: Ask user to delete services
$confirmation = Read-Host "Do you want to stop and delete the services 'aatpsensor' and 'aatpsensorupdater'? (yes/no)"
if ($confirmation -eq 'yes') {
    ...
}

# Step 2: Find all GUIDs for registry and cache deletion
$guids = Find-GUIDs -searchTerm $searchTerm -logFile $logFile
if ($guids.Count -gt 0) {
    ...
} else {
    Write-Host "No GUIDs found for '$searchTerm'."
    Write-Log "No GUIDs found for '$searchTerm'." -logFile $logFile
}

# Step 3: Confirm deletion of install folder
$confirmation = Read-Host "Do you want to delete the installation folder for '$searchTerm'? (yes/no)"
if ($confirmation -eq 'yes') {
    ...
}

Write-Log "Script completed." -logFile $logFile
```

</details>

---

## 📝 Notes

* Always test the script on a non-production machine before using it in a live environment.
* Ensure backups are made prior to deletion (see registry backup section).
* Some antivirus or EDR tools may interfere with deletion of sensor folders—consider disabling protection temporarily.

---
