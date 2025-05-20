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
    param (
        [string]$message,
        [string]$logFile
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logEntry
}

# Stops and deletes a Windows service by name, logging the result
function Delete-Service {
    param (
        [string]$serviceName,
        [string]$logFile
    )
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        try {
            sc.exe stop $serviceName
            Write-Host "'$serviceName' service is being stopped..."
            Write-Log "'$serviceName' service is being stopped." -logFile $logFile

            $waitTime = 0
            while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -ne 'Stopped' -and $waitTime -lt 60) {
                Start-Sleep -Seconds 5
                $waitTime += 5
                Write-Host "Waiting for '$serviceName' to stop... $waitTime seconds elapsed."
                Write-Log "Waiting for '$serviceName' to stop... $waitTime seconds elapsed." -logFile $logFile
            }

            if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
                Write-Host "'$serviceName' service has stopped."
                Write-Log "'$serviceName' service has stopped." -logFile $logFile
            } else {
                Write-Error "Failed to stop '$serviceName' within the timeout period."
                Write-Log "Failed to stop '$serviceName' within the timeout period." -logFile $logFile
                return
            }

            sc.exe delete $serviceName
            Write-Host "'$serviceName' service is being deleted..."
            Write-Log "'$serviceName' service is being deleted." -logFile $logFile

            Start-Sleep -Seconds 5
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -eq $null) {
                Write-Host "'$serviceName' service has been successfully deleted."
                Write-Log "'$serviceName' service has been successfully deleted." -logFile $logFile
            } else {
                Write-Error "Service '$serviceName' could not be deleted."
                Write-Log "Service '$serviceName' could not be deleted." -logFile $logFile
            }
        } catch {
            Write-Error "Failed to stop or delete service '$serviceName': $_"
            Write-Log "Failed to stop or delete service '$serviceName': $_" -logFile $logFile
        }
    } else {
        Write-Warning "Service '$serviceName' does not exist."
        Write-Log "Service '$serviceName' does not exist." -logFile $logFile
    }
}

# Deletes registry keys related to the provided GUID
function Delete-RegistryKeys {
    param (
        [string]$guid,
        [string]$logFile
    )
    $registryPaths = @(
        "HKLM:\SOFTWARE\Classes\Installer\Products\",
        "HKLM:\SOFTWARE\Classes\Installer\Features\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
        "HKLM:\SOFTWARE\Classes\Installer\Dependencies\"
    )
    foreach ($path in $registryPaths) {
        $regKey = "$path$guid"
        if (Test-Path $regKey) {
            Write-Host "Deleting registry key: $regKey"
            Remove-Item -Path $regKey -Recurse -Force
            Write-Log "Deleted registry key: $regKey" -logFile $logFile
        } else {
            Write-Warning "Registry key not found: $regKey"
            Write-Log "Registry key not found: $regKey" -logFile $logFile
        }
    }
}

# Deletes cache folder for a specific GUID under ProgramData
function Delete-CacheFolder {
    param (
        [string]$guid,
        [string]$logFile
    )
    $packageCacheFolder = "C:\ProgramData\Package Cache\$guid"
    if (Test-Path $packageCacheFolder) {
        Remove-Item -Path $packageCacheFolder -Recurse -Force
        Write-Host "Deleted folder: $packageCacheFolder"
        Write-Log "Deleted folder: $packageCacheFolder" -logFile $logFile
    } else {
        Write-Warning "Cache folder not found: $packageCacheFolder"
        Write-Log "Cache folder not found: $packageCacheFolder" -logFile $logFile
    }
}

# Deletes the sensor's installation folder
function Delete-InstallFolder {
    param (
        [string]$logFile
    )
    $installFolder = "C:\Program Files\Azure Advanced Threat Protection Sensor"
    if (Test-Path $installFolder) {
        Remove-Item -Path $installFolder -Recurse -Force
        Write-Host "Deleted installation folder: $installFolder"
        Write-Log "Deleted installation folder: $installFolder" -logFile $logFile
    } else {
        Write-Warning "Installation folder '$installFolder' does not exist."
        Write-Log "Installation folder '$installFolder' does not exist." -logFile $logFile
    }
}

# Searches the registry for GUIDs associated with the sensor by display name
function Find-GUIDs {
    param (
        [string]$searchTerm,
        [string]$logFile
    )
    $registryPaths = @(
        "HKLM:\SOFTWARE\Classes\Installer\Products\",
        "HKLM:\SOFTWARE\Classes\Installer\Features\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
        "HKLM:\SOFTWARE\Classes\Installer\Dependencies\"
    )
    $guids = @()
    foreach ($path in $registryPaths) {
        $subKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
        foreach ($key in $subKeys) {
            $keyPath = $path + $key.PSChildName
            $properties = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if ($properties.DisplayName -eq $searchTerm -or $properties.ProductName -eq $searchTerm) {
                $guids += $key.PSChildName
                Write-Log "Found GUID $($key.PSChildName) for '$searchTerm'" -logFile $logFile
            }
        }
    }
    return $guids | Select-Object -Unique
}

#---------------------- Main Script Logic ----------------------#

# Define search term and log file path
$searchTerm = "Azure Advanced Threat Protection Sensor"
$logFile = Join-Path $PSScriptRoot "MdiServiceDeletionLog.txt"

Write-Log "Script started." -logFile $logFile

# Step 1: Ask user to delete services
$confirmation = Read-Host "Do you want to stop and delete the services 'aatpsensor' and 'aatpsensorupdater'? (yes/no)"
if ($confirmation -eq 'yes') {
    Delete-Service -serviceName "aatpsensor" -logFile $logFile
    Delete-Service -serviceName "aatpsensorupdater" -logFile $logFile
} elseif ($confirmation -eq 'no') {
    Write-Host "Deletion process aborted by the user."
    Write-Log "Deletion process aborted by the user." -logFile $logFile
    exit
} else {
    Write-Host "Invalid input. Aborting the deletion process."
    Write-Log "Invalid input. Aborting the deletion process." -logFile $logFile
    exit
}

# Step 2: Find all GUIDs for registry and cache deletion
$guids = Find-GUIDs -searchTerm $searchTerm -logFile $logFile
if ($guids.Count -gt 0) {
    Write-Host "Found GUIDs for '$searchTerm':"
    $guids | ForEach-Object { Write-Host $_ }

    $confirmation = Read-Host "Do you want to delete registry keys and cache folders for these GUIDs? (yes/no)"
    if ($confirmation -eq 'yes') {
        foreach ($guid in $guids) {
            Delete-RegistryKeys -guid $guid -logFile $logFile
            Delete-CacheFolder -guid $guid -logFile $logFile
        }
    } elseif ($confirmation -eq 'no') {
        Write-Host "Registry and cache deletion skipped by the user."
        Write-Log "Registry and cache deletion skipped by the user." -logFile $logFile
    } else {
        Write-Host "Invalid input. Aborting."
        Write-Log "Invalid input. Aborting." -logFile $logFile
        exit
    }
} else {
    Write-Host "No GUIDs found for '$searchTerm'."
    Write-Log "No GUIDs found for '$searchTerm'." -logFile $logFile
}

# Step 3: Confirm deletion of install folder
$confirmation = Read-Host "Do you want to delete the installation folder for '$searchTerm'? (yes/no)"
if ($confirmation -eq 'yes') {
    Delete-InstallFolder -logFile $logFile
} elseif ($confirmation -eq 'no') {
    Write-Host "Installation folder deletion skipped by user."
    Write-Log "Installation folder deletion skipped by user." -logFile $logFile
} else {
    Write-Host "Invalid input. Aborting."
    Write-Log "Invalid input. Aborting." -logFile $logFile
    exit
}

Write-Log "Script completed." -logFile $logFile
