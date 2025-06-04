# 🧼 MDI Cleanup Script (English version)

This script fully removes all traces of **Azure Advanced Threat Protection Sensor (MDI Sensor)** from a Windows system, including:

* Backing up relevant registry keys (not necessary)
* Stopping and deleting services
* Cleaning up GUID-based folders
* Deleting the install directory
* Logging all actions to a `.txt` file

---

## 📦 Backup Registry Keys (not necessary)

```powershell
$backupPath = "C:\Temp\MdiSensorBackup"
if (!(Test-Path $backupPath)) {
    New-Item -ItemType Directory -Path $backupPath | Out-Null
}

$registryPaths = @(
    "HKLM:\SOFTWARE\Classes\Installer\Products\",
    "HKLM:\SOFTWARE\Classes\Installer\Features\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
    "HKLM:\SOFTWARE\Classes\Installer\Dependencies\"
)

foreach ($guid in $guids) {
    foreach ($regPath in $registryPaths) {
        $fullKey = "$regPath$guid"

        if (Test-Path $fullKey) {
            $safeName = ($regPath -replace "[:\\]", "_") + $guid + ".reg"
            $backupFile = Join-Path $backupPath $safeName

            $exportCommand = "reg export `"$($fullKey -replace 'HKLM:', 'HKLM')`" `"$backupFile`" /y"
            cmd.exe /c $exportCommand

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
```

---

## 🧽 Main Cleanup Script

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

function Write-Log {
    param (
        [string]$message,
        [string]$logFile
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logEntry
}

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

$searchTerm = "Azure Advanced Threat Protection Sensor"
$logFile = Join-Path $PSScriptRoot "MdiServiceDeletionLog.txt"

Write-Log "Script started." -logFile $logFile

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
```


以下是完整中文版的 **Azure Advanced Threat Protection Sensor（MDI Sensor）清理脚本**，包括注册表备份、服务删除、GUID 清理、安装目录删除以及操作日志记录。

---

# 🧼 MDI 清理脚本（中文版）

该脚本将从 Windows 系统中**彻底移除 Azure 高级威胁防护传感器（MDI Sensor）**，包括：

* 备份相关注册表项 (非必要)
* 停止并删除相关服务
* 清除与 GUID 相关的缓存文件夹
* 删除安装目录
* 所有操作写入 `.txt` 日志文件中

---

## 📦 备份注册表项 (非必要)

```powershell
$backupPath = "C:\Temp\MdiSensorBackup"
if (!(Test-Path $backupPath)) {
    New-Item -ItemType Directory -Path $backupPath | Out-Null
}

$registryPaths = @(
    "HKLM:\SOFTWARE\Classes\Installer\Products\",
    "HKLM:\SOFTWARE\Classes\Installer\Features\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
    "HKLM:\SOFTWARE\Classes\Installer\Dependencies\"
)

foreach ($guid in $guids) {
    foreach ($regPath in $registryPaths) {
        $fullKey = "$regPath$guid"

        if (Test-Path $fullKey) {
            $safeName = ($regPath -replace "[:\\]", "_") + $guid + ".reg"
            $backupFile = Join-Path $backupPath $safeName

            $exportCommand = "reg export `"$($fullKey -replace 'HKLM:', 'HKLM')`" `"$backupFile`" /y"
            cmd.exe /c $exportCommand

            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ 已备份：$fullKey -> $backupFile"
            } else {
                Write-Warning "⚠️ 无法备份：$fullKey"
            }
        } else {
            Write-Host "⏭️ 未找到项：$fullKey"
        }
    }
}
```

---

## 🧽 主清理脚本

```powershell
<#
.SYNOPSIS
    本 PowerShell 脚本可从系统中彻底移除 “Azure 高级威胁防护传感器”（MDI Sensor）。

.DESCRIPTION
    功能包括：
    - 停止并删除相关服务（aatpsensor, aatpsensorupdater）
    - 查找并删除相关注册表项和缓存文件夹
    - 删除安装目录
    - 所有操作记录到日志文件中

.PARAMETER searchTerm
    在注册表中用于匹配的显示名称（如 "Azure Advanced Threat Protection Sensor"）。

.PARAMETER logFile
    操作日志的输出路径。

.NOTES
    版本     : 1.0  
    作者     : MSlab  
    日期     : 2024-10-28  
    权限需求 : 管理员权限

.EXAMPLE
    以管理员权限打开 PowerShell，进入脚本目录，运行：
        .\Remove-MdiSensor.ps1

    你将会被提示是否确认执行以下操作：
    - 停止并删除相关服务
    - 删除注册表项和缓存目录
    - 删除安装目录

    日志将保存至脚本所在目录：MdiServiceDeletionLog.txt
#>

function Write-Log {
    param ([string]$message, [string]$logFile)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - $message"
}

function Delete-Service {
    param ([string]$serviceName, [string]$logFile)
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        try {
            sc.exe stop $serviceName
            Write-Host "正在停止服务 '$serviceName'..."
            Write-Log "正在停止服务 '$serviceName'" $logFile

            $waitTime = 0
            while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -ne 'Stopped' -and $waitTime -lt 60) {
                Start-Sleep -Seconds 5
                $waitTime += 5
                Write-Log "等待服务停止：$waitTime 秒" $logFile
            }

            if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
                Write-Log "服务已停止：$serviceName" $logFile
            } else {
                Write-Error "服务未能在超时时间内停止：$serviceName"
                Write-Log "服务未能停止：$serviceName" $logFile
                return
            }

            sc.exe delete $serviceName
            Start-Sleep -Seconds 5
            if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
                Write-Log "服务已成功删除：$serviceName" $logFile
            } else {
                Write-Log "服务删除失败：$serviceName" $logFile
            }
        } catch {
            Write-Error "删除服务失败：$serviceName - $_"
            Write-Log "删除服务失败：$serviceName - $_" $logFile
        }
    } else {
        Write-Log "服务不存在：$serviceName" $logFile
    }
}

function Delete-RegistryKeys {
    param ([string]$guid, [string]$logFile)
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
            Remove-Item -Path $regKey -Recurse -Force
            Write-Log "已删除注册表项：$regKey" $logFile
        } else {
            Write-Log "未找到注册表项：$regKey" $logFile
        }
    }
}

function Delete-CacheFolder {
    param ([string]$guid, [string]$logFile)
    $folder = "C:\ProgramData\Package Cache\$guid"
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse -Force
        Write-Log "已删除缓存文件夹：$folder" $logFile
    } else {
        Write-Log "未找到缓存文件夹：$folder" $logFile
    }
}

function Delete-InstallFolder {
    param ([string]$logFile)
    $folder = "C:\Program Files\Azure Advanced Threat Protection Sensor"
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse -Force
        Write-Log "已删除安装目录：$folder" $logFile
    } else {
        Write-Log "未找到安装目录：$folder" $logFile
    }
}

function Find-GUIDs {
    param ([string]$searchTerm, [string]$logFile)
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
            $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -eq $searchTerm -or $props.ProductName -eq $searchTerm) {
                $guids += $key.PSChildName
                Write-Log "发现 GUID：$($key.PSChildName)" $logFile
            }
        }
    }
    return $guids | Select-Object -Unique
}

# ---------------------- 主流程 ---------------------- #

$searchTerm = "Azure Advanced Threat Protection Sensor"
$logFile = Join-Path $PSScriptRoot "MdiServiceDeletionLog.txt"

Write-Log "脚本开始运行。" $logFile

$confirm = Read-Host "是否停止并删除服务 'aatpsensor' 和 'aatpsensorupdater'? (yes/no)"
if ($confirm -eq 'yes') {
    Delete-Service "aatpsensor" $logFile
    Delete-Service "aatpsensorupdater" $logFile
} elseif ($confirm -eq 'no') {
    Write-Log "用户取消了服务删除操作。" $logFile
    exit
} else {
    Write-Log "无效输入，脚本中止。" $logFile
    exit
}

$guids = Find-GUIDs $searchTerm $logFile
if ($guids.Count -gt 0) {
    Write-Host "找到以下 GUID："
    $guids | ForEach-Object { Write-Host $_ }

    $confirm = Read-Host "是否删除这些 GUID 的注册表项和缓存文件夹? (yes/no)"
    if ($confirm -eq 'yes') {
        foreach ($guid in $guids) {
            Delete-RegistryKeys $guid $logFile
            Delete-CacheFolder $guid $logFile
        }
    } elseif ($confirm -eq 'no') {
        Write-Log "用户跳过了 GUID 清理。" $logFile
    } else {
        Write-Log "无效输入，脚本中止。" $logFile
        exit
    }
} else {
    Write-Log "未找到与 '$searchTerm' 相关的 GUID。" $logFile
}

$confirm = Read-Host "是否删除安装目录？(yes/no)"
if ($confirm -eq 'yes') {
    Delete-InstallFolder $logFile
} elseif ($confirm -eq 'no') {
    Write-Log "用户跳过了安装目录删除。" $logFile
} else {
    Write-Log "无效输入，脚本中止。" $logFile
    exit
}

Write-Log "脚本执行完毕。" $logFile
```

