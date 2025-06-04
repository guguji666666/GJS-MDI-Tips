# 🧹 MDI Cleanup Script (Azure ATP Sensor Removal) - English Version

This script performs a complete cleanup of the **Azure Advanced Threat Protection Sensor** from a Windows system.  
It includes:
- Deletion of related Windows services
- Cleanup of registry keys and Package Cache folders
- Removal of installation directory

> **Author:** MSlab  
> **Date:** 2024-10-28  
> **Version:** 1.0  
> **Permissions Required:** Administrator  

---

## 🧼 Full MDI Cleanup Script

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
````

</details>

---

## 📝 Notes

* Always test the script on a non-production machine before using it in production.
* If antivirus or EDR interferes with file/folder deletion, consider temporarily disabling them.
* A backup of registry keys is possible (optional), but not required for most cleanups.

---

# 🇨🇳 中文版本

# 🧹 MDI 清理脚本（Azure ATP Sensor 卸载）

本脚本用于彻底清除 Windows 系统中安装的 **Azure Advanced Threat Protection Sensor（高级威胁防护传感器）**，包括以下操作：

- 删除相关的 Windows 服务（例如 `aatpsensor`, `aatpsensorupdater`）
- 清理注册表中与传感器相关的 GUID 项
- 删除安装目录和缓存文件夹（如 ProgramData 中的 Package Cache）

> **作者:** MSlab  
> **日期:** 2024-10-28  
> **版本:** 1.0  
> **所需权限:** 以管理员身份运行  

---

## 🧼 MDI 传感器清理主脚本

> **脚本文件名:** `Remove-MdiSensor.ps1`  
> 该脚本会移除系统中 Azure ATP Sensor 的所有残留内容。

<details>
<summary>点击展开完整脚本</summary>

```powershell
<#
.SYNOPSIS
    此 PowerShell 脚本可彻底删除系统中 Azure ATP Sensor 的所有相关内容。

.DESCRIPTION
    主要功能包括：
    - 停止并删除服务（aatpsensor 与 aatpsensorupdater）
    - 查找与传感器相关的注册表 GUID 并清理注册表
    - 删除 ProgramData 中的缓存目录
    - 删除安装路径（通常位于 "C:\Program Files"）
    - 将所有操作记录到日志文件中

.PARAMETER searchTerm
    注册表中用于识别目标程序的名称（如 "Azure Advanced Threat Protection Sensor"）。

.PARAMETER logFile
    日志记录文件的完整路径。

.NOTES
    版本     : 1.0  
    作者     : MSlab  
    日期     : 2024-10-28  
    所需权限 : 管理员权限

.EXAMPLE
    使用方法如下：
    1. 以管理员身份打开 PowerShell
    2. 切换至脚本所在目录
    3. 执行以下命令：
        .\Remove-MdiSensor.ps1

    脚本会提示确认以下操作：
    - 是否停止并删除相关服务
    - 是否删除注册表项和缓存文件夹
    - 是否删除安装目录

    脚本会在当前目录生成日志文件：MdiServiceDeletionLog.txt
#>
````

</details>

---

## 📝 注意事项

* 建议先在测试环境中执行脚本，确认无误后再用于生产环境。
* 某些杀毒软件或安全代理（如 EDR）可能会阻止文件删除，建议在操作时暂时关闭。
* 注册表项备份可选，默认脚本不启用，如需备份请手动开启备份流程。

---
