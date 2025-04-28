# GJS-MDI-Tips
## Defender for identity powershell module

### ✅ 步骤一：手动下载 `.nupkg` 文件至`C:\Temp\`中

1. 打开 [DefenderForIdentity 模块页面](https://www.powershellgallery.com/packages/DefenderForIdentity/1.0.0.3)
2. 点击右上角的 **“手动下载（Manual Download）”**
3. 或者直接打开下载链接：  
   [https://www.powershellgallery.com/api/v2/package/DefenderForIdentity/1.0.0.3](https://www.powershellgallery.com/api/v2/package/DefenderForIdentity/1.0.0.3)
4. 保存文件为：  
   `DefenderForIdentity.1.0.0.3.nupkg`

---

### ✅ 步骤二：重命名并解压 `.nupkg` 文件

在 PowerShell 中运行以下命令：

```powershell
Rename-Item -Path 'DefenderForIdentity.1.0.0.3.nupkg' -NewName 'DefenderForIdentity.zip'
Expand-Archive -Path 'DefenderForIdentity.zip' -DestinationPath 'C:\Temp\DefenderForIdentity'
```
---

### ✅ 步骤三：找到模块文件所在目录

进入解压后的目录：
```
C:\Temp\DefenderForIdentity\DefenderForIdentity\1.0.0.3\
```

新建文件夹 `1.0.0.3`

把当前目录下所有文件，移入文件夹`1.0.0.3`中
![image](https://github.com/user-attachments/assets/f792a5ed-7ee4-4d9b-ae4e-2e13ca8386b0)


确认该目录`\Temp\DefenderForIdentity\1.0.0.3`中包含：
- `DefenderForIdentity.psm1`
- `DefenderForIdentity.psd1`
![image](https://github.com/user-attachments/assets/d7547c19-db4a-4d9d-a3a5-abe2334cd8ca)

---

### ✅ 步骤四：复制到 PowerShell 模块路径

#### 👉 当前用户（不需要管理员权限）：

```powershell
$dest = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\DefenderForIdentity"
Copy-Item -Path 'C:\Temp\DefenderForIdentity\DefenderForIdentity\1.0.0.3' -Destination $dest -Recurse
```

#### 👉 所有用户（需要管理员权限）：

```powershell
$dest = "$env:ProgramFiles\WindowsPowerShell\Modules\DefenderForIdentity\1.0.0.3"
Copy-Item -Path 'C:\Temp\DefenderForIdentity\1.0.0.3' -Destination $dest -Recurse -Force
```
![image](https://github.com/user-attachments/assets/9e69e599-9f62-4fee-b599-c2f2dc8f371e)

---

### ✅ 步骤五：导入并验证模块

导入模块：

```powershell
Import-Module DefenderForIdentity
```

验证是否安装成功：

```powershell
Get-Module -ListAvailable DefenderForIdentity
```

---


## 1. Verify principals allowed to retrieve the GMSA password 
```powershell
# Retrieve the principals allowed to retrieve the managed password
$principals = Get-ADServiceAccount -Identity "<GMSA name with $ at end>" -Properties PrincipalsAllowedToRetrieveManagedPassword | 
              Select-Object -ExpandProperty PrincipalsAllowedToRetrieveManagedPassword

# Iterate over each principal to determine if it is a security group
foreach ($principal in $principals) {
    # Retrieve the object details for each principal
    $objectDetails = Get-ADObject -Identity $principal -Properties ObjectClass
    
    # Check if the object is a security group
    if ($objectDetails.ObjectClass -eq 'group') {
        # Output the name and distinguished name (location) of the security group
        $groupDetails = Get-ADGroup -Identity $principal
        [PSCustomObject]@{
            Name       = $groupDetails.Name
            Location   = $groupDetails.DistinguishedName
        }
    } else {
        # Optional: Print or log principals that are not security groups
        Write-Host "Not a security group: $($objectDetails.DistinguishedName)"
    }
}
```
![image](https://github.com/user-attachments/assets/01afa547-16f0-40f3-9a6d-4dd9f02fcc68)

## 2. Verify group membership of computer
```powershell
# Query the group membership of the machine
$computerName = "<Input computer hostname>"
$computer = Get-ADComputer -Identity $computerName

# Get the group membership and their respective OU location
$groups = Get-ADPrincipalGroupMembership -Identity $computer

# Output the group name and its location
foreach ($group in $groups) {
    $ou = ($group.DistinguishedName -split ",", 2)[1]  # Get the OU part of the Distinguished Name
    [PSCustomObject]@{
        GroupName = $group.Name
        Location  = $ou
    }
}
```
![image](https://github.com/user-attachments/assets/af57ffe7-7370-4ad0-83e1-e0d94e0705db)

## 3. GMSA last password change date
```powershell
# Replace 'YourServiceAccountName' with the name of your gMSA
$serviceAccountName = "<GMSA name with $ at end>"

# Get the AD service account object
$gmsa = Get-ADServiceAccount -Identity $serviceAccountName -Properties * 

# Get the pwdLastSet attribute which holds the last password change date
$pwdLastSet = $gmsa.pwdLastSet

# Convert the pwdLastSet attribute to a datetime object to make it human-readable
$lastPasswordChangeDate = [datetime]::FromFileTime($pwdLastSet)

# Output the last password change date
"Last password change date for ${serviceAccountName}: $lastPasswordChangeDate"
```

### Or we can use script below
English version
```powershell
# Set the computer name
$computerName = "<Hostname of affected machine>"

# Set the gMSA account name (make sure to include the trailing $)
$gmsaAccountName = "mdiSvc01$"

# Retrieve the computer object
$computer = Get-ADComputer -Identity $computerName

# Retrieve the list of groups the computer belongs to (Distinguished Names)
$computerGroups = Get-ADPrincipalGroupMembership -Identity $computer | Select-Object -ExpandProperty DistinguishedName

# Retrieve the gMSA account object with all properties
$gmsa = Get-ADServiceAccount -Identity $gmsaAccountName -Properties *

# Retrieve the list of principals allowed to retrieve the gMSA password
$allowedPrincipals = $gmsa.PrincipalsAllowedToRetrieveManagedPassword

# Retrieve the last password change time for the gMSA
$pwdLastSet = $gmsa.pwdLastSet
$lastPasswordChangeDate = [datetime]::FromFileTime($pwdLastSet)

# Output the groups the computer belongs to
Write-Host "`n=== Computer Group Memberships ==="
$computerGroups

# Output the principals allowed to retrieve the gMSA password
Write-Host "`n=== gMSA Principals Allowed to Retrieve Password ==="
$allowedPrincipals

# Check if the computer has permission to retrieve the gMSA password
Write-Host "`n=== Permission Check Result ==="
$hasDirectPermission = $allowedPrincipals -contains $computer.DistinguishedName
$hasGroupPermission = ($computerGroups | Where-Object { $allowedPrincipals -contains $_ }).Count -gt 0

if ($hasDirectPermission -or $hasGroupPermission) {
    Write-Host "✅ Computer '$computerName' has permission to retrieve the password for gMSA '$gmsaAccountName'." -ForegroundColor Green
} else {
    Write-Host "❌ Computer '$computerName' does NOT have permission to retrieve the password for gMSA '$gmsaAccountName'." -ForegroundColor Red
}

# Output the last password change date for the gMSA
Write-Host "`n=== gMSA Last Password Change Date ==="
Write-Host "Last password change date for ${gmsaAccountName}: $lastPasswordChangeDate"
```

Chinese version
```powershell
# 设置要检查的计算机名称
$computerName = "<主机名>"

# 设置要检查的gMSA账户名（注意带$）
$gmsaAccountName = "mdiSvc01$"

# 获取计算机对象
$computer = Get-ADComputer -Identity $computerName

# 获取计算机所属的组列表（返回完整的DN）
$computerGroups = Get-ADPrincipalGroupMembership -Identity $computer | Select-Object -ExpandProperty DistinguishedName

# 获取gMSA账户对象，拉取完整属性
$gmsa = Get-ADServiceAccount -Identity $gmsaAccountName -Properties *

# 获取被授权可以检索gMSA密码的主体列表（直接拿，不要Expand）
$allowedPrincipals = $gmsa.PrincipalsAllowedToRetrieveManagedPassword

# 获取gMSA密码上一次更改时间
$pwdLastSet = $gmsa.pwdLastSet
$lastPasswordChangeDate = [datetime]::FromFileTime($pwdLastSet)

# 打印计算机所属组
Write-Host "`n=== 计算机所属组列表 ==="
$computerGroups

# 打印gMSA允许访问的主体
Write-Host "`n=== gMSA账户允许访问的主体列表 ==="
$allowedPrincipals

# 检查计算机是否有权限访问gMSA密码
Write-Host "`n=== 检查结果 ==="
$hasDirectPermission = $allowedPrincipals -contains $computer.DistinguishedName
$hasGroupPermission = ($computerGroups | Where-Object { $allowedPrincipals -contains $_ }).Count -gt 0

if ($hasDirectPermission -or $hasGroupPermission) {
    Write-Host "✅ 机器 '$computerName' 有权限读取 gMSA '$gmsaAccountName' 的密码。" -ForegroundColor Green
} else {
    Write-Host "❌ 机器 '$computerName' 没有权限读取 gMSA '$gmsaAccountName' 的密码。" -ForegroundColor Red
}

# 输出gMSA账户上一次密码修改时间
Write-Host "`n=== gMSA账户上一次密码更改时间 ==="
Write-Host "账户 ${gmsaAccountName} 上一次密码更改时间: $lastPasswordChangeDate"
```


## 4.Verify Pcap, Npcap version installed on the machine

### Npcap version

```powershell
(Get-ItemProperty "C:\Windows\System32\Npcap\Packet.dll").VersionInfo
```

```powershell
(Get-ItemProperty "C:\Windows\System32\Npcap\Packet.dll").VersionInfo | Select-Object -Property FileVersion
```

![image](https://github.com/user-attachments/assets/0d98b3b5-fa50-400c-8e89-95d53ee5968d)


## 5. Network configuration mismatch for sensors running on VMware
### Disabling the Large Send Offload (LSO)
### a. list network adapters with LSO properties detected
```powershell
# Load the Active Directory module. This requires RSAT (Remote Server Administration Tools) to be installed if running from a workstation.
Import-Module ActiveDirectory

# Retrieve all servers in the domain (filtering for operating systems that include 'Server')
$Servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' | Select-Object -ExpandProperty Name

# Prompt for credentials to be used for remote execution on servers
$cred = Get-Credential

# Iterate through each server
foreach ($server in $Servers) {
    Write-Host "`n[$server] Processing..." -ForegroundColor Cyan

    # Execute commands remotely on each server
    Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock {
        try {
            # Find network adapters with 'Large' in their advanced properties, typically indicating Large Send Offload (LSO)
            $adapters = Get-NetAdapterAdvancedProperty | Where-Object {
                $_.DisplayName -match "^Large"
            } | Select-Object -ExpandProperty Name -Unique

            # Check if any adapters were found
            if ($adapters.Count -eq 0) {
                Write-Host "No adapters with 'Large' advanced properties found." -ForegroundColor Yellow
            }
            else {
                # Output adapters with 'Large' properties
                Write-Host "Adapters with 'Large' advanced properties:" -ForegroundColor Green
                foreach ($adapter in $adapters) {
                    Write-Host "Adapter: $adapter"
                }
            }
        }
        catch {
            # If an error occurs during execution, display the error message
            Write-Host "Error on $env:COMPUTERNAME - $_" -ForegroundColor Red
        }
    }
}
```

Sample output <br>
![image](https://github.com/user-attachments/assets/903c9327-1be9-499e-bd4c-da27bdec50bf)


### b. Then disable LSO on specific servers <br>
```powershell
# Manually specify the hostnames of the servers you want to process
$Servers = @(
    "Server1"
    "Server2",
    "Server3"
)

# Prompt for credentials to be used for remote execution on servers
$cred = Get-Credential

# Iterate through each server
foreach ($server in $Servers) {
    Write-Host "`n[$server] Processing..." -ForegroundColor Cyan

    # Execute commands remotely on each server
    Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock {
        try {
            # Find network adapters with 'Large' in their advanced properties, typically indicating Large Send Offload (LSO)
            $adapters = Get-NetAdapterAdvancedProperty | Where-Object {
                $_.DisplayName -match "^Large"
            } | Select-Object -ExpandProperty Name -Unique

            # Check if any adapters were found
            if ($adapters.Count -eq 0) {
                Write-Host "No adapters with 'Large' advanced properties found." -ForegroundColor Yellow
            }
            else {
                # For each adapter found, disable LSO
                foreach ($adapter in $adapters) {
                    Write-Host "Disabling LSO on adapter: $adapter" -ForegroundColor Green
                    Disable-NetAdapterLso -Name $adapter -Confirm:$false
                }

                # Verify the advanced properties again after disabling LSO
                $updatedAdapters = Get-NetAdapterAdvancedProperty | Where-Object {
                    $_.DisplayName -match "^Large"
                }
               
                if ($updatedAdapters) {
                    Write-Host "Updated 'Large' advanced properties after disabling LSO:" -ForegroundColor Cyan
                    $updatedAdapters | Format-Table -Property Name, DisplayName, DisplayValue
                }
                else {
                    Write-Host "No 'Large' advanced properties found after disabling LSO." -ForegroundColor Green
                }
            }
        }
        catch {
            # If an error occurs during execution, display the error message
            Write-Host "Error on $env:COMPUTERNAME - $_" -ForegroundColor Red
        }
    }
}
```

Explanation <br>
This script disables LSO for network adapters on specified servers. It connects remotely to each server using domain admin credentials, identifies adapters with LSO properties, disables LSO, and verifies the changes.

