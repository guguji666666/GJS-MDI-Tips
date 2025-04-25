# GJS-MDI-Tips
## Defender for identity powershell module

### ✅ 步骤一：手动下载 `.nupkg` 文件

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

确认该目录中包含：
- `DefenderForIdentity.psm1`
- `DefenderForIdentity.psd1`

---

### ✅ 步骤四：复制到 PowerShell 模块路径

#### 👉 当前用户（不需要管理员权限）：

```powershell
$dest = "$env:USERPROFILE\Documents\PowerShell\Modules\DefenderForIdentity"
Copy-Item -Path 'C:\Temp\DefenderForIdentity\DefenderForIdentity\1.0.0.3' -Destination $dest -Recurse
```

#### 👉 所有用户（需要管理员权限）：

```powershell
$dest = "$env:ProgramFiles\PowerShell\Modules\DefenderForIdentity"
Copy-Item -Path 'C:\Temp\DefenderForIdentity\DefenderForIdentity\1.0.0.3' -Destination $dest -Recurse
```

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

如你需要，我也可以帮你写一个一键安装脚本（不包含下载），用于在已经有 `.nupkg` 文件的情况下自动完成以上步骤。是否需要？


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

