# GJS-MDI-Tips
## Defender for identity powershell module (Manual installation)
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

## Useful powershell scripts

### 1. Verify principals allowed to retrieve the GMSA password 
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

### 2. Verify group membership of computer
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

### 3. GMSA last password change date
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


### 4. Test network connectivity to the domain controller
English version
```powershell
# Test network connectivity to the domain controller
$domainController = "ECNVADPABR001.envisioncn.com"
$portsToTest = @(389, 636, 88, 53)

Write-Host "`n=== Testing Network Connectivity to Domain Controller ==="
$connectionSummary = @()

foreach ($port in $portsToTest) {
    Write-Host "`nTesting port $port ..." -ForegroundColor Cyan
    $testResult = Test-NetConnection -ComputerName $domainController -Port $port

    if ($testResult.TcpTestSucceeded) {
        Write-Host "✅ Port $port is reachable." -ForegroundColor Green
        $connectionSummary += [PSCustomObject]@{
            Port = $port
            Status = "Pass"
        }
    } else {
        Write-Host "❌ Port $port is not reachable." -ForegroundColor Red
        $connectionSummary += [PSCustomObject]@{
            Port = $port
            Status = "Fail"
        }
    }
}

Write-Host "`n=== Test Summary ===" -ForegroundColor Yellow
$connectionSummary | Format-Table -AutoSize

if ($connectionSummary.Status -contains "Fail") {
    Write-Host "`nSummary: Some critical ports are unreachable. Please check network connectivity or firewall policies." -ForegroundColor Red
} else {
    Write-Host "`nSummary: All critical ports are reachable. Communication with the domain controller is normal." -ForegroundColor Green
}
```

Chinese version
```powershell
# 测试与域控制器的网络连通性
$domainController = "ECNVADPABR001.envisioncn.com"
$portsToTest = @(389, 636, 88, 53)

Write-Host "`n=== 测试与域控制器的网络连通性 ==="
$connectionSummary = @()

foreach ($port in $portsToTest) {
    Write-Host "`n正在测试端口 $port ..." -ForegroundColor Cyan
    $testResult = Test-NetConnection -ComputerName $domainController -Port $port

    if ($testResult.TcpTestSucceeded) {
        Write-Host "✅ 端口 $port 可访问。" -ForegroundColor Green
        $connectionSummary += [PSCustomObject]@{
            Port = $port
            Status = "Pass"
        }
    } else {
        Write-Host "❌ 端口 $port 无法访问。" -ForegroundColor Red
        $connectionSummary += [PSCustomObject]@{
            Port = $port
            Status = "Fail"
        }
    }
}

Write-Host "`n=== 测试总结 ===" -ForegroundColor Yellow
$connectionSummary | Format-Table -AutoSize

if ($connectionSummary.Status -contains "Fail") {
    Write-Host "`n总结：存在无法访问的关键端口，请检查网络连通性或防火墙策略。" -ForegroundColor Red
} else {
    Write-Host "`n总结：所有关键端口均可访问，域控制器通信正常。" -ForegroundColor Green
}
```

### 5.Verify Pcap, Npcap version installed on the machine

Npcap version

```powershell
(Get-ItemProperty "C:\Windows\System32\Npcap\Packet.dll").VersionInfo
```

```powershell
(Get-ItemProperty "C:\Windows\System32\Npcap\Packet.dll").VersionInfo | Select-Object -Property FileVersion
```

![image](https://github.com/user-attachments/assets/0d98b3b5-fa50-400c-8e89-95d53ee5968d)


### 6. Network configuration mismatch for sensors running on VMware
#### Disabling the Large Send Offload (LSO)
a. list network adapters with LSO properties detected
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


b. Then disable LSO on specific servers <br>
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


### 7. Test connection to MDI endpoint
#### 1. Without Proxy (direct test)
Use Test-NetConnection to directly test:
```powershell
Test-NetConnection -ComputerName <MDI workspace name>sensorapi.atp.azure.com -Port 443
```
This will output info like:

* TcpTestSucceeded: True or False
* Latency
* Remote Address
 
If TcpTestSucceeded = True, direct connection is working.


#### 2. With Proxy (proxy_ip:proxy_port)
```powershell
# Proxy settings
$proxyAddress = "http://proxy_ip:proxy_port"

# Target URL
$url = "https://contoso-corpsensorapi.atp.azure.com:443"

# Create the WebRequest
$webRequest = [System.Net.WebRequest]::Create($url)

# Set the proxy
$webProxy = New-Object System.Net.WebProxy($proxyAddress, $true)
$webRequest.Proxy = $webProxy

# Set timeout (optional)
$webRequest.Timeout = 5000  # in milliseconds

try {
    $response = $webRequest.GetResponse()
    Write-Host "✅ Connection via proxy successful!" -ForegroundColor Green
    $response.Close()
} catch {
    Write-Host "❌ Connection via proxy failed: $($_.Exception.Message)" -ForegroundColor Red
}
```

### 8. Get security events from all DC, ADCS, ADFS servers

```powershell
# ================================
# CONFIGURATION SECTION
# ================================

# Define the domain to search in. Replace with your actual domain.
$domainName = "xxxx"

# Define the destination UNC path where Security.evtx logs will be saved.
$logDestination = "\\fileserver\logs$"  # Ensure this path is accessible and writable

# Prompt the user for domain admin or delegated credentials
$cred = Get-Credential -Message "Enter domain admin credentials"

# ================================
# FUNCTION: Discover DC, ADFS, and ADCS Servers
# ================================

function Get-ADInfraServers {

    # Query all computer objects in the domain with server operating systems
    $allServers = Get-ADComputer -Filter * -SearchBase "DC=$($domainName -replace '\.',',DC=')" -Properties Name,OperatingSystem |
                  Where-Object { $_.OperatingSystem -like "*Server*" } |  # Limit to Windows Server OS
                  Select-Object -ExpandProperty Name  # Extract only the name

    $infraServers = @()  # Initialize an array to store matching servers

    foreach ($server in $allServers) {
        try {
            # Test basic connectivity (ping) before proceeding
            if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet)) { continue }

            $roles = @()  # List to store roles (DC, ADFS, ADCS)

            # Check if the computer object is under the "Domain Controllers" OU
            $adObject = Get-ADComputer $server -Properties DistinguishedName
            if ($adObject.DistinguishedName -like "*OU=Domain Controllers,*") {
                $roles += "DC"
            }

            # Use remote PowerShell to check if ADFS service exists
            $adfs = Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock {
                Get-Service -Name adfssrv -ErrorAction SilentlyContinue
            }
            if ($adfs) { $roles += "ADFS" }

            # Use remote PowerShell to check if ADCS (Certificate Services) is present
            $adcs = Invoke-Command -ComputerName $server -Credential $cred -ScriptBlock {
                Get-Service -Name CertSvc -ErrorAction SilentlyContinue
            }
            if ($adcs) { $roles += "ADCS" }

            # Only collect information if the server has at least one matching role
            if ($roles.Count -gt 0) {
                # Resolve the Fully Qualified Domain Name (FQDN)
                $fqdn = ([System.Net.Dns]::GetHostByName($server)).HostName

                # Get the first IPv4 address
                $ip = [System.Net.Dns]::GetHostAddresses($server) |
                      Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                      Select-Object -First 1

                # Store the result in a custom object
                $infraServers += [PSCustomObject]@{
                    FQDN     = $fqdn
                    Hostname = $server
                    Role     = ($roles -join ", ")  # Join multiple roles if applicable
                    IP       = $ip.IPAddressToString
                }
            }

        } catch {
            # Catch any error during server check
            Write-Warning "Failed to check $server: $_"
        }
    }

    # Return the final list of infrastructure servers
    return $infraServers
}

# ================================
# STEP 1: Get all infrastructure servers
# ================================

# Call the function and retrieve servers
$serverList = Get-ADInfraServers

# Display the server list in a formatted table
$serverList | Format-Table -AutoSize

# ================================
# STEP 2: Copy Security.evtx logs from each server
# ================================

foreach ($server in $serverList) {
    try {
        # Create a PowerShell remote session to the target server
        $session = New-PSSession -ComputerName $server.Hostname -Credential $cred -ErrorAction Stop

        # Define the remote log file path
        $remotePath = "C:\Windows\System32\winevt\Logs\Security.evtx"

        # Define the local destination file name
        $localFile = Join-Path $logDestination "$($server.Hostname)-Security.evtx"

        # Copy the Security log from the remote server to the destination share
        Copy-Item -Path $remotePath -Destination $localFile -FromSession $session -Force

        # Log success message
        Write-Host "✅ Copied Security log from $($server.Hostname) to $localFile"

        # Clean up the remote session
        Remove-PSSession $session

    } catch {
        # Handle errors such as access denied or file not found
        Write-Warning "❌ Failed to copy from $($server.Hostname): $_"
    }
}
```

✅ Output Example (From Format-Table)

| FQDN                        | Hostname      | Role          | IP          |
|----------------------------|---------------|---------------|-------------|
| adfs01.corp.contoso.com    | ADFS01        | ADFS          | 10.1.1.10   |
| ca01.corp.contoso.com      | CA01          | ADCS          | 10.1.1.11   |
| dc01.corp.contoso.com      | DC01          | DC            | 10.1.1.1    |
| dc02.corp.contoso.com      | DC02          | DC, ADFS      | 10.1.1.2    |




### 9. 统计 DC 的 Security 事件数量和 `lsass.exe` 的内存使用情况

当然可以，以下是你要的完整 PowerShell 脚本（容错增强版），适用于持续采样服务器资源数据，**含中英文注释**，可直接贴到 GitHub：

---

```powershell
param(
    [int]$DurationMinutes = 120,  # [EN] Total runtime in minutes / [中文] 脚本运行总时长（分钟）
    [int]$IntervalSeconds = 60,   # [EN] Interval between each sampling / [中文] 每轮采样之间的间隔（秒）
    [string]$OutputCSV = "DC_MDI_Usage_Report.csv",  # [EN] Output CSV file path / [中文] 导出文件路径
    [System.Management.Automation.PSCredential]$Credential  # [EN] Credentials for remote DCs / [中文] 用于远程访问 DC 的凭据
)

# [EN] Prompt for credentials if not provided / [中文] 如果未提供凭据，提示输入
if (-not $Credential) {
    $Credential = Get-Credential -Message "Please enter credentials / 请输入凭据"
}

$results = @()
$startTime = Get-Date
$endTime = $startTime.AddMinutes($DurationMinutes)
$round = 1

# [EN] Get domain controllers / [中文] 获取域控制器列表
try {
    $DCs = Get-ADDomainController -Filter * | Select-Object Name, HostName, IPv4Address
} catch {
    Write-Error "❌ Unable to retrieve DC list. Ensure the ActiveDirectory module is available. / 无法获取 DC 列表，请确认 ActiveDirectory 模块可用"
    exit
}

# [EN] Loop until time is up / [中文] 直到达到总运行时长前持续采样
while ((Get-Date) -lt $endTime) {
    Write-Host "`n🔁 Sampling Round $round @ $(Get-Date -Format 'HH:mm:ss') / 第 $round 轮采样" -ForegroundColor Cyan

    foreach ($dc in $DCs) {
        try {
            $hostname = $dc.HostName
            $ip = $dc.IPv4Address
            $fqdn = $dc.Name
            $timeWindow = (Get-Date).AddSeconds(-$IntervalSeconds)

            # [EN] Get security event counts / [中文] 获取安全事件数量
            $eventCount = Invoke-Command -ComputerName $hostname -Credential $Credential -ScriptBlock {
                Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$using:timeWindow} -ErrorAction SilentlyContinue |
                Group-Object -Property ProviderName | Select-Object Name, Count
            }

            # [EN] Get LSASS memory usage / [中文] 获取 LSASS 内存使用
            $lsassInfo = Invoke-Command -ComputerName $hostname -Credential $Credential -ScriptBlock {
                $p = Get-Process lsass
                [PSCustomObject]@{
                    MemoryMB = [math]::Round($p.WorkingSet64 / 1MB, 2)
                    PeakMB   = [math]::Round($p.PeakWorkingSet64 / 1MB, 2)
                    Time     = Get-Date
                }
            }

            # [EN] Get system memory info / [中文] 获取系统内存
            $sysInfo = Invoke-Command -ComputerName $hostname -Credential $Credential -ScriptBlock {
                $cs = Get-CimInstance Win32_ComputerSystem
                [PSCustomObject]@{
                    TotalRAMGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                    DynamicRAM = if ($cs.MemoryDevices -gt 0) { "Yes / 是" } else { "No / 否" }
                }
            }

            # [EN] Get CPU usage (fault-tolerant) / [中文] 获取 CPU 使用率（容错）
            $cpuUsage = Invoke-Command -ComputerName $hostname -Credential $Credential -ScriptBlock {
                try {
                    $val = Get-Counter '\\Processor(_Total)\\% Processor Time' -ErrorAction Stop
                    if ($val.CounterSamples.Count -gt 0) {
                        [math]::Round($val.CounterSamples[0].CookedValue, 2)
                    } else { 0 }
                } catch { 0 }
            }

            # [EN] Get network usage (fault-tolerant) / [中文] 获取网络吞吐量（容错）
            $netUsage = Invoke-Command -ComputerName $hostname -Credential $Credential -ScriptBlock {
                try {
                    $val = Get-Counter -Counter "\\Network Interface(*)\\Bytes Total/sec" -ErrorAction Stop
                    if ($val.CounterSamples.Count -gt 0) {
                        ($val.CounterSamples | Measure-Object -Property CookedValue -Average).Average
                    } else { 0 }
                } catch { 0 }
            }

            # [EN] Combine all results into one record / [中文] 整合所有信息为一条记录
            foreach ($ev in $eventCount) {
                $results += [PSCustomObject]@{
                    DC_FQDN        = $fqdn
                    DC_IP          = $ip
                    Time           = $lsassInfo.Time
                    EventProvider  = $ev.Name
                    EventCount     = $ev.Count
                    LSASS_Mem_MB   = $lsassInfo.MemoryMB
                    LSASS_Peak_MB  = $lsassInfo.PeakMB
                    Total_RAM_GB   = $sysInfo.TotalRAMGB
                    Dynamic_RAM    = $sysInfo.DynamicRAM
                    CPU_Usage_Pct  = $cpuUsage
                    Net_Bytes_Sec  = [math]::Round($netUsage / 1KB, 2)
                }
            }

            Write-Host "✅ Sampled $fqdn / 采样完成: $fqdn" -ForegroundColor Green
        } catch {
            Write-Warning "❌ Failed to sample $($dc.Name): $_ / 无法采集 $($dc.Name)"
        }
    }

    $round++
    Start-Sleep -Seconds $IntervalSeconds
}

# [EN] Export to CSV / [中文] 导出为 CSV 文件
$results | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8
Write-Host "`n📁 CSV saved to: $OutputCSV / 数据已导出至 CSV 文件" -ForegroundColor Cyan
```

---

🔧 建议保存为文件名：`Check-MDI-DCUsage-Resilient.ps1`

🟢 运行示例：

```powershell
.\Check-MDI-DCUsage-Resilient.ps1 -DurationMinutes 60 -IntervalSeconds 30
```




