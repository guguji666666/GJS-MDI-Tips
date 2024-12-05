# MDI TSG logs

## 1.Netlogon logs
By enabling Netlogon we will capture all the auth attempts; including the MDI Sensors authenticating with the GMSA account.

### 1.Launch powershell as `administator` 

### 2.Start logging
```powershell
Nltest /DBFlag:2080FFFF

net stop netlogon

net start netlogon
```

### 2.Restart MDI sensor service
### 3.Stop logging
```powershell
nltest /dbflag:0x0
```
### 4.Once Netlogon is running with the new flag set it will write the log file to `%windir%\debug\netlogon.log`



## 2.Capture tracing logs
### 1. Run bat 1 file below as administrator
```bat
@echo off
:: Create a directory at C:\temp if it does not exist
MD C:\temp

:: Create a trace named "GMSATracing"
logman create trace "GMSATracing" -ow -o C:\temp\gmsatracing.etl -p {2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

:: Update the "GMSATracing" trace with a provider 
logman update trace "GMSATracing" -p {CA030134-54CD-4130-9177-DAE76A3C5791} 0xffffffffffffffff 0xff -ets

:: Update the "GMSATracing" trace with another provider
logman update trace "GMSATracing" -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -ets

:: Create a trace named "KDC"
logman create trace "KDC" -ow -o C:\temp\KDC.etl -p {1BBA8B19-7F31-43C0-9643-6E911F79A06B} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

:: Create a trace named "ds_security_kerb"
logman create trace "ds_security_kerb" -ow -o C:\temp\ds_security_kerb.etl -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

:: Update the "ds_security_kerb" trace with an additional provider
logman update trace "ds_security_kerb" -p {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4} 0xffffffffffffffff 0xff -ets

:: Create a trace named "minio_netio"
logman create trace "minio_netio" -ow -o C:\temp\minio_netio.etl -p {EB004A05-9B1A-11D4-9123-0050047759BC} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 2048 -ets

:: Update the "minio_netio" trace with the TCPIP provider
logman update trace "minio_netio" -p "Microsoft-Windows-TCPIP" 0xffffffffffffffff 0xff -ets

:: Update the "minio_netio" trace with the Winsock AFD provider
logman update trace "minio_netio" -p "Microsoft-Windows-Winsock-AFD" 0xffffffffffffffff 0xff -ets

:: Update the "minio_netio" trace with another provider
logman update trace "minio_netio" -p {B40AEF77-892A-46F9-9109-438E399BB894} 0xffffffffffffffff 0xff -ets

:: Modify the registry to set SamLogLevel in Lsa
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v SamLogLevel /t REG_DWORD /d 0x00002000 /f

:: Set the database flag for nltest
nltest /dbflag:0x2effffff

:: Start a network trace with netsh
netsh trace start capture=yes filemode=circular overwrite=yes maxsize=512 tracefile=C:\temp\nettrace.etl

:: Notify completion
echo Tracing has been configured and started. Logs will be stored in C:\temp.
```

### 2. Stop the sensor service and restart it if possible

### 3. Run bat file below as administrator
```bat
@echo off
echo Stopping logman sessions...
logman stop "GMSATracing" -ets
logman stop "KDC" -ets
logman stop "ds_security_kerb" -ets
logman stop "minio_netio" -ets

echo Disabling debug flags...
nltest /dbflag:0x0

echo Generating Group Policy result report...
gpresult /h C:\Temp\gpresult.html

echo Setting SamLogLevel in the registry...
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v SamLogLevel /t REG_DWORD /d 0x0 /f

echo Copying event logs to C:\Temp...
copy /y C:\Windows\System32\winevt\logs\System.evtx C:\Temp\
copy /y C:\Windows\System32\winevt\logs\Application.evtx C:\Temp\
copy /y C:\Windows\System32\winevt\logs\Microsoft-Windows-Security-Netlogon%4Operational.evtx C:\Temp\
copy /y C:\Windows\System32\winevt\logs\Microsoft-Windows-TaskScheduler%4Operational.evtx C:\Temp\
copy /y C:\Windows\Debug\netlogon.* C:\Temp\
copy /y C:\Windows\Debug\sam.* C:\Temp\

echo Stopping network tracing...
netsh trace stop

echo All commands executed successfully!
pause
```
The logs will be generated under C:\temp

## 3.Check if gmsa is in a deny group
```powershell
$denyGroups = @(
    "Deny log on locally",
    "Deny log on as a batch job",
    "Deny access to this computer from the network"
)

foreach ($group in $denyGroups) {
    $denyGroupMembers = Get-ADGroupMember -Identity $group
    if ($denyGroupMembers | Where-Object { $_.SamAccountName -eq $gMSAAccount }) {
        Write-Host "$gMSAAccount is a member of $group"
    } else {
        Write-Host "$gMSAAccount is NOT a member of $group"
    }
}
```
