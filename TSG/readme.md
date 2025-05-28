# 🛠️ MDI Troubleshooting: Log Collection Guide

This guide outlines steps to collect detailed logs for **Microsoft Defender for Identity (MDI)** sensor authentication troubleshooting, including Netlogon logs, ETW traces, and policy checks.

---

## 📘 1. Enable and Collect Netlogon Logs

> Useful for capturing authentication attempts, including those made by MDI Sensors using gMSA accounts.

### ✅ Step 1: Launch PowerShell as **Administrator**

### ✅ Step 2: Start Netlogon Debug Logging

```powershell
Nltest /DBFlag:2080FFFF   # Enable verbose Netlogon logging
net stop netlogon         # Restart Netlogon service
net start netlogon
```

### ✅ Step 3: Restart the MDI Sensor service

### ✅ Step 4: Stop Logging After Reproduction

```powershell
Nltest /DBFlag:0x0        # Disable Netlogon debug logging
```

### 📂 Log Location:

```
%windir%\debug\netlogon.log
```

---

## 🧪 2. Capture ETW Tracing Logs

> Captures trace-level diagnostics related to Kerberos, network, SAM, and KDC processes.

### ✅ Step 1: Create and Start Tracing (Run as Administrator)

Save the following as `start_trace.bat` and run:

```bat
@echo off
MD C:\temp

:: GMSA Tracing
logman create trace "GMSATracing" -ow -o C:\temp\gmsatracing.etl -p {2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman update trace "GMSATracing" -p {CA030134-54CD-4130-9177-DAE76A3C5791} 0xffffffffffffffff 0xff -ets
logman update trace "GMSATracing" -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -ets

:: KDC Tracing
logman create trace "KDC" -ow -o C:\temp\KDC.etl -p {1BBA8B19-7F31-43C0-9643-6E911F79A06B} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

:: Kerberos Security Tracing
logman create trace "ds_security_kerb" -ow -o C:\temp\ds_security_kerb.etl -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman update trace "ds_security_kerb" -p {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4} 0xffffffffffffffff 0xff -ets

:: Network I/O Tracing
logman create trace "minio_netio" -ow -o C:\temp\minio_netio.etl -p {EB004A05-9B1A-11D4-9123-0050047759BC} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 2048 -ets
logman update trace "minio_netio" -p "Microsoft-Windows-TCPIP" 0xffffffffffffffff 0xff -ets
logman update trace "minio_netio" -p "Microsoft-Windows-Winsock-AFD" 0xffffffffffffffff 0xff -ets
logman update trace "minio_netio" -p {B40AEF77-892A-46F9-9109-438E399BB894} 0xffffffffffffffff 0xff -ets

:: Registry settings
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v SamLogLevel /t REG_DWORD /d 0x2000 /f
nltest /dbflag:0x2effffff

:: Start NetSh Trace
netsh trace start capture=yes filemode=circular overwrite=yes maxsize=512 tracefile=C:\temp\nettrace.etl

echo ✅ Tracing started. Logs saved in C:\temp
```

### ✅ Step 2: Restart the MDI Sensor service (if needed)

---

### ✅ Step 3: Stop Tracing and Export Logs (Run as Administrator)

Save as `stop_trace.bat` and run:

```bat
@echo off
echo 🔻 Stopping ETW traces...
logman stop "GMSATracing" -ets
logman stop "KDC" -ets
logman stop "ds_security_kerb" -ets
logman stop "minio_netio" -ets

echo 🧹 Cleaning up debug flags and registry...
nltest /dbflag:0x0
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v SamLogLevel /t REG_DWORD /d 0x0 /f

echo 📋 Exporting Group Policy and logs...
gpresult /h C:\Temp\gpresult.html

copy /y C:\Windows\System32\winevt\logs\System.evtx C:\Temp\
copy /y C:\Windows\System32\winevt\logs\Application.evtx C:\Temp\
copy /y C:\Windows\System32\winevt\logs\Microsoft-Windows-Security-Netlogon%4Operational.evtx C:\Temp\
copy /y C:\Windows\System32\winevt\logs\Microsoft-Windows-TaskScheduler%4Operational.evtx C:\Temp\
copy /y C:\Windows\Debug\netlogon.* C:\Temp\
copy /y C:\Windows\Debug\sam.* C:\Temp\

netsh trace stop

echo ✅ All logs collected at C:\temp
pause
```

---

## 🔍 3. Check If gMSA Account Is In Any Deny Group

> Useful for validating potential GPO or security misconfigurations blocking MDI operations.

```powershell
# Replace with your actual gMSA name
$gMSAAccount = "YourgMSA$"

# Common deny groups to audit
$denyGroups = @(
    "Deny log on locally",
    "Deny log on as a batch job",
    "Deny access to this computer from the network"
)

# Check group memberships
foreach ($group in $denyGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
        if ($members | Where-Object { $_.SamAccountName -eq $gMSAAccount }) {
            Write-Host "$gMSAAccount is a member of $group" -ForegroundColor Red
        } else {
            Write-Host "$gMSAAccount is NOT a member of $group" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️ Failed to query group '$group': $_" -ForegroundColor Yellow
    }
}
```

---

✅ **Final Note:** All logs will be collected under: `C:\temp`
