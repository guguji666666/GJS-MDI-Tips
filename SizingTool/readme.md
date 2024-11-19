![image](https://github.com/user-attachments/assets/6930160e-bf49-4e16-bfd8-b68492cce3c5)# MDI SizingTool 

## Run MDI SizingTool in scheduled task

### 1. Download [MDI SizingTool](https://github.com/microsoft/Microsoft-Defender-for-Identity-Sizing-Tool)
### 2. Create powershell script under the same path where you saved the MDI sizing tool, name it script1.ps1
### 3. Create powershell script under the same path where you saved the MDI sizing tool, name it script2.ps1
### 4. Edit script1.ps1
```powershell
$username = "domain\domain admin username"  # Eneter domain admin account
$password = "domain admin password"        # Eneter domain admin password
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

$scriptToRun = "C:\path\to\script2.ps1" # Enter 
$executionPolicy = "Bypass"

# Start the second PowerShell script in a hidden window with the given credentials
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy $executionPolicy -File `"$scriptToRun`"" -Credential $credential -Wait -NoNewWindow -PassThru

# Optional: Check exit code or log results
if ($LASTEXITCODE -ne 0) {
    Write-Output "Script execution failed with code $LASTEXITCODE"
} else {
    Write-Output "Script executed successfully"
}
```

### 5. Edit script2.ps1
```powershell
Add-Type -AssemblyName System.Windows.Forms

# Function to start a process hidden
function Start-ProcessHidden {
    param (
        [string]$exePath
    )
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $exePath
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.UseShellExecute = $false
    $process = [System.Diagnostics.Process]::Start($startInfo)
    return $process
}

# Start the executable as a hidden process
$process = Start-ProcessHidden -exePath "C:\path\to\TriSizingTool.exe"

Start-Sleep -Seconds 2 # Adjust this if needed for your application

# Function to send Enter key periodically and Ctrl+C after 4 minutes
function Send-KeysRepeatedly {
    param (
        [int]$intervalInSeconds = 2, # Define interval between sending Enter
        [int]$maxDurationInMinutes = 15, # Maximum duration to run the script in minutes, for test purpose i set 15 minutes
        [int]$ctrlCDurationInMinutes = 14 # Duration after which to send Ctrl+C, for test purpose i configured sizing tool to stop automatically after 14 minutes
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $process.HasExited) {
        if ($stopwatch.Elapsed.TotalMinutes -ge $maxDurationInMinutes) {
            Write-Output "Maximum duration reached. Stopping the process and exiting the script."
            $process.Kill()
            break
        }
        if ($stopwatch.Elapsed.TotalMinutes -ge $ctrlCDurationInMinutes) {
            Write-Output "Sending Ctrl+C to the process."
            [System.Windows.Forms.SendKeys]::SendWait("^c")
            break
        } else {
            Write-Output "Sending Enter to the process."
            [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
        }
        
        Start-Sleep -Seconds $intervalInSeconds
    }
    $stopwatch.Stop()
}

# Call function function to send Enter key repeatedly then Ctrl+C after 4 minutes
Send-KeysRepeatedly -intervalInSeconds 2 -maxDurationInMinutes 14 -ctrlCDurationInMinutes 4

# Wait for the process to complete (in case it's still running)
if (-not $process.HasExited) {
    $process.WaitForExit()
}
```

### 6. Create a bat file in the same path where you saved the MDI sizing tool, edit context
```bash
@echo off
start "" /b powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\path\to\script1.ps1"
```

The workflow via scheduled task would be:
* 1. Launch bat file using system account
* 2. Bat file calls script 1 with domain account credentials saved
* 3. script 1 calls script 2 to trigger sizing tool

![image](https://github.com/user-attachments/assets/0dc94dbd-9a57-44dd-b963-c2f64c74e45a)

![image](https://github.com/user-attachments/assets/396ae32d-b405-43b3-9bdb-2ea305d26150)



