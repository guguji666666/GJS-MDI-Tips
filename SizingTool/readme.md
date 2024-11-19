# MDI SizingTool 

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
# Load the Windows Forms assembly for sending key events
Add-Type -AssemblyName System.Windows.Forms

# Function to start a process in a hidden window
function Start-ProcessHidden {
    param (
        [string]$exePath # Path to the executable file to start
    )
    
    # Create a new ProcessStartInfo object
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $exePath # Set the executable file path
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden # Set the window style to hidden
    $startInfo.UseShellExecute = $false # Disable the use of the operating system shell to start the process
    
    # Start the process with the specified start info
    $process = [System.Diagnostics.Process]::Start($startInfo)
    return $process # Return the process object for further manipulation
}

# Start the executable as a hidden process
$process = Start-ProcessHidden -exePath "C:\path\to\TriSizingTool.exe"

# Wait for a short duration before starting to send keys (adjust as needed)
Start-Sleep -Seconds 2 # Adjust this based on the time your application needs to fully start

# Set parameters in advance for send keys function
$intervalInSeconds = 2 # Interval in seconds between sending Enter key presses
$maxDurationInMinutes = 14 # Maximum duration to run the script in minutes (for testing, set to 14 minutes)
$ctrlCDurationInMinutes = 10 # Duration in minutes after which to send Ctrl+C to stop the process (for testing, set to 4 minutes)

# Function to send the Enter key periodically and Ctrl+C after a specified time
function Send-KeysRepeatedly {
    param (
        [int]$intervalInSeconds, # Interval in seconds between sending Enter key presses
        [int]$maxDurationInMinutes, # Maximum duration to run the script in minutes
        [int]$ctrlCDurationInMinutes # Duration in minutes after which to send Ctrl+C to stop the process
    )

    # Start a stopwatch to keep track of elapsed time
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    # Loop until the process exits or the maximum duration is reached
    while (-not $process.HasExited) {
        if ($stopwatch.Elapsed.TotalMinutes -ge $maxDurationInMinutes) {
            Write-Output "Maximum duration reached. Stopping the process and exiting the script."
            # Kill the process if the maximum duration is reached
            $process.Kill()
            break
        }
        if ($stopwatch.Elapsed.TotalMinutes -ge $ctrlCDurationInMinutes) {
            Write-Output "Sending Ctrl+C to the process."
            # Send Ctrl+C to the process to interrupt it
            [System.Windows.Forms.SendKeys]::SendWait("^c")
            break
        } else {
            Write-Output "Sending Enter to the process."
            # Send the Enter key to the process
            [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
        }
        
        # Wait for the specified interval before sending the next key press
        Start-Sleep -Seconds $intervalInSeconds
    }
    
    $stopwatch.Stop() # Stop the stopwatch
}

# Call the function using preset parameters
Send-KeysRepeatedly -intervalInSeconds $intervalInSeconds -maxDurationInMinutes $maxDurationInMinutes -ctrlCDurationInMinutes $ctrlCDurationInMinutes

# Wait for the process to complete (if it hasn't exited already)
if (-not $process.HasExited) {
    $process.WaitForExit() # Wait for the process to exit
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



