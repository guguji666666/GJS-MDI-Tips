# GJS-MDI-Tips

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


### Pcap version
```powershell
(Get-ItemProperty "C:\Windows\System32\wpcap.dll").VersionInfo | Select-Object -Property FileVersion
```
