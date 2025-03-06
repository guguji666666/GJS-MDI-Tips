# GJS-MDI-Tips

## 1. Verify principals allowed to retrieve the GMSA password 
```powershell
# Retrieve the principals allowed to retrieve the managed password
$principals = Get-ADServiceAccount -Identity "gjsmdigmsa$" -Properties PrincipalsAllowedToRetrieveManagedPassword | 
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


## 2.Verify Pcap, Npcap version installed on the machine

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
