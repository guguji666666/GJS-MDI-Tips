# GJS-MDI-Tips

## Verify Pcap, Npcap version installed on the machine


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
