# Amadey - CyberDefenders

## Case
An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged malware aligns with the Amadey Trojan Stealer. Your job is to analyze the presented memory dump and create a detailed report for actions taken by the malware.

## Tools
Volatility3

## Questions and Procedures

### Q1. In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?

First things first, we will look at all the processes running in memory using 'windows.pslist'. After a few peaks, I found a process called **lssass.exe**, **PID 2748** and PPID 2524. This is highly suspicious as it's trying to blend in as the legit lsass.exe
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.pslist
```


![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q1.png "Suspicious lssass.exe")

### Q2. Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?

Digging deeper, I used windows.dlllist with the PID that we found to see what the file contains.
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.dlllist --pid 274
```

This impostor is located at:
**C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe**

![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q2.png)

I wanted to gather more information about the process that spawned lssass.exe, but when I searched by PID it didn't return any results (probably got overwritten?).

### Q3. Persistent external communications suggest the malware's attempts to reach out C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?

Keeping up with the hunt, I wanted to know if this process communicated through the network, so I ran windows.netscan, focusing on lssass.exe.
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.netscan | grep lssass.exe
```

We can see that it did established a connection with IP **41.75.84.12**. As you can see in the following screenshot, it communicated over Port 80.

![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q3.png)

