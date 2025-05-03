# Amadey - CyberDefenders

## Case
An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged malware aligns with the Amadey Trojan Stealer. Your job is to analyze the presented memory dump and create a detailed report for actions taken by the malware.

## Tools
Volatility3

## Questions and Procedures

### Q1. In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?

First things first, we will look at all the processes running in memory using 'windows.pslist'. After some analysis, I found a process called **lssass.exe**, **PID 2748** and PPID 2524. This is highly suspicious as it's trying to blend in as the legit lsass.exe.
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.pslist
```


![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q1.png "Suspicious lssass.exe")


### Q2. Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?

Digging deeper, I used windows.dlllist with the PID that we found to see what the file contains.
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.dlllist --pid 274
```

![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q2.png)

This impostor is located at:
- **C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe**

I wanted to gather more information about the process that spawned lssass.exe, but when I searched by PID it didn't return any results (probably got overwritten?).

### Q3. Persistent external communications suggest the malware's attempts to reach out C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?

Keeping up with the hunt, I wanted to know if this process communicated through the network, so I ran windows.netscan, focusing on lssass.exe.
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.netscan | grep lssass.exe
```

We can see that it did established a connection with IP **41.75.84.12**. As you can see in the following screenshot, it communicated over Port 80.

![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q3.png)


### Q4. Following the malware link with the C2C, the malware is likely fetching additional tools or modules. How many distinct files is it trying to bring onto the compromised workstation?

Circling back to the previous question, we saw that it was communicating over Port 80 so we will focus on HTTP traffic. On a first look, since there are two TCP connections to 41.75.84.12, my initial guess is that it downloaded two files. But guessing is not enough. 

After doing some research on volatility3 documentation, we can find this information using windows.memmap.Memmap with the specific PID 2748. This will analyze the memory mapping for this specific process and we can dump it for deeper analysis.
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.memmap.Memmap --pid 2748 --dump
```
Once finished, it will generate a file called "pid.2748.dmp". If you try cat or mousepad like I did, you will encounter a whole lot of strings, so we will analyze it using, you guessed it: **strings**, and searching for "GET" requests. As you can see in the following screenshot, it returns 2 files: **cred64.dll** and **clip64.dll**

![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q4.1.png)

### Q5. Identifying the storage points of these additional components is critical for containment and cleanup. What is the full path of the file downloaded and used by the malware in its malicious activity?

Now, we want to see if any of these files were ran in the system. We will use windows.cmdline to locate all the processes command lines.
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.cmdline
```
After analysing it for a few minutes, I found clip64.dll. As you may know, this is being executed by rundll32.exe, a Living Of The Land Binary. I didn't find anything related to cred64.dll, so this is what was used by Amadey.

![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q5.png)

### Q6. Once retrieved, the malware aims to activate its additional components. Which child process is initiated by the malware to execute these files?

Now, we want to know what is the child process that **lssass.exe** initiated. From the information that we've found so far, my guess is that the child process is rundll32.exe, because it's what executed clip64.dll. Yet again, guessing is not enough, so we use windows.pstree to look at parent-child relationships. 
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.pstree
```
![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q6.png)

As we can see in the screenshot, it is in fact rundll32.exe.

### Q7. Understanding the full range of Amadey's persistence mechanisms can help in an effective mitigation. Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?

To find this, we will use windows.filescan. This command will scan the memory dump for file objects like open files or binaries. I ran it without a specific value and got a LOT of information, therefore, we will use grep to locate only file objects that contains lssass.exe: 
```bash
python3 vol.py -f ../../Artifacts/Windows\ 7\ x64-Snapshot4.vmem windows.filescan | grep lssass.exe
```
![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q7.png)

As we can see, it gave us 3 results, 2 of them are the same path we found on Q2, and the other one is **C:\Windows\System32\Tasks\lssass.exe**. Due to the nature of the path where is stored, its safe to assume that it's using scheduled tasks to persist on this machine.


## References
**You can find this lab here:** https://cyberdefenders.org/blueteam-ctf-challenges/amadey/

Important resources: 
- https://attack.mitre.org/software/S1025/
- https://volatility3.readthedocs.io/en/stable/index.html#
- https://lolbas-project.github.io/#

