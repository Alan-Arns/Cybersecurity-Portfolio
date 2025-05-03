# Amadey - CyberDefenders

## Case
An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged malware aligns with the Amadey Trojan Stealer. Your job is to analyze the presented memory dump and create a detailed report for actions taken by the malware.

## Tools
Volatility3

## Questions and Procedures

##### Q1. In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?

First things first, we will look at all the processes running in memory using 'windows.pslist'. After a few peaks, I found a process called *lssass.exe*, PID 2748 and PPID 2524. This is highly suspicious as it's trying to blend in as the legit lsass.exe

![alt text](https://github.com/cyberalises/Cybersecurity-Portfolio/blob/main/Images/CTF%20Challenges/Amadey/Q1.png "Suspicious lssass.exe")
