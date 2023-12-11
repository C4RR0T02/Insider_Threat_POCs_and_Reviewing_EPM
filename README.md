# CSIT_AdminGuard_POC
POC of AdminGuard: Strengthening OS Security from Within

This repository consists of 5 Proof of Concept attacks on the threats of malicious administrators/vendors when they have administrative access within the Windows Server OS

## POCS Developed
1. [POC 1 - Microsoft’s Active Directory Data Exfiltration](/POC1.md)
2. [POC 2 - Keylogging and Screen Capturing](/POC2.md)
3. [POC 3 - Denial of Service Attack on Boot Up of Device](/POC3.md)
4. [POC 4 - Reverse Shell to Remain on Device](/POC4.md)
5. [POC 5 - Ransomware to Destroy Files](/POC5.md)

## Tested on the following Machines with the following configurations

### Machines Used

|Machine Name|Machine IP|Type of Machine|Domain|
|--|:--:|:--:|:--:|
|Windows Server 2022|192.168.8.10|Domain Controller|c4rr0ting.com|
|Windows 10 Client|192.168.8.11|Client|c4rr0ting.com|
|Kali Linux|192.168.8.6|Attacker|-|

### Users

|User Name|Domain|Group|
|--|--|--|
|CARR0T|c4rr0ting.com|Administrator|
|Test|c4rr0ting.com|Users|
|S1|c4rr0ting.com|Sales|
|S2|c4rr0ting.com|Sales|
|S3|c4rr0ting.com|Sales|
