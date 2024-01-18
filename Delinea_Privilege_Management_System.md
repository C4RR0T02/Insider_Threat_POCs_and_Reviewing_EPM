# Delinea Privilege Management System

## Description of Dealinea Privilege Management System

Privilege Manager is an endpoint least privilege and application control solution for Windows and macOS, capable of supporting enterprises and fast-growing organizations at scale. Mitigate malware and modern security threats from exploiting applications by removing local administrative rights from endpoints. The two major components are Local Security and Application Control.

Using Privilege Manager discovery, administrators can automatically discover local administrator privileges and enforce the principle of least privilege through policy-driven actions. 

There are a total of four policy-driven actions which are 

- blocking, elevating, monitoring, allowing
- application quarantine, sandbox, and isolation
- application privilege elevation
- endpoint monitoring

## Features of Dealinea Privilege Management System

1. Able to be integrated with Active Directory
2. Able to generate Agent and OS Report
3. Local Admin Rights Removal
4. Application Discovery for Administrative or Root Privileges
5. Centralized Application and Execution Event Logging
6. Custom and Scheduled Reports
7. Realtime Application Analysis Reputation Check
8. Sandboxing
9. Tailored Block Elevation Justification and Monitoring Policies
10. User Account Control (UAC) Override
11. Windows & Mac Account Discovery on Endpoints

### 1. Able to be integrated with Active Directory

Privilege Manager integrates with AD so administrators can synchronize Domain Objects such as computers, OUs, and security groups from AD with their application control policies. This can ensure unauthorized changes to AD made by endpoint users, can be blocked automatically in real time. 

### 2. Able to generate Agent and OS Report

Privilege Manager is able to make use of Privilege Manager Agents to evaluate the health and status of end point Operating Systems in real time. The reporting is fully customizable and can be exported to various applications and formats.

### 3. Local Admin Rights Removal

Privilege Manager can automatically revoke all local administrative privileges on endpoints to adhere to a least privilege policy. The application-level privilege elevation, user-level privileges are not required. Systems and Resources can still be accessed when required.

### 4. Application Discovery for Administrative or Root Privileges

The most powerful applications installed on endpoints are those that require administrator credentials or root privileges to run. Privilege Manager discovers all applications that run on endpoints through its Learning Mode, giving a precise snapshot of how these applications are used before changes are implemented. Discovery policies can be set up to target any new application action that requires administrator or root access, so no privileged action goes unnoticed.

Non-Domain Endpoint Support: Privilege Manager provides management and application control support for endpoints even if it is not associated with the organizational network. Because it utilizes agents, it can manage endpoints outside the network, such as those used by vendors, contractors, and partners, with the same dexterity and precision control as those within the network.

### 5. Centralized Application and Execution Event Logging

Privilege Manager can record all executable events on managed endpoints to be reviewed, searched, and analyzed. These logs in a unified manner without leaving the console.

### 6. Custom and Scheduled Reports

Privilege Manager's ability to quickly generate fully customized reports and schedule the execution and delivery of these reports is essential to maintaining a real-time understanding of aspects of the least privilege program.

### 7. Realtime Application Analysis Reputation Check

Privilege Manager integrates with reputation checking software like VirusTotal to provide application analysis in real time. This unique feature allows for reputation analysis of any unknown applications in order to mitigate risk of endpoint attacks from ransomware, zero-day attacks, drive-by downloads, and other unknown malicious software. With Privilege Manager, all applications that meet a general condition (i.e. executed from a specific directory or directories, file names, types, or any applications that are disassociated with existing policies) can be sent to VirusTotal for a reputation check and analysis.

### 8. Sandboxing

Sandboxing quarantines applications so they are not allowed to execute, or only allowed to execute in a limited way so they don't touch any system folders or underlying OS configurations. Privilege Manager supports sandboxing for applications that are not known, to ensure they do not negatively impact productivity or introduce threats to the endpoint or network.

### 9. Tailored Block Elevation Justification and Monitoring Policies

Privilege Manager supports allowing trusted applications, blocking to deny known malicious applications based on attributes, file hash, location, or certificates, and monitoring to prevent unknown applications from running. Monitoring provides a system for discovering the unknowns and adding an action that hinges on a reputation check. Distinct from allowing applications to run with default user level privileges, an elevation policy applies admin credentials to specified applications. This type of policy is often paired, so that employees can perform trusted tasks that require administrator credentials to complete, like installing a trusted application (Adobe) or device (printer), without involving IT support.

### 10. User Account Control (UAC) Override

By only elevating application privileges based upon specific policies and criteria, Privilege Manager ensures people don't use Microsoft's UAC capabilities to grant a dangerous or unknown application administrative rights under any circumstance.

### 11. Windows & Mac Account Discovery on Endpoints

The Privilege Manager is able to identify all local accounts on agent-installed endpoints and flags those with local admin rights, including hidden or hardcoded admin privileges. The viewing of this information through the Privilege Manager provides an overview to the devices and makes management easy.

## Useful Features to Detect POCs Identified

### Creation of Custom Policies

There are a total of two types of policies that can be created. Monitoring Policy as well as Controlling Policy. Policies can be created making use of three methods, Policy Wizard, Workstation Policies as well as Policy Templates. After the creation of the policy, the policy can be further customised. 

#### Default Policies

While policy templates are not provided with the product, the default policies can be downloaded within the Privilege Manager Console. These list of default features allow a quick and easy configuration and activation of policies. 

Some policies that have been identified and can potentially block some of the POCs that have been curated includes
- Removal of Advanced Privileges for Advanced Users
- Block Script User/Group/LSA Management
  - Blocks Management of Local Users/Groups and Adding/Removing LSA Privileges from CLI Tools
- Limit Process Rights For Unclassified Applications Discovered In the Last Week
- Event Discovery Audit Elevated Privileges Policy

### Application Firewall

The application firewall consists of a total of three types of policies. These policies are Monitoring Policy, Controlling Policy and Workstation Policy. These various policies either monitors the actions being performed or control the permissioning allowing a set of predefined services to have elevation rights based on the needs of the Organisation. 

### Blocking Policies

Blocking is a policy which denies the application from running on the endpoint based on the application's attributes, files, hash, location or certificates. This provides the ability of blocking specific known and unwanted applications from running on the end point. 

Within the blocking configurations, the administrators are given the option to configure the blocking as either a block silently option or a notify and block option. This policy is able to potentially block the data exfiltration of data through online cloud storage by creating a blocking policy to silently block data from moving to an unknown endpoint. 
