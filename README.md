# PowerShell-Process-Execution-Detection
Investigation-- PowerShell Process Execution Detection

**PowerShell Process Execution Detection**

Objective

To detect and investigate PowerShell process execution on a monitored Windows 11 endpoint using Wazuh and Sysmon.

Lab Environment

* SIEM: Wazuh
* Endpoint: Windows 11
* Telemetry: Sysmon
* Detection: Wazuh Rule ID 92027
* Sysmon Event: Event ID 1 — Process Creation

Test Activity

A controlled PowerShell command was executed on the Windows endpoint to generate a process-creation event.

Detection

Wazuh generated the following alert:

Field	                           Value
Rule ID	                         92027
Rule Level                       	4
Event ID                        	1
Description           	Windows PowerShell
Process ID	                     1244

Investigation

The alert was investigated using process-related telemetry, including:

* Process image
* Command line
* Parent process
* Parent command line
* User account
* Process ID
* File hashes
* Current working directory

Process Relationship

The parent-child process relationship is important during investigation.

For example:

WINWORD.EXE → powershell.exe

Would indicate that Microsoft Word launched PowerShell. This can require additional investigation because document-based attacks can use scripting interpreters to execute commands.

However, the presence of PowerShell alone is not sufficient to classify an event as malicious. The command line, parent process, user activity, file origin, hashes, and related network/process events should be reviewed before making a determination.

SOC Investigation Workflow

Log → Detection → Alert → Triage → Investigation → Evidence → Classification → Response

Key Learning

This exercise demonstrated how Sysmon process-creation telemetry can be collected by Wazuh and used to investigate PowerShell execution through process metadata and parent-child relationships, rather than relying solely on the alert severity.

[ WINWORD.EXE   ---->   powershell.exe  
 This can be suspicious because a Word document may have triggered PowerShell, potentially through a malicious macro or exploit... ]




1. Image path                —                  Is it actually running from the legitimate Microsoft Office directory?
2. Parent process            —                  What launched Word?
3. Child processes           —                  Did Word launch powershell.exe, cmd.exe, wscript.exe, mshta.exe, etc.?
4. Command line              —                  Any unusual arguments?
5. User                      —                  Which account launched it?
6. Network connections       —                  Did Word make an unusual outbound connection?
7. File activity             —                  Did it create/drop an executable or script?
 
