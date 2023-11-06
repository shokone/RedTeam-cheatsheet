
# 1 Information Gathering

## 1.1 Rustscan

Rustscan is a faster way to discover all open ports and autorun nmap to do the
script scanning on those ports.

```sh
VICTIM_IP=VICTIM_IP
sudo rustscan --ulimit 5000 -a $VICTIM_IP -- -n -Pn -sV --script "default,safe,vuln" -oA tcp-all
```

## 1.2 Nmap

If using scripts, you can get script help by `nmap --script-help="nfs-*"`.

```sh
# fast full TCP discovery using massscan:
sudo masscan -p1-65535 --rate=1000 -e tun0 $VICTIM_IP | tee masscan.txt
ports=$(cat masscan.txt | cut -d ' ' -f 4 | cut -d '/' -f 1 | sort -n | tr '\n' ',' | sed 's/,$//')
sudo nmap -v -n -p $ports -oA nmap/tcp-all -Pn --script "default,safe,vuln" -sV $VICTIM_IP

# all TCP ports, fast discovery, then script scan:
# verbose, no DNS resolution, fastest timing, all TCP ports, output all formats
ports=$(nmap -vvv -n -sS -T4 --min-rate 1000 -p- --open --reason $VICTIM_IP | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -n -vvv -sCV -Pn -p $ports -oA nmap/tcp-all $VICTIM_IP

# another option to fast discovery TCP ports
sudo nmap -p- -sS --open --min-rate 5000 -vvv -n -oA enumeration/nmap1 IP
nmap -sCV -p $(cat enumeration/nmap1.nmap | grep open | grep -v nmap | cut -d "/" -f 1 | tr "\n" "," | sed 's/.$//') -oA enumeration/nmap2 IP

# UDP fast scan (top 100)
sudo nmap -n -v -sU -F -T4 --reason --open -T4 -oA nmap/udp-fast $VICTIM_IP
# top 20 UDP ports
sudo nmap -n -v -sU -T4 --top-ports=20 --reason --open -oA nmap/udp-top20 $VICTIM_IP

# specifying safe and wildcard ftp-* scripts
# logic: and, or, not all work. "," is like "or"
nmap --script="safe and ftp-*" -v -n -p 21 -oA nmap/safe-ftp $VICTIM_IP

# to get help on scripts:
nmap --script-help="ftp-*"
```

Nmap Services file lists most common ports by frequency:

```sh
cat /usr/share/nmap/nmap-services
```

The nmap scripts are found in the directory `/usr/share/nmap/scripts`.

If you add a script to that directory (that you download from the internet, for example), then you must update the `script.db` by running:

```sh
sudo nmap --script-updatedb
```



## 1.3 Nessus

First, manually install Nessus on Kali from the `.deb` file. It's not in the `apt` repo.

[Installation Instructions](https://www.tenable.com/blog/getting-started-with-nessus-on-kali-linux)

```sh
# ensure Nessus is started
sudo systemctl start nessusd.service
```

Browse to **https://127.0.0.1:8834** and accept the self-signed SSL cert. Set up free Nessus Essentials license and complete setup prompts. Also create an admin username and password.

Create a New Scan, and navigate the GUI to configure it. The major scan templates are grouped under Discover, Vulnerability, and Compliance.

Nessus is slow and not allowed on the OSCP exam, so this is mostly just for awareness.



## 1.4 Windows Port Scanning

This is a way to live off the land in Windows and perform a port scan.

```powershell
# perform full TCP connection to test if port open
Test-NetConnection -Port 445 $VICTIM_IP

# scanning multiple ports
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("VICTIM_IP", $_)) "TCP port $_ is open"} 2>$null

# limited ports to search
22,25,80,135,139,445,1443,3306,3389,5432 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("VICTIM_IP", $_)) "TCP port $_ is open"} 2>$null
```

## 1.5 Ping Scanner

Pings all hosts in a /24 subnet. Provide any IP address in the subnet as arg.

On Linux with bash:

```sh
#!/bin/bash
addr=${1:-10.1.1.0}
subnet="${addr%.*}"
for i in {1..254}; do
  host="$subnet.$i"
  ping -c1 -w1 $subnet.$i >& /dev/null && echo "$host UP ++++" || echo "$host down" &
  sleep 0.1 || break  # lets you Ctrl+C out of loop
done
wait $(jobs -rp)
echo "Done"
```

And here's a one-liner to do it in Windows:

```powershell
# note: meant to be copy-pasted, not in .bat script (%i vs %%i)
for /L %i in (1,1,255) do @ping -n 1 -w 2 10.2.2.%i | findstr "Reply"
```

## 1.6 Bash Port Scanner

Scans all 65535 ports of a single host. Provide host IP as arg. Only works on Linux systems using bash!

```sh
#!/bin/bash
host=${1}
for port in {1..65535}; do
  timeout .5 bash -c "(echo -n > /dev/tcp/$host/$port) >& /dev/null" &&
    echo "port $port is open" &
done
wait $(jobs -rp)
echo "Done"
```


## 1.7 NC Port Enumeration

Enumerate port in all hosts in a /24 subnet. Provide any PORT to check.

```
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i PORT; done
```

Or enumerate all ports of a single host. Provide host IP as arg.

```
for i in $(seq 1 65536); do nc -zv -w 1 172.16.50.1 $i; done

Or

nc -nvv -w 1 -z 172.16.50.1 1-65535
```


## 1.8 IPv6 to bypass IPv4 filters

Sometimes if you see `filtered` on an nmap scan, the filter may only be applied on IPv4, but not IPv6. Try scanning it again using the host's IPv6 address.

```bash
# First take note of MAC address from nmap scan of device with 'filtered' port.
# NOTE: nmap must be run as sudo to get MAC address.
# If you don't have the MAC from nmap, you can probably get it from
# your arp table with `arp -an`. If you have a hostname, you can
# do a DNS lookup for the AAAA record.

# get list of IPv6 neighbors on tun0 interface
ping6 -c2 ff02::1%tun0 >/dev/null
ip -6 n | grep -i MACADDR

# Then rescan using nmap's IPv6 mode
sudo nmap -6 -n -v -sC -sV -p FILTERED_PORT IPV6_ADDR
```

Here is another example of a script to try to get the link-local IPv6 address by building the EUI format from the MAC:

```bash
#!/bin/bash -e
# Usage: ./ipv4to6.sh 192.168.0.1
# source: https://askubuntu.com/a/771914

IP=$1
ping -c 1 $1 > /dev/null 2> /dev/null
MAC=$(arp -an $1 | awk '{ print $4 }')
IFACE=$(arp -an $1 | awk '{ print $7 }')

python3 -c "
from netaddr import IPAddress
from netaddr.eui import EUI
mac = EUI(\"$MAC\")
ip = mac.ipv6(IPAddress('fe80::'))
print('{ip}%{iface}'.format(ip=ip, iface=\"$IFACE\"))"
```


## 1.9 Whois

Perform `whois` lookups to get information about a domain name, such as the name server and registrar.

```sh
whois megacorpone.com

# optionally specify server to use for whois lookup
whois megacorpone.com -h $WHOIS_SERVER

# perform a reverse lookup
whois 38.100.193.70
```