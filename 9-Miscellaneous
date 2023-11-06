
# 9 Miscellaneous

## 9.1 Port Knocking

```sh
# port knock on ports 24->23->22 with nmap
# "-r" forces ports to be hit in order
# may want to add "--max-parallelism 1"
nmap -Pn --host-timeout 201 --max-retries 0 -r -p24,23,22 $VICTIM_IP

# doing the same thing with netcat
# NOTE: netcat can only knock on sequential ports without using a for-loop
nc -z $VICTIM_IP 22-24
```

If you're able to read files on the victim, check out their `/etc/knockd.conf`

## 9.2 Convert text to Windows UTF-16 format on Linux

```sh
# useful for encoding a powershell command in base64
echo "some text" | iconv -t UTF-16LE
```

## 9.3 Extract UDP pcap packet payload data

Using scapy:

```python
#!/usr/bin/env python3
from scapy.all import *
import sys

def handler(packet):
    print(str(packet.payload.payload.payload))

pcap = sys.argv[1]
sniff(offline=pcap, prn=handler, filter="udp")
```

Using Tshark from the command line:

```bash
tshark -r udp.pcap -w udp.hex -Y udp -T fields -e udp.payload | tr -d '\n' | xxd -r -p
# -r = input file
# -w = output file
# -Y = wiresark display filter
# -T = set the output format. "fields" shows only the fileds you select with -e
# -e = chosen fields to display with '-T fields'
# xxd: cannot combine '-r -p' like '-rp'
```

## 9.4 Execute Shellcode from Bash

```sh
cd /proc/$$;exec 3>mem;echo "McBQaC8vc2hoL2JpbonjUFOJ4bALzYA=" | base64 -d | dd bs=1 seek=$(($((16#`cat maps | grep /bin/bash | cut -f1 -d- | head -n 1`)) + $((16#300e0))))>&3
```

Explained:

-  cd into `/proc/$$/` to write to the current PID
-  Create a file descriptor 3 and point it to mem so you an write to FD 3 in the proc’s memory.
-  Echo shellcode as base64 and decode it
-  Use `dd` to write to your memory starting at the output of seek
   -  The line reads out the maps file showing the memory map of the bash process, then it greps for `/bin/bash` to find where it is loaded in memory. It gets the address with cut and head then converts it from base16 to decimal. It adds that number to `0x300e0`
   -  `0x300e0` is the location of bash’s exit function in memory
   -  Net result: You overwrite bash’s exit function with the shellcode

## 9.5 Encryption

### 9.5.1 Create self-signed SSL/TLS certificate

```sh
# generate separate .key and .crt files
openssl req -newkey rsa:2048 -nodes -keyout mycert.key -x509 -days 365 -subj '/CN=example.com/O=Company Inc./C=UK' -out mycert.crt

# simpler method?
openssl req -new -x509 -nodes -out mycert.pem -keyout mycert.key -days 365

# convert .key/.cert to .pem file (easy way)
cat mycert.crt mycert.key > mycert.pem

# official way to convert combo of .key and .crt to .pem if needed:
openssl pkcs12 -export -in mycert.crt -inkey mycert.key -out mycert.p12
openssl pkcs12 -in mycert.p12 -nodes -out mycert.pem

# create client cert from ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out client.pem
openssl pkcs12 -export -in client.pem -inkey ca.key -out client.p12
```

### 9.5.2 Decrypting files with GPG

```sh
# import public and private keys into gpg
gpg --import secring.gpg pubring.gpg

# list imported pubkeys
gpg --list-keys

# list imported private keys
gpg --list-secret-keys

# decrypting file with keys already imported
gpg -d -o secret.txt secret.txt.gpg
```

## 9.6 Validating Checksums

This is how you validate a sha256 checksum for a file:

```sh
# make checksum check-file.
# Format is <hexdigest><space><filename>, in same directory as file.
echo "4987776fef98bb2a72515abc0529e90572778b1d7aeeb1939179ff1f4de1440d Nessus-10.5.0-debian10_amd64.deb" > sha256sum_nessus

# run sha256sum with '-c <check-file>' to have it validate the checksums match
sha256sum -c sha256sum_nessus
```

## 9.7 Inspecting Files with Exiftool

We can examine the metadata of files with `exiftool`, which can reveal a lot of useful information. This information may be helpful for client-side attacks.

```sh
# -a shows duplicated tags
# -u shows unknown tags
exiftool -a -u FILENAME

# TIP: use gobuster to look for files
gobuster dir -ezqrkt100 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -x doc,docx,pdf,xls,xlsx,ppt,pptx,zip -u http://VICTIM_IP
# you can also use an extension wordlist with the (capital) `-X` flag:
# -X /usr/share/seclists/Discovery/Web-Content/raft-small-extensions-lowercase.txt
```

Things to look for:

- file creation date
- last modified date
- author's name
- operating system
- application used to create the file

References:

- [List of tags recognized by `exiftool`](https://exiftool.org/TagNames/)
- [Exiftool download](https://exiftool.org) - shows list of supported files

