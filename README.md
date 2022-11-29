# TOOLS TO MASTER
- dirb (dirbuster)
- gobuster
- nmap
- hydra
- smbclient
- rpcclient
- enum4linux
- dnsdumpster.io or dnsrecon
- netcraft.com
- smbmap
- arp-scan
- wireshark
- dig
- METASPLOIT
- whatweb

# Assessment Methodologies: Information Gathering

## Information Gathering
Information Gathering is the first step of any penetration test. It's one of the most important phases, because any further steps are relying on the information we've gathered. Typically we can devide Information-Gathering in two categories:
- Passive Information Gathering
-- Identifying IP addresses & DNS information
-- Identifying domain names and domain ownership information
-- Identifying email addresses and social media profiles
-- Identifying web technologies being used on target sites
-- Identify Subdomains

- Active Information Gathering
-- Discovering open ports on target systems
-- Learning about the internal infrastructure of a target network/organization
-- Enumerating information from targets


## Passive Information Gathering
### Website Recon and Footprinting
- host hackersploit.org -> DNS lookup and get IP-Addresses -> if more than one ipv4 / ipv6 than a proxy or firewall (cloudflare etc.) is likely used by this website.
- check robots.txt file -> is used to refuse crawlers to certain directories / what files should not be indexed
- check sitemap.xml / sitemaps.xml -> provide search engines a sturcture for indexing
- buildwith -> firefox plugin for website technology and cms detection
- wappalyzer -> quite the same as buildwith
- whatweb hackersploit.org -> command for identifying web technologies and plugins that is used (equivalent to plugins mentioned above)
- httrack -> program to copy a website locally for further analysis
- whois hackersploit.org or who.is website-> query dns register

### Website Footprinting with Netcraft
- netcraft.com -> Scan a website for technology, network information, first seen, hsoting history, basic ssl vulnerability check etc.
- Easy to consume infos (collection of all methods / commands mentioned above)


### DNS Recon
- dnsrecon -d gkd-group.com -> get all dns records (NS, A, TXT, MX ..)
- dnsdumpster.io -> best dns reconnaicance tool for organized information!!!

### Detect WAF with wafw00f
- wafw00f http://www.gkd-group.com -> check if a waf is used

### subdomain enumeration with sublist3r
- sublist3r -d [DOMAIN] (opt. -t threads; -b bruteforce; -e search engines)
- -b belongs to active reconnaicance.

### Google Dorks
- site: -> limit all results to a given Domain e.g. site: gkd-group.com; site:*.ine.com -> show all subdomains that have been indexed by google.
- inurl: -> search for a part of a url e.g. site:gkd-group.com inurl:wp-content
- intitle: -> specific keyword in site-title
- filetype: -> show all files of a specific filetype e.g. pdf
- intitle:index of -> common vulnerability of directory listing.
- cache: show older versions of a website (for more details better use waybachmachine -> web.archive.org
- Use GOOGLE HACKING DATABASE (GHDB) on exploit-db.com to show some interesting queries.

### E-Mail Harvesting with theHarvester
- theHarvester command / program is preistalled on Kali & Parrot
- theHarvester -d example.com -l 500 -b linkedin -> searches for linkedin information to a given domain
- spyse source is very interesting but requires a subscription

### Leaked Password Databases
- good for password spraying ;)
- haveibeenpwned.com -> Aggregates various databreaches all over the world



## Active Information Gathering

### DNS Zone Transfers
A DNS Zone Transfer is the process to move zone Files from one DNS-Server to another. If misconfigured and left unsecured, this functionality can be abused by attackers to copy the zone files from the primary DNS server to another DNS server. A DNS Zone transfer can provide penetrations testers with a holistic view of an organizations network layout. 
- dnsenum example.com -> tries also to perform a Zone transfer
- dig axfr @NAMESERVER DOMAIN -> axfr is the Zone Transfer Switch
- fierce -dns hackersploit.org -> DNS Bruteforce

### Host Discovery with NMAP
- sN Option -> No Port-Scan Option, only Host discovery (Also known as Ping Scan or Ping Sweep) [nmap -sn 10.0.0.0/16]
- 
- OR USE NETDISCOVER to discover devices via ARP Requests. [sudo netdisvover]


### Port Scanning with NMAP
- Standard NMAP scan is a SYN scan for the 1000 most common ports
- Windows Machine can block Ping requests by default. In this case, NMAP fires up the error "Host seems down.". In this case try the -Pn switch to avoid an availability Ping Scan. (DO not check if host is down)
- nmap -Pn -p- x.x.x.x -> Scanning all Ports
- nmap -Pn -p 80 -> Scan port 80
- nmap -Pn -p 80,445,139 -> Scan a Port selection
- nmap -Pn -p 21-100 -> Scan within a given Range
- By default NMAP will perform a TCP Port-Scan. Use the -sU switch to perform a UDP scan.
- -v switch increases the verbosity
- -sV Service Version detection
- -O switch performs a Operation System Scan (not very accurate)
- -F Fast Switch (scan fewer ports than default)
- -T1-5 switch to speed up a scan (0 = paranoid; 5 = insane)
- -sU -> Perform a UDP Scan, because by default nmap will discover tcp connections. This scan will take some time!
- --top-port 25 --open -> scan top 25 ports and filter for open ports


# Assessment Methodologies: Footprinting and Scanning

## Mapping the Network
- Before any Penetration Test will start, a Scope needs to be defined. It's important that a P-test will provide a value for a customer and will not knock-out production systems.
- Physical Access (Physical Security, OSINT, Social Engineering)
- Sniffing (Passive Recon, Watch network traffic)
- ARP ()
- ICMP (Tracroute, Ping)

Tools -> WIRESHARK, ARP-SCAN, PING, FPING, NMAP, ZENMAP

### ARP-SCAN
- Run an ARP-SCAN via sudo arp-scan -I eth0 -g 10.0.0.0/16

### FPING
- Can send packets to multiple hosts at a time
- fping -I eth0 -g 10.0.0.0/16 -a 2>/dev/null    (filter out errors with the last part)





# Assessment Methodologies: Enumeration
"Enumeration is the method that a penetration tester uses to identify information about in-scope assets."
"Enumeration is defined as a process which establishes an active connection to the target hosts to discover potential attack vectors..."

## SMB: Windows Discover and Mount
- Discover via nmap (Usually Port 445 / 139 TCP).
- Linux: List SMB shares of a Server -> smbclient -L //Server
- Linux: Connect to SMB Share -> smbclient //Server/Share -U USERNAME
- Windows: Connec to SMB Share -> net use Z: \\Server\\Share PASSWORD /user:USERNAME
- Windows: Direct Access -> \\SERVER\SHARE

## SMB: NMAP Scripts
- Run nmap and identify potential targets that are using smb.
- After a target is identified, run nmap -p445 --script smb-protocols 10.x.x.x -> E.g. check if SMBv1 is used.
- nmap -p445 --script smb-security-mode 10.x.x.x -> e.g. ceck is message signing is disabled.
- nmap -p445 --script smb-enum-sessions 10.x.x.x -> Get active / logged on users with active sessions
- nmap -p445 --script smb-enum-shares 10.x.x.x -> Share enumeration
- nmap -p445 --script smb-enum-users --script-args smbusername=USERNAME,smbpassword=PASSWORD 10.x.x.x
- nmap -p445 --script smb-enum-domains --script-args smbusername=USERNAME,smbpassword=PASSWORD 10.x.x.x 10.x.x.x
- nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=USERNAME,smbpassword=PASSWORD 10.x.x.x -> enum and list share content


## SMB: SMBMAP
- Knowing when there is a Server that supports smbv1, we can utilize smbmap with a null-session.
- smbmap -u guest -p "" -d . -H 10.x.x.x
- If you get results with guest user and a null session for more than read access to IPC$ and print$ share, you should report this.
- SMBmap supports some other commands like uploading a file or listing a shared drive. See Documentation -> https://github.com/ShawnDEvans/smbmap


## Linux Samba
- metasploit has some samba / smb enumeration and exploit tools
- nmblookup -A <IP-ADDRESS>
- If we can see IPC$ with a null session you can probably connect via rpc (rpcclient)
- RPC NULL SESSION CONNECT: rpcclient -U '' -N 192.x.x.x

With an anonymous null session you can access the IPC$ share and interact with services exposed via named pipes. The enum4linux utility within Kali Linux is particularly useful; with it, you can obtain the following:
- Operating system information
- Details of the parent domain
- A list of local users and groups
- Details of available SMB shares
- The effective system security policy

## enum4linux
  - Power Tools for Linux and Windows enumeration tasks
  - USAGE: enum4linix -o 192.x.x.x

## Check for SMB Dialect / Versions of smb2
  - start metasploit
  - use auxiliary/scanner/smb/smb2
  - set RHOSTS x.x.x.x
  - run
  
## User enumeration with SMB and RPC
  - NMAP smb-enum-users script
  - Enum4Linux -> shows users
  - rpcclient NULL session and enter following command: enumdomusers
  
  
## SMB Dictionary Attack
  - Start Metasploit
  - use auxiliary/scanner/smb/smb_login
  - show options
  - at least fill RHOSTS
  - set an smb user
  - set a pass_file
  - run exploit
  
  - Using Hydra:
  - hydra -l <USERNAME> -P <PATH TO PASS-FILE> <IP> smb
  
## Find out services which are piped through smb -> named pipes are used for service communication
  - start metasploit
  - use auxiliary/scanner/smb/pipe_auditor
  - set smbuser
  - set smbpass
  - set rhosts
  
## Get SID of Users 
  - enum4linux -r -u 'admin' -p 'password1' 192.x.x.x
  

  
## FTP
- Maybe use Hydra to Bruteforce ftp: hydra -l <USERNAME> -P <PATH TO PASS-FILE> <IP> ftp
- Check for anonymous login: nmap x.x.x.x -p21 --script ftp-anon (Or try manually by username "anonymous" and no password)
  
  
## SSH
- netcat (nc) can also grab a banner by default connection (just like with an nmap service scan)
- nmap x.x.x.x -p22 --script ssh2-enum-algos -> Enumerate Alogrithms for Key creation
- nmap x.x.x.x -p22 --script ssh-hostkey --script-args ssh_hostkey=full -> Grab the full rsa hostkey (WRITE THAT DOWN!)
- nmap x.x.x.x -p22 --script ssh-auth-methods --script-args="ssh.user=admin" -> show authentication methods -> if it shows none_auth THATS DANGEROUS AND WRITE THAT DOWN!
- Dictionary Attack: hydra -l <NAME> -P /usr/share/wordlists/rockyou.txt <IP> ssh
- Bruteforce with NMAP: nmap x.x.x.x -p22 --script ssh-brute --script-args userdb=/root/user
- METASPLOIT: use auxiliary/ssh/ssh_login -> set RHOSTS, set userpass_file, set STOP_ON_SUCCESS, DEFAULT USERNAME IS ROOT
  
  
## HTTP
  ### IIS
  - whatweb <IP or DOMAIN> -> basic enumeration
  - dirb http://<DOMAIN or IO> -> Find directories with default wordlist
  - browsh --startup-url http://x.x.x.x/Default.aspx -> Rendering a website in shell
  - nmap scripts:
    - nmap x.x.x.x -sV -p80 --script http-enum
    - nmap x.x.x.x -sV -p80 --script http-headers (HTTP HEADER INFORMATION)
    - nmap x.x.x.x -sV -p80 --script http-methods --script-args http-methods.url-path=/webdav/ (or something else..)
    - nmap x.x.x.x -sV -p80 --script http-webdav-scan --script-args http-methods.url-path=/webdav/ -> WEBDAV Scan
  
  ### APACHE
  - the same from above applies also here!
  - msfconsole
    - use auxiliary/scanner/http/http_version (check the options and run)
    - use auxiliary/scanner/http/brute_dirs -> Bruteforce / Wordlist Directories
    - ROBOTS.TXT: use auxiliary/scanner/http/robots_txt
  
  
  
  
  
  

  
  
  
  
  

  

  
  
