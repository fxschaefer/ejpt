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


