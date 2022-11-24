# ejpt

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

