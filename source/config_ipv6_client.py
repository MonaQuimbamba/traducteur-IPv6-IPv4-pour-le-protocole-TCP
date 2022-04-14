#!/usr/bin/python


import subprocess
from scapy.all import *


def traiter_packet(p):
    if ICMPv6NDOptPrefixInfo in p:
        #p.show2()
        config_ipv6(p[ICMPv6NDOptPrefixInfo].prefix)

def config_ipv6(prefix_global):
    cmd = subprocess.Popen("ip l show | grep ether | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
    (mac, ignorer) = cmd.communicate()
    ip6_id_global =prefix_global[:-2]
    id_machine="2451"
    mac = mac.decode().split("\n")[0].strip()
    mac= mac.replace(":","")
    mac = [mac[i:i+4] for i in range(0, len(mac), 4)]
    for hex in mac: # add le mac pour le id dans @ ipv6
        ip6_id_global+=':'+hex
    ip6_id_global+=":"+id_machine+"/64"
    print(ip6_id_global," addr global ")
    cmd = subprocess.Popen("sudo ip addr add %s dev hoste1-eth0"%ip6_id_global, shell=True,stdout=subprocess.PIPE)
    (cmd, ignorer) = cmd.communicate()

    ## ajouter la route par default
    #  sudo ip -6 route add  2001:2:3:4501::/64 dev hoste1-eth0 metric 1
    # dig  -x @ip6
    # dig -t aaaa +short @ip4 ou hostname 

sniff(count=1,lfilter = lambda x: x.haslayer(ICMPv6ND_RA),prn=traiter_packet,iface=["hoste1-eth0"])
