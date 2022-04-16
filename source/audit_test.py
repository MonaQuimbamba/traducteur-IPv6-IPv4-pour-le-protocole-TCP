#!/usr/bin/python


import subprocess
from scapy.all import *


def traiter_packet(p):
    if TCP in p:
        if p[IP].dst=='8.8.8.8':
            p.show2()

    # sudo ip a add 10.188.12.200/16 dev switchipv6
    ## dig ipv4 to ipv6
    # dig -x 74.125.236.167 +short
    # dig -t aaaa dns.google +short

    ## dig ipv6 to ipv4
    #dig -x 2001:4860:4860::8844 +short
    #dig -t a dns.google +short

    #Netfilter
    #sudo iptables -t mangle -A PREROUTING -p tcp --dport 7890 -j NFQUEUE --queue-num 0
    #sudo ip6tables -t mangle -A PREROUTING -i switchipv6 -p tcp --dport 7890 -j NFQUEUE --queue-num 0

    # socat - tcp6-listen:7890
    # socat - tcp6:[2001:4860:4860::8844]:7890
    # socat - tcp6:[fe80::e02b:17ff:fe97:db47%eth0]:7890


    # pour envoyer une trame ethernet sur l'interface bridge_ipv6
    #sendp(pkt,iface="bridge_ipv6")

    # type ether
    #  ipv4 0x800
    # IPv6  0x86DD

    # recuperer les ethernet @
    # sudo ip netns exec hote1 ip a show dev <interface> | grep "ether" | cut -b 16-33
sniff(count=0,prn=traiter_packet,iface=["wlp0s20f3"])
