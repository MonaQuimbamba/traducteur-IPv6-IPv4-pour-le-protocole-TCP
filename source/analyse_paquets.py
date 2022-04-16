#!/usr/bin/python
# coding=utf-8
import nfqueue, socket
from scapy.all import *
import subprocess

liste_addr=[]

def traite_paquet(payload):
    # le paquet est fourni sous forme d'une séquence d'octet, il faut l'importer
    data = payload.get_data()
    # il faut identifier sa nature IPv6 ou IPv4
    premier_quartet = data[0].encode("hex")[0]
    if (premier_quartet == '4') :
        # paquet IPv4
        pkt = IP(data)
        #cmd = subprocess.Popen("ip a show dev switchipv6 | grep 'ether' | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
        #(addr_ether_src, ignorer) = cmd.communicate()
        #ether=Ether()
        #ether.dst= 'ff:ff:ff:ff:ff:ff'
        #ether.src=str(addr_ether_src.decode()).strip()
        #ether.type=0x800
        print(" ici ")
    else:
        # paquet IPv6 to ipv4
        pkt = IPv6(data)

        addr_ipv4_dst =traducteur(pkt.dst,6)
        if addr_ipv4_dst:
            # sauvegarder la correspondance ipv6 to ipv4
            liste_addr.append((pkt.dst,addr_ipv4_dst))
            #cmd = subprocess.Popen("ip a show dev switchipv6 | grep 'inet ' | cut -b 10-22", shell=True,stdout=subprocess.PIPE)
            #(addr_ipv4_src, ignorer) = cmd.communicate()
            addr_ipv4_src='10.188.12.200'
            ip4 = IP()
            ip4.dst=addr_ipv4_dst
            ip4.src=str(addr_ipv4_src.decode()).strip()
            # faire le paquet
            pkt[TCP].sport=pkt[TCP].dport
            pkt[TCP].dport=80
            pkt4=ip4/pkt[TCP]
            del pkt4[IP].chksum
            #del pkt4[TCP].chksum
            pkt4.show2()
            # si modifie : le paquet est remis MODIFIE dans la pile TCP/IP et poursuit sa    route
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, bytes(pkt4), len(pkt4))
            ## pour envoyer un datagramme IP sur l'interface wlp0s20f3
            send(pkt4,iface="wlp0s20f3")
        else:
            # si rejete : le paquet est rejeté
            payload.set_verdict(nfqueue.NF_DROP)



    #pkt.show()
    # accepte le paquet : le paquet est remis dans la pile TCP/IP et poursuit sa route
    #payload.set_verdict(nfqueue.NF_ACCEPT)



def traducteur(ipx,type):
    if type==4:
        cmd = subprocess.Popen("dig -x %s +short"%ipx, shell=True,stdout=subprocess.PIPE)
        (dns, ignorer) = cmd.communicate()
        cmd = subprocess.Popen("dig -t aaaa %s +short"%str(dns.decode()).strip(), shell=True,stdout=subprocess.PIPE)
        (addr_ipv6, ignorer) = cmd.communicate()
        return addr_ipv6.decode().split("\n")[0]
    if type==6:
        cmd = subprocess.Popen("dig -x %s +short"%ipx, shell=True,stdout=subprocess.PIPE)
        (dns, ignorer) = cmd.communicate()
        cmd = subprocess.Popen("dig -t a %s +short"%str(dns.decode()).strip(), shell=True,stdout=subprocess.PIPE)
        (addr_ipv4, ignorer) = cmd.communicate()
        #print(repr(addr_ipv4.decode()))
        return addr_ipv4.decode().split("\n")[0]





q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET6)
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET6)
q.bind(socket.AF_INET)
q.set_callback(traite_paquet)
q.create_queue(0)
try:
    q.try_run()
except KeyboardInterrupt(e):
    print("interruption")
q.unbind(socket.AF_INET)
q.unbind(socket.AF_INET6)
q.close()
