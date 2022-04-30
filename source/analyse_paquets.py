#!/usr/bin/python
# coding=utf-8
import nfqueue, socket
from scapy.all import *
import subprocess

liste_addr=[]
liste_addr.append(("3001:1030:5329:6d2c:211:deff:fead:beef","172.16.1.254",7890))
interface=""
def traite_paquet(payload):
    # le paquet est fourni sous forme d'une séquence d'octet, il faut l'importer
    data = payload.get_data()
    # il faut identifier sa nature IPv6 ou IPv4
    premier_quartet = data[0].encode("hex")[0]
    if (premier_quartet == '4') :
        # paquet IPv4
        pkt = IP(data)
        addr_ipv4_src = pkt.src
        if addr_ipv4_src == liste_addr[0][1]: # pour les serveur externe sur un netns avec socat
            #Partie Ethernet
            cmd = subprocess.Popen("ip netns exec hote1 ip a show dev hote1-eth0 | grep 'ether' | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
            (addr_ether_dst, ignorer) = cmd.communicate()
            ether=Ether()
            ether.dst= str(addr_ether_dst.decode()).strip()
            ether.type=0x86DD
            cmd = subprocess.Popen("ip a show dev resB | grep 'ether' | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
            (addr_ether_src, ignorer) = cmd.communicate()
            ether.src=str(addr_ether_src.decode()).strip()
            #Partie IPV6
            cmd = subprocess.Popen("ip netns exec hote1 ip a show dev hote1-eth0 | grep 'global' | cut -b 11-43", shell=True,stdout=subprocess.PIPE)
            (addr_ipv6_dst, ignorer) = cmd.communicate()
            addr_ipv6_dst= str(addr_ipv6_dst.decode()).strip()
            add_ipv6_src=liste_addr[0][0]

            pkt6 = IPv6(dst=addr_ipv6_dst, src = add_ipv6_src)
            pkt6 = ether/pkt6/pkt[TCP]
            del pkt6[IPv6].chksum
            del pkt6[TCP].chksum
            #pkt6.show2()
            print(" connexion etape : ",pkt6[TCP].flags)
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, bytes(pkt6), len(pkt6))
            sendp(pkt6,iface="switchipv6")
        else: # pour les serveur externe sur internet
                if addr_ipv4_src in [ str(addr[1]) for addr in liste_addr ]:
                    #Partie Ethernet
                    cmd = subprocess.Popen("ip netns exec hote1 ip a show dev hote1-eth0 | grep 'ether' | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
                    (addr_ether_dst, ignorer) = cmd.communicate()
                    ether=Ether()
                    ether.dst= str(addr_ether_dst.decode()).strip()
                    ether.type=0x86DD
                    cmd = subprocess.Popen("ip a show dev switchipv6 | grep 'ether' | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
                    (addr_ether_src, ignorer) = cmd.communicate()
                    ether.src=str(addr_ether_src.decode()).strip()
                    #Partie IPV6
                    cmd = subprocess.Popen("ip netns exec hote1 ip a show dev hote1-eth0 | grep 'global' | cut -b 11-43", shell=True,stdout=subprocess.PIPE)
                    (addr_ipv6_dst, ignorer) = cmd.communicate()
                    addr_ipv6_dst= str(addr_ipv6_dst.decode()).strip()
                    add_ipv6_src=""
                    port_dst =0
                    for addr in liste_addr:
                        if addr[1]== addr_ipv4_src:
                            add_ipv6_src = addr[0]
                            port_dst=int(addr[2])
                            break

                    pkt[TCP].dport = port_dst
                    pkt[TCP].sport=7890
                    pkt6 = IPv6(dst=addr_ipv6_dst, src = add_ipv6_src)
                    pkt6 = ether/pkt6/pkt[TCP]
                    del pkt6[IPv6].chksum
                    del pkt6[TCP].chksum
                    #pkt6.show2()
                    print(" connexion etape : ",pkt6[TCP].flags)
                    payload.set_verdict_modified(nfqueue.NF_ACCEPT, bytes(pkt6), len(pkt6))
                    sendp(pkt6,iface="switchipv6")
                else:
                    # si rejete : le paquet est rejeté
                    payload.set_verdict(nfqueue.NF_DROP)

    else:
        # paquet IPv6 to ipv4
        pkt = IPv6(data)
        if pkt.dst in [ str(addr[0]) for addr in liste_addr ]: # pour les serveur externe sur un netns
            ether=Ether()
            cmd = subprocess.Popen("ip netns exec server ip a show dev server-eth0 | grep 'ether' | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
            (addr_ether_dst, ignorer) = cmd.communicate()
            ether.dst= str(addr_ether_dst.decode()).strip()
            #ether.dst= "f6:19:e6:14:08:5a"
            ether.type=0x800
            cmd = subprocess.Popen("ip a show dev resB | grep 'ether' | cut -b 16-33", shell=True,stdout=subprocess.PIPE)
            (addr_ether_src, ignorer) = cmd.communicate()
            ether.src=str(addr_ether_src.decode()).strip()
            cmd = subprocess.Popen("ip a show dev resB | grep 'inet ' | cut -b 10-21", shell=True,stdout=subprocess.PIPE)
            (addr_ipv4_src, ignorer) = cmd.communicate()
            ip4 = IP()
            addr_ipv4_dst=liste_addr[0][1]
            ip4.dst=addr_ipv4_dst
            ip4.src=str(addr_ipv4_src.decode()).strip()
            # faire le paquet
            pkt[TCP].dport=liste_addr[0][2]
            pkt4=ether/ip4/pkt[TCP]
            del pkt4[IP].chksum
            del pkt4[TCP].chksum
            #pkt4.show2()
            print(" connexion etape : ",pkt4[TCP].flags)
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, bytes(pkt4), len(pkt4))
            sendp(pkt4,iface="resB")


        else: # pour les serveur externe sur internet
            addr_ipv4_dst =traducteur(pkt.dst,6)
            if addr_ipv4_dst:
                # sauvegarder la correspondance ipv6 to ipv4 (ip6,ip4,port)
                liste_addr.append((pkt.dst,addr_ipv4_dst, pkt[TCP].sport))
                ## récuperer @ ipv4 de la machine hote
                cmd = subprocess.Popen("ip a show dev %s | grep 'inet ' | cut -b 10-21"%interface, shell=True,stdout=subprocess.PIPE)
                (addr_ipv4_src, ignorer) = cmd.communicate()
                ip4 = IP()
                ip4.dst=addr_ipv4_dst
                ip4.src=str(addr_ipv4_src.decode()).strip()
                # faire le paquet
                pkt[TCP].sport=pkt[TCP].dport
                pkt[TCP].dport=80
                pkt4=ip4/pkt[TCP]
                del pkt4[IP].chksum
                del pkt4[TCP].chksum
                pkt4.show2()
                # si modifie : le paquet est remis MODIFIE dans la pile TCP/IP et poursuit sa    route
                payload.set_verdict_modified(nfqueue.NF_ACCEPT, bytes(pkt4), len(pkt4))
                send(pkt4,iface=interface)

            else:
                # si rejete : le paquet est rejeté
                payload.set_verdict(nfqueue.NF_DROP)

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
        return addr_ipv4.decode().split("\n")[0]

interface="wlp0s20f3" #input("Entrer le nom de l'interface")
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
