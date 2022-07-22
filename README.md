# IPv6 translation ⟺ IPv4 thrus TCP protocol

The goal of the project is to allow a machine using only the TCP/IPv6 stack to communicate with
machines in IPv4 transparently through the TCP protocol.

![image](https://user-images.githubusercontent.com/75567246/180519030-80e4beed-5e91-4bd3-bfaa-1ada86dcf51a.png)



## Dig In

### The IPv6 ⟺ IPv4 protocol translation happens as follows:

* The Hote1 machine obtains the global IPv6 network prefix from the router (**Hote**):
* The Hote1 machine connects to a server external to the network, according to its global IPv6 address
* The connection of the Hote1 machine is supported by the router in the following way:

    * Packet received in IPv6 containing the TCP protocol intended for a server external to the network: 
    
          => TCP segment decapsulation
          => Encapsulation of the segment in an IPv4 datagram
          => Sending the packet to the external server according to its IPv4 address
          
    * Packet received in IPv4 containing the TCP protocol intended for the client machine
          
          => decapsulation of the TCP segment;
          => encapsulation of the segment in an IPv6 datagram;
          => sending the packet to the client machine;



### Tools to used 
  
***NetFilter***, the firewall built into Linux, in particular the “mangle” table which will allow us to inter-
accept packets at the entrance of the TCP/IP stack thanks to its "PREROUTING" chain;

***NFQueue***, the NetFilter ⇔ "User space" gateway that will allow us to retrieve the packets
IPv4 and IPv6 within a user program from a NetFilter rule;

***Scapy*** for the analysis, modification, creation and injection of IPv4 or IPv6 packets;

***Radvd*** the daemon doing router advertisement broadcasting for network prefix broadcasting
IPv6 and router supporting traffic to and from outside the local network;

***Socat***, as a tool for making TCP connections whether in IPv4 or IPv6.



## contributors :

* [Yawavi Jeona-Lucie LATEVI](https://github.com/jeo284)
* [Claudio Antonio](https://github.com/MonaQuimbamba)
