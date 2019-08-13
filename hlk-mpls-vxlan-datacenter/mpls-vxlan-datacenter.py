#!/usr/bin/python
#

# This frankenpacket uses multiple levels of encapsulation.

# Its not unrealistic to see one such if two datacenters uses VXLAN
# and the underlying internet provider uses MPLS

###[ Loading modules ]###
import sys
import getopt
#from scapy.all import PcapReader, wrpcap, Packet, NoPayload
from scapy.all import *

load_contrib("mpls")
mpls_eth = Ether(src="00:16:3e:11:11:11", dst="ca:01:07:fc:00:1c", type=0x8847)
mpls_lables=MPLS(label=16, s=0, ttl=255)/MPLS(label=18, s=0, ttl=255)/MPLS(label=18, s=0, ttl=255)/MPLS(label=16, s=1, ttl=255)

# VLAN
prepacket=mpls_eth/mpls_lables/Ether(dst="00:00:00:00:00:03")/Dot1Q(vlan=42)

vtepsrc="192.0.2.1"
vtepdst="192.0.2.2"
vxlanport=4789
vni=100

# Create a VXLAN header
vxlan=prepacket/IP(src=vtepsrc,dst=vtepdst, options=IPOption('\x44\x10\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x83\x03\x10'))/UDP(sport=1234,dport=vxlanport)/VXLAN(vni=vni,flags="Instance")

# Make VXLAN innner packet
broadcast="ff:ff:ff:ff:ff:ff"
srcmac="00:24:9b:47:0d:49"
source="198.51.100.124"
dstmac="00:50:56:12:34:56"
destination="198.51.100.200"

realpacket=IP(src=source,dst=destination, options=IPOption('\x83\x03\x10'))/UDP()/DNS(rd=1,id=0xdead,qd=DNSQR(qname="www.bornhack.dk"))

packet=vxlan/Ether(dst=dstmac,src=srcmac)/realpacket
#packet2=vxlan/Ether(dst=dstmac,src=srcmac)/packet

# Debug
#packet.show()

headers=len(packet)-len(realpacket)

# Stats
print "Length of packet with all encapsulation: " + str(len(packet))
print "Length of headers packet: " + str(headers)
print "Length of innermost packet: " + str(len(realpacket))
print "Overhead ratio: " + str(100 * len(packet) / float ( len(realpacket)) )

wrpcap("mpls-vxlan-datacenter.cap",packet)
wireshark (packet)
