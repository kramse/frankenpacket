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
vxlan=prepacket/IP(src=vtepsrc,dst=vtepdst)/UDP(sport=1234,dport=vxlanport)/VXLAN(vni=vni,flags="Instance")

# Make VXLAN innner packet
broadcast="ff:ff:ff:ff:ff:ff"
srcmac="00:24:9b:47:0d:49"
source="198.51.100.124"
dstmac="00:50:56:12:34:56"
destination="198.51.100.200"

#realpacket=IP(src=source,dst=destination)/UDP()/DNS(rd=1,id=0xdead,qd=DNSQR(qname="www.bornhack.dk"))

# This part from https://www.packetlevel.ch/html/scapy/scapyipv6.html
a=IPv6(nh=58, src='fe80::214:f2ff:fe07:af0', dst='ff02::1', version=6L, hlim=255, plen=64, fl=0L, tc=224L)
b=ICMPv6ND_RA(code=0, chlim=64, H=0L, M=0L, O=0L, routerlifetime=1800, P=0L, retranstimer=0, prf=0L, res=0L, reachabletime=0, type=134)
c=ICMPv6NDOptSrcLLAddr(type=1, len=1, lladdr='00:14:f2:07:0a:f1')
d=ICMPv6NDOptMTU(res=0, type=5, len=1, mtu=1500)
e=ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L, len=4, prefix='2001:db99:dead::', R=0L, validlifetime=2592000, prefixlen=64, preferredlifetime=604800, type=3)
realpacket=a/b/c/d

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

wrpcap("packet.cap",packet)
wireshark (packet)
