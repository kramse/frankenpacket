# frankenpacket
What is the most encapsulated packet, with a somewhat believable story


So internet uses Internet Protocol (IP) suite but over the years a lot of technologies have been added to this mess :-D

Lets try to do some encapsulation, and lets see what stupid, strange, fun packets we can generate!

## Rules

Be Excellent to Each Other

Produce frankenpackets with a LOT of encapsulation and layers!

Produce packets in a repeatable way, I choose Scapy https://scapy.readthedocs.io/en/latest/installation.html which is easy to work with.

Packets should have a somewhat believable story, so adding 1000 (one thousand) MPLS labels is not believable.

So if you add IPv6 extension headers, I guess the limit is somewhere 5-10

First example in hlk-mpls-vxlan-datacenter
 is an example which might happen if an ISP uses Ethernet, MPLS, VLAN and the customer uses VXLAN - to send a DNS packet, which is UDP, IP, in Ethernet.

Please include the pcap also when submitting packets.

## Goals

Have fun and learn networking on a low level.

Find packets that make routers and firewalls puke, or at least spend more resources processing.

I will use these as input for Zeek https://www.zeek.org/ and Suricata https://suricata-ids.org/ to see if they break :-D
