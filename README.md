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

## Submit yours!

I want to see what crazy packets we can create. I hope you will join me, by submitting pull requests.

Make a new directory with your handle and some short name. In this I expect you to leave a script/program to produce it, and a pcap. You are free to build on my examples or start from scratch.

When you submit something I hope they are "correct" or somewhat perfect packets. Getting network tools like tcpdump, wireshark to at least parse some of it is mandatory - so they would be forwarded in case you sent them on a real network.

Note: perfect in this world might be something you can inject, and not necessarily something a real system would produce. Think of the ping of death
which was a malformed packets.

https://en.wikipedia.org/wiki/Ping_of_death

## Goals

Have fun and learn networking on a low level.

Find packets that make routers and firewalls puke, or at least spend more resources processing.

I will use these as input for Zeek https://www.zeek.org/ and Suricata https://suricata-ids.org/ to see if they break :-D
