#!/usr/bin/env python
import dpkt
import random
import sys

counter = 0
ipcounter = 0
tcpcounter = 0
udpcounter = 0

infile = sys.argv[1]
outfile = sys.argv[2]

output_pcapfile = dpkt.pcap.Writer(open(outfile, 'wb'))

pkts = list()
# read packets to list
for ts, pkt in dpkt.pcap.Reader(open(infile, 'r')):
    counter += 1
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    ipcounter += 1

    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcpcounter += 1

    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udpcounter += 1

    pkts.append(pkt)

# shuffle the packets
random.shuffle(pkts)

# write them to output pcap file
for pkt in pkts:
    output_pcapfile.writepkt(pkt)

# print some stats
print ("Total number of packets in the pcap file: " + str(counter))
print ("Total number of ip packets: " + str(ipcounter))
print ("Total number of tcp packets: " + str(tcpcounter))
print ("Total number of udp packets: " + str(udpcounter))
