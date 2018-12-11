#!/usr/bin/python

import dpkt, pcap, binascii, redis

timeout = 120 # ttl of observed mac address in seconds
prefix = 'mac_' # key prefix in redis db

pc = pcap.pcap()
pc.setfilter('arp')
r = redis.Redis()

for timestamp, packet in pc:
        eth = dpkt.ethernet.Ethernet(packet)
        r.setex(prefix + binascii.hexlify(eth.src), 1, timeout)
