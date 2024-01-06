from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *


def getThroughput(packets, protocol, port):
    total = 0
    count = 0
    if protocol == 'TCP':
        for packet in packets[TCP]:
            count += 1
        for i in range(count):
            if packets[TCP][i][2].dport == port:
                total += len(packets[TCP][i])
    else:
        for packet in packets[UDP]:
            count += 1
        for i in range(count):
            if packets[UDP][i][2].dport == port:
                total += len(packets[UDP][i])
    Mbps = (total * 8 / 1000000) / 5
    return Mbps

# read pcap
packets_h3_T = rdpcap("../out/TCP_h3.pcap") 
packets_h4_T = rdpcap("../out/TCP_h4.pcap") 
packets_h3_U = rdpcap("../out/UDP_h3.pcap") 
packets_h4_U = rdpcap("../out/UDP_h4.pcap") 


print("\n --- TCP --- ")
print("Flow1(h1->h3):              {} Mbps".format(getThroughput(packets_h3_T, "TCP", 7777)))
print("Flow2(h1->h3):              {} Mbps".format(getThroughput(packets_h3_T, "TCP", 7776)))
print("Flow3(h2->h4):              {} Mbps".format(getThroughput(packets_h4_T, "TCP", 7775)))
print("")
print(" --- UDP --- ")
print("Flow1(h1->h3):              {} Mbps".format(getThroughput(packets_h3_U, "UDP", 7777)))
print("Flow2(h1->h3):              {} Mbps".format(getThroughput(packets_h3_U, "UDP", 7776)))
print("Flow3(h2->h4):              {} Mbps\n".format(getThroughput(packets_h4_U, "UDP", 7775)))
