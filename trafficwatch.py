import argparse

from scapy.all import *
from datetime import datetime

from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse, NBTSession, NBTDatagram
from scapy.layers.snmp import SNMP

from colorama import Fore, Style
from scapy.packet import Raw

from core.trafficWatchfiglet import trafficwatchfiglet

def analyze_packets(packets, protocol_filter=None, packet_count=None):
    print(f"{Fore.CYAN}{trafficwatchfiglet()}{Style.RESET_ALL}")
    print("----------------------------------------")

    displayed_count = 0

    for packet in packets:
        if packet_count is not None and displayed_count >= packet_count:
            break
        if protocol_filter:
            if protocol_filter == 'ARP' and not packet.haslayer(ARP):
                continue
            elif protocol_filter == 'ICMP' and not packet.haslayer(ICMP):
                continue
            elif protocol_filter == 'TCP' and not packet.haslayer(TCP):
                continue
            elif protocol_filter == 'UDP' and not packet.haslayer(UDP):
                continue
            elif protocol_filter == 'DNS' and not packet.haslayer(DNS):
                continue
            elif protocol_filter == 'DHCP' and not packet.haslayer(DHCP):
                continue
            elif protocol_filter == 'HTTP' and not packet.haslayer(HTTP):
                continue
            elif protocol_filter == 'SNMP' and not packet.haslayer(SNMP):
                continue
            elif protocol_filter == 'LLMNR' and not (packet.haslayer(LLMNRQuery) or packet.haslayer(LLMNRResponse)):
                continue
            elif protocol_filter == 'NetBIOS' and not (
                    packet.haslayer(NBNSQueryRequest) or packet.haslayer(NBNSQueryResponse)):
                continue

        if packet.haslayer(LLMNRQuery):
            print(f"\t{Fore.CYAN}LLMNR Query Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}LLMNR Name       :{Style.RESET_ALL}", packet[LLMNRQuery].qname.decode('utf-8'))
            print("----------------------------------------")



        # LLMNR Response paketlerini kontrol et
        elif packet.haslayer(LLMNRResponse):
            print(f"\t{Fore.CYAN}LLMNR Response Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}LLMNR Name       :{Style.RESET_ALL}", packet[LLMNRResponse].rrname.decode('utf-8'))
            print("----------------------------------------")

        elif packet.haslayer(NBNSQueryRequest):
            print(f"\t{Fore.CYAN}NetBIOS Name Service Query Request Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}NetBIOS Name     :{Style.RESET_ALL}", packet[NBNSQueryRequest].QUESTION_NAME)
            print("----------------------------------------")

        # NetBIOS Name Service Query Response paketlerini kontrol et
        elif packet.haslayer(NBNSQueryResponse):
            print(f"\t{Fore.CYAN}NetBIOS Name Service Query Response Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}NetBIOS Name     :{Style.RESET_ALL}", packet[NBNSQueryResponse].RR_NAME)

            print("----------------------------------------")

        # NetBIOS Session Service paketlerini kontrol et (NetBT ile ilişkili)
        elif packet.haslayer(NBTSession):
            print(f"\t{Fore.CYAN}NetBIOS Session Service Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}Session Length   :{Style.RESET_ALL}", packet[NBTSession].LENGTH)

            print("----------------------------------------")
        # NetBIOS Datagram Service paketlerini kontrol et (NetBT ile ilişkili)
        elif packet.haslayer(NBTDatagram):
            print(f"\t{Fore.CYAN}NetBIOS Datagram Service Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}NetBIOS Type     :{Style.RESET_ALL}", packet[NBTDatagram].Type)
            print(f"{Fore.GREEN}NetBIOS Flags    :{Style.RESET_ALL}", packet[NBTDatagram].Flags)

            print("----------------------------------------")


        elif packet.haslayer(SNMP):
            print(f"\t{Fore.CYAN}SNMP Packet Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}SNMP Version     :{Style.RESET_ALL}", packet[SNMP].version)
            print(f"{Fore.GREEN}SNMP Community   :{Style.RESET_ALL}", packet[SNMP].community.decode('utf-8'))
            print(f"{Fore.GREEN}SNMP PDU Type    :{Style.RESET_ALL}", packet[SNMP].PDUType)
            print("----------------------------------------")
        elif packet.haslayer(DHCP):
            print(f"\t{Fore.CYAN}DHCP Packet Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            dhcp_options = packet[DHCP].options
            for option in dhcp_options:
                if isinstance(option, tuple):
                    print(f"{Fore.GREEN}{option[0]:12.12}     :{Style.RESET_ALL}", option[1])
            print("----------------------------------------")

        elif packet.haslayer(ARP):
            print(f"\t{Fore.CYAN}ARP Packet Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Operation        :{Style.RESET_ALL}", "Request" if packet[ARP].op == 1 else "Reply")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[ARP].psrc)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[ARP].pdst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[ARP].hwsrc)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[ARP].hwdst)
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

            print("----------------------------------------")

        elif packet.haslayer(ICMP):
            print(f"\t{Fore.CYAN}ICMP Packet Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}IP Version       :{Style.RESET_ALL}", packet[IP].version)
            print(f"{Fore.GREEN}TTL              :{Style.RESET_ALL}", packet[IP].ttl)
            print(f"{Fore.GREEN}Checksum         :{Style.RESET_ALL}", packet[IP].chksum)
            print(f"{Fore.GREEN}Packet Size      :{Style.RESET_ALL}", len(packet), "bytes")
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}ICMP Type        :{Style.RESET_ALL}", packet[ICMP].type)
            print(f"{Fore.GREEN}Echo Identifier  :{Style.RESET_ALL}",packet[ICMP].id if hasattr(packet[ICMP], 'id') else 'N/A')
            print(f"{Fore.GREEN}Echo Sequence    :{Style.RESET_ALL}",packet[ICMP].seq if hasattr(packet[ICMP], 'seq') else 'N/A')
            print("----------------------------------------")

        elif packet.haslayer(TCP):
            print(f"\t{Fore.CYAN}TCP Packet Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}IP Version       :{Style.RESET_ALL}", packet[IP].version)
            print(f"{Fore.GREEN}TTL              :{Style.RESET_ALL}", packet[IP].ttl)
            print(f"{Fore.GREEN}Checksum         :{Style.RESET_ALL}", packet[IP].chksum)
            print(f"{Fore.GREEN}Packet Size      :{Style.RESET_ALL}", len(packet), "bytes")
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}Source Port      :{Style.RESET_ALL}", packet[TCP].sport)
            print(f"{Fore.GREEN}Destination Port :{Style.RESET_ALL}", packet[TCP].dport)
            print(f"{Fore.GREEN}TCP Flags        :{Style.RESET_ALL}", packet[TCP].flags)
            print("----------------------------------------")
        elif packet.haslayer(UDP):
            print(f"\t{Fore.CYAN}UDP Packet Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}IP Version       :{Style.RESET_ALL}", packet[IP].version)
            print(f"{Fore.GREEN}TTL              :{Style.RESET_ALL}", packet[IP].ttl)
            print(f"{Fore.GREEN}Checksum         :{Style.RESET_ALL}", packet[IP].chksum)
            print(f"{Fore.GREEN}Packet Size      :{Style.RESET_ALL}", len(packet), "bytes")
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}Source Port      :{Style.RESET_ALL}", packet[UDP].sport)
            print(f"{Fore.GREEN}Destination Port :{Style.RESET_ALL}", packet[UDP].dport)

            print("----------------------------------------")

        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):  # DNSQR: DNS Question Record
            print(f"\t{Fore.CYAN}DNS Request Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Timestamp       :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}Source IP       :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP  :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC      :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Packet Size     :{Style.RESET_ALL}", len(packet), "bytes")
            print(f"{Fore.GREEN}TTL             :{Style.RESET_ALL}", packet[IP].ttl)
            print(f"{Fore.GREEN}Type            :{Style.RESET_ALL}", packet[DNSQR].qtype)
            print(f"{Fore.GREEN}IP Checksum     :{Style.RESET_ALL}", packet[IP].chksum)
            print(f"{Fore.GREEN}UDP Checksum    :{Style.RESET_ALL}", packet[UDP].chksum)
            print(f"{Fore.GREEN}DNS Request     :{Style.RESET_ALL}", packet[DNSQR].qname.decode('utf-8'))

            print("----------------------------------------")

        # DNS Response paketlerini kontrol et
        elif packet.haslayer(DNS) and packet.haslayer(DNSRR):  # DNSRR: DNS Resource Record
            print(f"\t{Fore.CYAN}DNS Response Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Timestamp       :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}Source IP       :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP  :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC      :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}Packet Size     :{Style.RESET_ALL}", len(packet), "bytes")
            print(f"{Fore.GREEN}TTL             :{Style.RESET_ALL}", packet[IP].ttl)
            print(f"{Fore.GREEN}Type            :{Style.RESET_ALL}", packet[DNSRR].type)
            print(f"{Fore.GREEN}IP Checksum     :{Style.RESET_ALL}", packet[IP].chksum)
            print(f"{Fore.GREEN}UDP Checksum    :{Style.RESET_ALL}", packet[UDP].chksum)
            print(f"{Fore.GREEN}DNS Response    :{Style.RESET_ALL}", packet[DNSRR].rdata)
            print("----------------------------------------")

        elif packet.haslayer(HTTP) and packet.haslayer(Raw):
            if b"GET" in packet[Raw].load or b"POST" in packet[Raw].load:
                print(f"\t{Fore.CYAN}HTTP Request Detected:{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
                print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
                print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
                print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
                print(f"{Fore.GREEN}IP Version       :{Style.RESET_ALL}", packet[IP].version)
                print(f"{Fore.GREEN}TTL              :{Style.RESET_ALL}", packet[IP].ttl)
                print(f"{Fore.GREEN}Packet Size      :{Style.RESET_ALL}", len(packet), "bytes")
                print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                print(f"{Fore.GREEN}HTTP Load        :{Style.RESET_ALL}", packet[Raw].load.decode(errors='replace'))
                print("----------------------------------------")
        # HTTP Response paketlerini kontrol et
        elif packet.haslayer(HTTP) and packet.haslayer(Raw) and b"HTTP" in packet[Raw].load:
            print(f"\t{Fore.CYAN}HTTP Response Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP        :{Style.RESET_ALL}", packet[IP].src)
            print(f"{Fore.GREEN}Destination IP   :{Style.RESET_ALL}", packet[IP].dst)
            print(f"{Fore.GREEN}Source MAC       :{Style.RESET_ALL}", packet[Ether].src)
            print(f"{Fore.GREEN}Destination MAC  :{Style.RESET_ALL}", packet[Ether].dst)
            print(f"{Fore.GREEN}IP Version       :{Style.RESET_ALL}", packet[IP].version)
            print(f"{Fore.GREEN}TTL              :{Style.RESET_ALL}", packet[IP].ttl)
            print(f"{Fore.GREEN}Packet Size      :{Style.RESET_ALL}", len(packet), "bytes")
            print(f"{Fore.GREEN}Passing Time     :{Style.RESET_ALL}", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            print(f"{Fore.GREEN}HTTP Load        :{Style.RESET_ALL}", packet[Raw].load.decode(errors='replace'))
            print("----------------------------------------")
        displayed_count += 1


def main():
    parser = argparse.ArgumentParser(description='Packet Sniffer Tool')
    parser.add_argument('-f', '--file', required=True, help='Path to the .pcap file to analyze')
    parser.add_argument('-p', '--protocol', choices=['ARP', 'ICMP', 'TCP', 'UDP', 'DNS', 'DHCP', 'HTTP', 'SNMP', 'LLMNR', 'NetBIOS'], help='Filter by specific protocol')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to display')
    parser.add_argument('-w', '--write', help='Path to the .pcap file to write')

    args = parser.parse_args()
    pcap_file = args.file
    protocol_filter = args.protocol
    packet_count = args.count
    output = args.write

    packets = rdpcap(pcap_file)

    analyze_packets(packets, protocol_filter, packet_count)
    if output:
        if not ".pcap" in output:
            output = output + ".pcap"
        filtered_packets = packets[:packet_count] if packet_count is not None else packets
        wrpcap(output, filtered_packets)
        print(Fore.GREEN + f"Saved in {output}")
if __name__ == '__main__':
    main()
