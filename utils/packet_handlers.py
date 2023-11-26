from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNSQR, DNSRR
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
from scapy.layers.snmp import SNMP
from scapy.packet import Raw

from utils.packet_utils import print_packet_details


def handle_arp(packet):
    """
    Processes and logs details of ARP packets.
    :param packet: The packet to be processed, expected to be an ARP packet.
    """
    if not packet.haslayer(ARP):
        return
    details = {
        "Operation": "Request" if packet[ARP].op == 1 else "Reply",
        "Source IP": packet[ARP].psrc,
        "Destination IP": packet[ARP].pdst,
        "Source MAC": packet[ARP].hwsrc,
        "Destination MAC": packet[ARP].hwdst
    }
    print_packet_details("ARP", details)


def handle_icmp(packet):
    """
    Processes and logs details of ICMP packets.
    :param packet: The packet to be processed, expected to be an ICMP packet.
    """
    if not packet.haslayer(ICMP):
        return
    details = {
        "Type": packet[ICMP].type,
        "Code": packet[ICMP].code
    }
    print_packet_details("ICMP", details)


def handle_tcp(packet):
    """
    Processes and logs details of TCP packets, including source and destination ports, and flags.
    :param packet: The packet to be processed, expected to be a TCP packet.
    """
    if not packet.haslayer(TCP):
        return
    details = {
        "Source Port": packet[TCP].sport,
        "Destination Port": packet[TCP].dport,
        "Flags": packet[TCP].flags
    }
    print_packet_details("TCP", details)


def handle_udp(packet):
    """
    Processes and logs details of UDP packets, including source and destination ports.
    :param packet: The packet to be processed, expected to be a UDP packet.
    """
    if not packet.haslayer(UDP):
        return
    details = {
        "Source Port": packet[UDP].sport,
        "Destination Port": packet[UDP].dport
    }
    print_packet_details("UDP", details)


def handle_dns(packet):
    """
    Processes and logs details of DNS packets. Differentiates between DNS queries and responses.
    :param packet: The packet to be processed, expected to be a DNS packet.
    """
    if packet.haslayer(DNSQR):
        details = {"Query Name": packet[DNSQR].qname.decode('utf-8')}
        print_packet_details("DNS Request", details)
    elif packet.haslayer(DNSRR):
        details = {"Response Name": packet[DNSRR].rrname.decode('utf-8')}
        print_packet_details("DNS Response", details)


def handle_dhcp(packet):
    """
    Processes and logs details of DHCP packets, including DHCP options.
    :param packet: The packet to be processed, expected to be a DHCP packet.
    """
    if not packet.haslayer(DHCP):
        return
    details = {option[0]: option[1] for option in packet[DHCP].options if isinstance(option, tuple)}
    print_packet_details("DHCP", details)


def handle_http(packet):
    """
    Processes and logs details of HTTP packets, particularly focusing on the payload.
    :param packet: The packet to be processed, expected to contain HTTP data.
    """
    if packet.haslayer(Raw):
        details = {"Payload": packet[Raw].load.decode(errors='replace')}
        print_packet_details("HTTP", details)


def handle_snmp(packet):
    """
    Processes and logs details of SNMP packets, including version and community string.
    :param packet: The packet to be processed, expected to be an SNMP packet.
    """
    if not packet.haslayer(SNMP):
        return
    details = {
        "Version": packet[SNMP].version,
        "Community": packet[SNMP].community.decode('utf-8')
    }
    print_packet_details("SNMP", details)


def handle_llmnr(packet):
    """
    Processes and logs details of LLMNR packets, differentiating between queries and responses.
    :param packet: The packet to be processed, expected to be an LLMNR packet.
    """
    if packet.haslayer(LLMNRQuery):
        details = {"Query Name": packet[LLMNRQuery].qname.decode('utf-8')}
        print_packet_details("LLMNR Query", details)
    elif packet.haslayer(LLMNRResponse):
        details = {"Response Name": packet[LLMNRResponse].rrname.decode('utf-8')}
        print_packet_details("LLMNR Response", details)


def handle_netbios(packet):
    """
    Processes and logs details of NetBIOS packets, differentiating between query requests and responses.
    :param packet: The packet to be processed, expected to be a NetBIOS packet.
    """
    if packet.haslayer(NBNSQueryRequest):
        details = {"NetBIOS Name": packet[NBNSQueryRequest].QUESTION_NAME}
        print_packet_details("NetBIOS Query Request", details)
    elif packet.haslayer(NBNSQueryResponse):
        details = {"NetBIOS Name": packet[NBNSQueryResponse].RR_NAME}
        print_packet_details("NetBIOS Query Response", details)
