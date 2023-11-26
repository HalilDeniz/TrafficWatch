from .packet_handlers import handle_arp, handle_icmp, handle_tcp, handle_udp, handle_dns, handle_dhcp, handle_http, \
    handle_snmp, handle_llmnr, handle_netbios

protocol_handlers = {
    'ARP': handle_arp,
    'ICMP': handle_icmp,
    'TCP': handle_tcp,
    'UDP': handle_udp,
    'DNS': handle_dns,
    'DHCP': handle_dhcp,
    'HTTP': handle_http,
    'SNMP': handle_snmp,
    'LLMNR': handle_llmnr,
    'NetBIOS': handle_netbios
}
