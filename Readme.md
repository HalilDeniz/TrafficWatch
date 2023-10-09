# TrafficWatch

TrafficWatch, a packet sniffer tool, allows you to monitor and analyze network traffic from PCAP files or live network interfaces. It provides insights into various network protocols and can help with network troubleshooting, security analysis, and more.

<img src="core/trafficwatch.png">


## Features

- Packet capture from PCAP files or live network interfaces.
- Protocol-specific packet analysis for ARP, ICMP, TCP, UDP, DNS, DHCP, HTTP, SNMP, LLMNR, and NetBIOS.
- Packet filtering based on protocol, source IP, destination IP, source port, destination port, and more.
- Summary statistics on captured packets.
- Interactive mode for in-depth packet inspection.
- Timestamps for each captured packet.
- User-friendly colored output for improved readability.


## Requirements

- Python 3.x
- scapy
- argparse
- pyshark
- colorama

## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/HalilDeniz/TrafficWatch.git
   ```

2. Navigate to the project directory:

   ```shell
   cd TrafficWatch
   ```

3. Install the required dependencies:

   ```shell
   pip install -r requirements.txt
   ```

### Usage

   ```
 python3 trafficwatch.py --help
usage: trafficwatch.py [-h] -f FILE [-p {ARP,ICMP,TCP,UDP,DNS,DHCP,HTTP,SNMP,LLMNR,NetBIOS}] [-c COUNT]

Packet Sniffer Tool

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to the .pcap file to analyze
  -p {ARP,ICMP,TCP,UDP,DNS,DHCP,HTTP,SNMP,LLMNR,NetBIOS}, --protocol {ARP,ICMP,TCP,UDP,DNS,DHCP,HTTP,SNMP,LLMNR,NetBIOS}
                        Filter by specific protocol
  -c COUNT, --count COUNT
                        Number of packets to display

   ```


To analyze packets from a PCAP file, use the following command:

```bash
python trafficwatch.py -f path/to/your.pcap
```

To specify a protocol filter (e.g., HTTP) and limit the number of displayed packets (e.g., 10), use:

```bash
python trafficwatch.py -f path/to/your.pcap -p HTTP -c 10
```

### Options

- `-f` or `--file`: Path to the PCAP file for analysis.
- `-p` or `--protocol`: Filter packets by protocol (ARP, ICMP, TCP, UDP, DNS, DHCP, HTTP, SNMP, LLMNR, NetBIOS).
- `-c` or `--count`: Limit the number of displayed packets.

## Contributing

Contributions are welcome! If you want to contribute to TrafficWatch, please follow our [contribution guidelines](CONTRIBUTING.md).

## Contact
If you have any questions, comments, or suggestions about Dosinator, please feel free to contact me:

- LinkedIn: [Halil Ibrahim Deniz](https://www.linkedin.com/in/halil-ibrahim-deniz/)
- TryHackMe: [Halilovic](https://tryhackme.com/p/halilovic)
- Instagram: [deniz.halil333](https://www.instagram.com/deniz.halil333/)
- YouTube: [Halil Deniz](https://www.youtube.com/c/HalilDeniz)
- Email: halildeniz313@gmail.com

## License

This project is licensed under the [MIT License](LICENSE).

## 💰 You can help me by Donating
  Thank you for considering supporting me! Your support enables me to dedicate more time and effort to creating useful tools like DNSWatch and developing new projects. By contributing, you're not only helping me improve existing tools but also inspiring new ideas and innovations. Your support plays a vital role in the growth of this project and future endeavors. Together, let's continue building and learning. Thank you!"<br>
  [![BuyMeACoffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/halildeniz) 
  [![Patreon](https://img.shields.io/badge/Patreon-F96854?style=for-the-badge&logo=patreon&logoColor=white)](https://patreon.com/denizhalil) 

  
