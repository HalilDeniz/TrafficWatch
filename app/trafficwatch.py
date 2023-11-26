from scapy.all import *

from core.trafficWatchfiglet import trafficwatchfiglet
from utils.arg_parser import parse_arguments
from utils.custom_logger import setup_logging
from utils.protocol_map import protocol_handlers

setup_logging()


def analyze_packets(packets, protocol_filter=None, packet_count=None):
    """
    Analyzes a set of packets based on the specified protocol filter and packet count.
    For each packet, if a protocol filter is specified, the corresponding protocol handler is invoked.
    If no filter is specified, the packet can be processed with a default handler or skipped.

    :param packets: The collection of packets to be analyzed.
    :param protocol_filter: Optional; the specific protocol to filter packets by.
    :param packet_count: Optional; the number of packets to analyze.
    """
    logging.info(f"{trafficwatchfiglet()}")
    logging.info("----------------------------------------")

    displayed_count = 0

    for packet in packets:
        if packet_count is not None and displayed_count >= packet_count:
            break

        # If a protocol filter is specified, use the corresponding handler
        if protocol_filter:
            if handler := protocol_handlers.get(protocol_filter):
                handler(packet)
                displayed_count += 1
                continue

        # If no filter is specified, or if the protocol is not supported,
        # you can choose to either print basic details of every packet or skip it.
        # For example, you might want to implement a function like print_basic_packet_info(packet)
        # print_basic_packet_info(packet) # A hypothetical function to display basic packet info
        displayed_count += 1


def main():
    args = parse_arguments()

    pcap_file = args.file

    if not os.path.exists(pcap_file):
        logging.error(f"The file {pcap_file} does not exist.")
        exit(1)

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        logging.error(f"Error reading {pcap_file}: {e}")
        exit(1)

    analyze_packets(packets, args.protocol, args.count)

    if output := args.write:
        if ".pcap" not in output:
            output = f"{output}.pcap"

        filtered_packets = packets[:args.count] if args.count is not None else packets
        try:
            wrpcap(output, filtered_packets)
            logging.info(f"Saved in {output}")
        except Exception as e:
            logging.error(f"Error writing to {output}: {e}")
            exit(1)


if __name__ == '__main__':
    main()
