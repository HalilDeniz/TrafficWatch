import logging


def print_packet_details(packet_type, details):
    """
    Logs packet details using a predefined logging format.

    :param packet_type: A string representing the type of the packet (e.g., 'ARP', 'TCP').
    :param details: A dictionary containing key-value pairs of packet details.
    """
    logging.info(f"{packet_type} Packet Detected")
    for key, value in details.items():
        logging.info(f"{key:18}: {value}")
