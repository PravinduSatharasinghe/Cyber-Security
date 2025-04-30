from scapy.all import IP, TCP
from collections import defaultdict
import threading
import time
import logging

class TrafficAnalyzer:
    def __init__(self):
        """
        Initializes the TrafficAnalyzer instance with default settings.
        """
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

        # Lock for thread-safe access to shared data structures
        self.lock = threading.Lock()

        # Set up basic logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def analyze_packet(self, packet):
        """
        Analyzes the given packet to update flow statistics.

        :param packet: The packet to analyze.
        :return: A dictionary containing the extracted features, or None if packet is not relevant.
        """
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Lock to ensure thread-safe access to flow_stats
            with self.lock:
                stats = self.flow_stats[flow_key]
                stats['packet_count'] += 1
                stats['byte_count'] += len(packet)
                current_time = packet.time

                # Set the start time if it's the first packet in the flow
                if not stats['start_time']:
                    stats['start_time'] = current_time
                stats['last_time'] = current_time

                # Return the extracted features for this packet
                return self.extract_features(packet, stats)

        # If packet is not TCP, ignore it
        return None

    def extract_features(self, packet, stats):
        """
        Extracts relevant features from the packet and flow statistics.

        :param packet: The packet to extract features from.
        :param stats: The flow statistics for this flow.
        :return: A dictionary of extracted features.
        """
        # Avoid division by zero by checking if the flow duration is positive
        flow_duration = stats['last_time'] - stats['start_time']
        if flow_duration <= 0:
            flow_duration = 1  # Set a default value to prevent division by zero

        features = {
            'packet_size': len(packet),
            'flow_duration': flow_duration,
            'packet_rate': stats['packet_count'] / flow_duration,
            'byte_rate': stats['byte_count'] / flow_duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }

        self.logger.debug(f"Extracted features: {features}")
        return features

    def get_flow_stats(self, flow_key):
        """
        Returns the flow statistics for a given flow key.

        :param flow_key: A tuple of (src_ip, dst_ip, src_port, dst_port) representing the flow.
        :return: A dictionary containing the flow statistics.
        """
        with self.lock:
            return self.flow_stats.get(flow_key, None)
