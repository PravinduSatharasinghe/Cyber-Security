import logging
import queue
from scapy.all import IP, TCP
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert import AlertSystem
from packet_capture import PacketCapture


class IntrusionDetectionSystem:
    """
    A lightweight Intrusion Detection System using Scapy for packet capture,
    analysis, detection, and alerting.
    """

    def __init__(self, interface: str = "Ethernet") -> None:
        self.interface = interface
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)

    def start(self) -> None:
        """
        Starts the IDS by initializing packet capture and processing loop.
        """
        self.logger.info(f"Starting Intrusion Detection System on interface: {self.interface}")
        self.packet_capture.start_capture(self.interface)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                except queue.Empty:
                    continue

                features = self.traffic_analyzer.analyze_packet(packet)
                if not features:
                    continue

                threats = self.detection_engine.detect_threats(features)
                for threat in threats:
                    packet_info = self._extract_packet_info(packet)
                    self.alert_system.generate_alert(threat, packet_info)

        except KeyboardInterrupt:
            self.logger.info("KeyboardInterrupt detected. Shutting down IDS...")
        except Exception as e:
            self.logger.exception(f"Unexpected error occurred: {e}")
        finally:
            self.packet_capture.stop()
            self.logger.info("IDS stopped gracefully.")

    def _extract_packet_info(self, packet) -> dict:
        """
        Extract relevant packet information for alerting.
        """
        try:
            return {
                'source_ip': packet[IP].src,
                'destination_ip': packet[IP].dst,
                'source_port': packet[TCP].sport,
                'destination_port': packet[TCP].dport
            }
        except IndexError:
            self.logger.warning("Malformed packet encountered, skipping.")
            return {}


if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()
