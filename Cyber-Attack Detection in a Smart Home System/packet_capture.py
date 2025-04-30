from scapy.all import sniff, IP, TCP
import threading
import queue
import logging

class PacketCapture:
    def __init__(self, interface="eth0"):
        """
        Initializes the PacketCapture instance.

        :param interface: Network interface to capture packets from (default is eth0).
        """
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.interface = interface
        self.capture_thread = None

        # Set up basic logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def packet_callback(self, packet):
        """
        Callback function to process incoming packets.

        :param packet: Scapy packet to process.
        """
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
            self.logger.debug(f"Packet captured: {packet.summary()}")

    def start_capture(self):
        """
        Starts the packet capture in a separate thread.
        """
        if self.capture_thread and self.capture_thread.is_alive():
            self.logger.warning("Capture thread is already running.")
            return

        def capture_thread():
            """Function to capture packets using Scapy."""
            try:
                sniff(iface=self.interface,
                      prn=self.packet_callback,
                      store=0,
                      stop_filter=lambda _: self.stop_capture.is_set())
            except Exception as e:
                self.logger.error(f"Error during packet capture: {e}")

        # Start the capture thread
        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()
        self.logger.info(f"Packet capture started on interface: {self.interface}")

    def stop(self):
        """
        Stops the packet capture thread.
        """
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.logger.warning("No active capture thread to stop.")
            return

        self.stop_capture.set()
        self.capture_thread.join()
        self.logger.info("Packet capture stopped.")

    def get_packet(self, timeout=1):
        """
        Retrieve a packet from the queue.

        :param timeout: Timeout for waiting for a packet (in seconds).
        :return: The packet from the queue or None if timeout occurs.
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
