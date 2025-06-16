import time
import logging
import os
import threading
import signal
import subprocess

from scapy.layers.dot11 import Dot11Elt, Dot11EltVendorSpecific, Dot11, RadioTap
from scapy.sendrecv import AsyncSniffer
from typing import Callable, Optional
from controller import SSHController
from process_packet import process_packet
from scapy.all import RawPcapReader, Packet

from scapy.all import PcapWriter

__all__ = ["SniffManager"]

LOG = logging.getLogger(__name__)


# Helper function
def is_beacon_management_frame(pkt: Packet) -> bool:
    """
    Filters only 802.11 management frames with subtype 8 (Beacon).

    Args:
        pkt (Packet): The scapy packet to inspect.

    Returns:
        bool: True if it's a beacon management frame, False otherwise.
    """
    return pkt.haslayer("Dot11") and pkt.type == 0 and pkt.subtype == 8


class WiFiFileSniffer:
    """
    Parses a pcap file and forwards the parsed packets to the handler.
    """

    def __init__(self, filename: str, on_packet_received: Callable[[Packet], None]) -> None:
        """
        Args:
            filename (str): The filename of the file to be read and parsed.
            on_packet_received (Callable[[Packet], None]): Callback function to process received packets.
        """
        self.filename = filename
        self.on_packet_received = on_packet_received

        def safe_callback(pkt):
            try:
                if is_beacon_management_frame(pkt):
                    self.on_packet_received(pkt)
            except Exception as e:
                LOG.exception(f"[!] Packet processing error: {e}")

        self.sniffer = AsyncSniffer(
            offline=filename,
            prn=safe_callback,
            store=False,
        )


    def start(self) -> bool:
        """
        Reads the file and parses its content.

        Returns:
            bool: Always succeeds and returns True.
        """
        logging.info(f"Starting to parse file {self.filename}")
        self.sniffer.start()
        self.sniffer.join()
        return True

    def stop(self) -> None:
        """
        Stops all sniffing efforts.
        """
        logging.info(f"Stop parsing file {self.filename}")
        self.sniffer.stop()


class WiFiInterfaceSniffer:
    """
    Parses a remote tcpdump stream from a BufferedReader and forwards parsed packets to a handler.
    """

    def __init__(self, host, username, password=None, key_filename=None, on_packet_received: Callable[[Packet], None] = None) -> None:
        """
        Args:
            host (str): IP or hostname of the remote device.
            username (str): SSH username.
            password (str): SSH password (optional if using key).
            key_filename (str): Path to private key file.
            on_packet_received (Callable[[Packet], None]): Callback for handling packets.
        """
        self.controller = SSHController(host, username, password, key_filename)
        self.on_packet_received = on_packet_received
        self.proc: Optional[subprocess.Popen] = None
        self.running = False
        self.reader_thread: Optional[threading.Thread] = None

    def start(self):
        """
        Sets up monitor mode, starts tcpdump, and begins packet processing in a thread.
        """
        LOG.info("Starting sniffer...")
        self.controller.setup_monitor_mode()

        self.proc = self.controller.start_tcpdump_stream()
        self.running = True
        self.reader_thread = threading.Thread(target=self._read_packets, daemon=True)
        self.reader_thread.start()

    def _read_packets(self):
        """
        Internal packet reader loop that decodes packets and calls the callback only for beacon management frames.
        """
        LOG.info("Starting packet processing loop...")

        writer = PcapWriter("test_output.pcap", append=True, sync=True)
        try:
            for pkt_data, _ in RawPcapReader(self.proc):
                if not self.running:
                    break

                try:
                    pkt = RadioTap(pkt_data)    # Use RadioTap instead of Packet
                    pkt_len = len(pkt_data)

                    writer.write(pkt)           # Write for testing

                    # Filter only beacon management frames
                    if is_beacon_management_frame(pkt):
                        self.on_packet_received(pkt)

                except Exception as e:
                    LOG.warning(f"[!] Failed to decode packet: {e}")
        except Exception as e:
            LOG.error(f"[!] Error while reading packet stream: {e}")
        finally:
            writer.close()

        LOG.info("Packet processing loop exited.")

    def terminate_tcpdump(self):
        """
        Stops the packet reader and terminates tcpdump over SSH (Paramiko).
        """
        LOG.info("Stopping sniffer...")
        self.running = False

        # Step 1: Stop TCPDump on controller
        self.controller.stop_tcpdump_stream()

        # Step 2: Join reader thread
        if self.reader_thread:
            self.reader_thread.join(timeout=5)
            if self.reader_thread.is_alive():
                LOG.warning("[!] Reader thread did not exit cleanly.")
            else:
                LOG.info("Reader thread exited.")
            self.reader_thread = None

    def pause(self):
        """
        Pauses tcpdump by sending SIGSTOP.
        """
        if self.proc:
            self.proc.send_signal(signal.SIGSTOP)
            LOG.info("Sniffer paused.")

    def resume(self):
        """
        Resumes tcpdump by sending SIGCONT.
        """
        if self.proc:
            self.proc.send_signal(signal.SIGCONT)
            LOG.info("Sniffer resumed.")

    def stop(self):
        """
        Fully shuts down the sniffer and remote monitor interface.
        """
        self.terminate_tcpdump()
        self.controller.shutdown()
        LOG.info("Sniffer closed.")


class SniffManager:
    """
    Manage all different kinds of sniffers.
    Can start/stop new/existing sniffers.
    """

    def __init__(self, on_packet_received: Callable[[Packet], None]) -> None:
        """
        Args:
            on_packet_received (Callable[[Packet], None]): Callback function to process received packets.
        """
        self.sniffers = []
        self.file_sniffers = []
        self.on_packet_received = on_packet_received

    def start_sniffing(self, host: str, username: str, password: str = None, key_filename: str = None) -> None:
        """
        Starts a WiFiInterfaceSniffer that connects to a remote device via SSH and processes live packets.

        Args:
            host (str): IP or hostname of the remote device.
            username (str): SSH username.
            password (str, optional): SSH password.
            key_filename (str, optional): SSH private key path.
        """
        LOG.info("Creating Wi-Fi Interface Sniffer...")
        sniffer = WiFiInterfaceSniffer(
            host=host,
            username=username,
            password=password,
            key_filename=key_filename,
            on_packet_received=self.on_packet_received
        )
        self.sniffers.append(sniffer)
        sniffer.start()

    def parse_file(self, filename: str) -> None:
        """
        Starts a FileSniffer for file with filename. If lte is True a LteFileSniffer is started, otherwise a
        WiFiFileSniffer is started.

        Args:
            filename (str): Filename of the file to be parsed.
        """
        LOG.info("Creating Wi-Fi File Sniffer...")
        sniffer = WiFiFileSniffer(filename, self.on_packet_received)
        self.file_sniffers.append(sniffer)
        sniffer.start()

    def shutdown(self) -> None:
        """
        Shuts down all sniffers.
        """
        # Stop all WiFiInterfaceSniffers directly
        for sniffer in self.sniffers.copy():
            try:
                sniffer.stop()
            except Exception as e:
                LOG.warning(f"[!] Failed to stop sniffer: {e}")
        self.sniffers.clear()

        # Stop all WiFiFileSniffers
        for sniffer in self.file_sniffers:
            try:
                sniffer.stop()
            except Exception as e:
                LOG.warning(f"[!] Failed to stop file sniffer: {e}")
        self.file_sniffers.clear()

        LOG.info("All sniffers were stopped successfully.")

    @staticmethod
    def test():
        sniffer = SniffManager(on_packet_received=process_packet)
        sniffer.parse_file("test.pcap")          # CHANGE THIS FILE FOR TESTING


if __name__ == "__main__":

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )
    sniffer = SniffManager(on_packet_received=process_packet)
    sniffer.parse_file("test.pcap")
