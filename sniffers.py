import time
import logging
import os
from threading import Thread, Event
from scapy.layers.dot11 import Dot11Elt,Dot11EltVendorSpecific
from scapy.sendrecv import AsyncSniffer
from scapy.config import conf
from scapy.packet import Packet
from typing import Callable

__all__ = ["SniffManager"]

from process_packet import process_packet

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


class SniffManager:
    """
    Managed all different kinds of sniffers.
    Can start/stop new/existing sniffers.
    """

    def __init__(self, on_packet_received: Callable[[Packet], None]) -> None:
        """
        Args:
            on_packet_received (Callable[[Packet], None]): Callback function to process received packets.
        """
        self.sniffers = {}
        self.file_sniffers = []
        self.on_packet_received = on_packet_received

    # def start(self, interface: str) -> bool:
    #     """
    #     Starts a new WiFiInterfaceSniffer on that interface
    #     First stops the sniffer if one for that interface already exists.
    #
    #     Args:
    #         interface (str): Device/interface to sniff on.
    #
    #     Returns:
    #         bool: True when the sniffing started successfully, False otherwise.
    #     """
    #     # remove existing sniffer for that interface
    #     self.stop(interface)
    #     LOG.info(f"Starting sniffer for interface {interface}...")
    #     sniffer = WiFiInterfaceSniffer(interface, self.on_packet_received)
    #     success = sniffer.start()
    #     if success:
    #         LOG.info(f"Sniffer for interface {interface} started")
    #         self.sniffers[interface] = sniffer
    #     else:
    #         LOG.warning(f"Failed to start sniffer for interface {interface}")
    #     return success
    #
    def stop(self, interface: str) -> None:
        """
        Stops the WiFiInterfaceSniffer for that interface IF it exists.

        Args:
            interface (str): The interface to stop the sniffing on.
        """
        if interface in self.sniffers:
            sniffer = self.sniffers[interface]
            sniffer.stop()
            del self.sniffers[interface]
    #
    # def set_sniffing_interfaces(self, interfaces: list[str]) -> None:
    #     """
    #     Sets the WiFiInterfaceSniffers up for the provided list of interfaces.
    #     Stops other interfaces and starts new ones if necessary.
    #     The outcome is that only the provided interfaces are sniffed on.
    #
    #     Args:
    #         interfaces (list[str]): List of interfaces we want to sniff on.
    #     """
    #     LOG.info(f"Setting sniffing interfaces to {interfaces}...")
    #     # add new ones
    #     for interface in interfaces:
    #         if interface not in self.sniffers:
    #             self.start(interface)
    #
    #     # remove old ones
    #     for interface in self.sniffers.copy():  # requires copy to avoid modification during iteration
    #         if interface not in interfaces:
    #             self.stop(interface)

    def parse_file(self, filename: str) -> None:
        """
        Starts a FileSniffer for file with filename. If lte is True a LteFileSniffer is started, otherwise a
        WiFiFileSniffer is started.

        Args:
            filename (str): Filename of the file to be parsed.
        """
        LOG.info("Creating Wi-Fi Sniffer...")
        sniffer = WiFiFileSniffer(filename, self.on_packet_received)
        self.file_sniffers.append(sniffer)
        sniffer.start()

    def shutdown(self) -> None:
        """
        Shuts down all sniffers.
        """
        # stop all WiFiInterfaceSniffers
        LOG.info("Stopping all sniffers...")
        for interface in self.sniffers.copy():
            self.stop(interface)

        # stop all WiFiFileSniffers
        for sniffer in self.file_sniffers:
            sniffer.stop()
        self.file_sniffers = []
        LOG.info("All sniffers were stopped successfully.")


if __name__ == "__main__":

    logging.basicConfig(
        level=logging.DEBUG,  # or logging.INFO to reduce noise
        format='%(asctime)s [%(levelname)s] %(message)s',
    )
    sniffer = SniffManager(on_packet_received=process_packet)
    sniffer.parse_file("test.pcap")
    # time.sleep(2)  # Wait for the sniffer to process packets
    # sniffer.shutdown()