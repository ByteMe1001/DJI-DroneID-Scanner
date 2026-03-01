import logging

from scapy.layers.dot11 import Dot11EltVendorSpecific
from scapy.packet import Packet

from extensions import socketio        # No circular import

# Local files in the same directory
from parser_manager import ParserService

from typing import List
from pydantic import BaseModel


LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)

def process_packet(packet: Packet) -> None:
    """
    Filters Wi-Fi packets and processes vendor-specific elements that match known OUIs.

    Args:
        packet (Packet): A Wi-Fi 802.11 frame.
    """
    vendor_spec: Dot11EltVendorSpecific = _get_vendor_specific(packet)

    while vendor_spec:
        oui_bytes = vendor_spec.oui

        if isinstance(oui_bytes, int):
            oui_bytes = oui_bytes.to_bytes(3, 'big')

        layer_oui = ":".join(f"{b:02X}" for b in oui_bytes)

        if ParserService.is_supported_protocol(layer_oui):
            parsed_message = ParserService.dispatch_vendor_parser(vendor_spec.info)
            if parsed_message:
                LOG.debug(f"Parsed message: {parsed_message}")
                # Push to websocket
                try:
                    socketio.emit('update_drone', parsed_message.to_payload())
                except Exception as e:
                    LOG.warning(f"WebSocket emit failed: {e}")
            break  # Only handle one vendor element per packet
        else:
            # incase there are multiple vendor-specific elements in the same packet
            vendor_spec = vendor_spec.payload.getlayer(Dot11EltVendorSpecific)


def _get_vendor_specific(packet: Packet) -> Dot11EltVendorSpecific:
    """
    Extracts the first Dot11EltVendorSpecific layer from the packet.

    Args:
        packet (Packet): A Wi-Fi packet.

    Returns:
        Dot11EltVendorSpecific | None: Vendor-specific IE if present.
    """
    return packet.getlayer(Dot11EltVendorSpecific) if packet.haslayer(Dot11EltVendorSpecific) else None