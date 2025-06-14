import logging

from scapy.layers.dot11 import Dot11EltVendorSpecific
from scapy.packet import Packet

# Local files in the same directory
from parser_service import ParserService

from typing import List
from pydantic import BaseModel

LOG = logging.getLogger(__name__)
#
# # Time-buffered batch saving for database
# time_buffer = TimeBuffer(interval_seconds=1, on_flush=save_messages)
#
# # Time-buffered batch broadcasting to WebSocket
# time_buffer_ws = TimeBuffer(interval_seconds=0.1, on_flush=broadcast)
#

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


# def _save_db_models(db_models: List[BaseModel]) -> None:
#     """Saves parsed messages to the database with throttling."""
#     for model in db_models:
#         time_buffer.add(model)
#
#
# def _broadcast_location(db_models: List[BaseModel]) -> None:
#     """Sends location-related messages to the websocket."""
#     for model in db_models:
#         if isinstance(model, DjiMessage):
#             time_buffer_ws.add(MinimalDroneDto(
#                 sender_id=model.sender_id,
#                 position=Position(lat=model.dji_latitude, lng=model.dji_longitude)
#             ))
#         elif isinstance(model, LocationMessage):
#             time_buffer_ws.add(MinimalDroneDto(
#                 sender_id=model.sender_id,
#                 position=Position(lat=model.latitude, lng=model.longitude)
#             ))
