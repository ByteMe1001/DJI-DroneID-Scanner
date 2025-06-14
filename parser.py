import struct
from typing import Optional, List
from abc import ABC, abstractmethod

class MessageModel(ABC):
    """Represents a parsed Remote ID message from any supported protocol."""
    provider: str

    def __init__(self, provider: str):
        self.provider = provider

    @abstractmethod
    def __str__(self):
        pass


class Parser:
    """
    Root Parser for a vendor specific packet.
    """
    header_size = 8
    oui: List[str] = []  # List of supported OUIs

    @staticmethod
    def extract_header(packet: bytes) -> tuple:
        """
        Extracts the OUI, vendor-specific bytes, and version from the first 8 bytes of a vendor-specific element.

        Args:
            packet (bytes): Wi-Fi packet payload.

        Returns:
            tuple: (oui_bytes, vendor_spec_bytes, version)
        """
        header_format = '<3s4sB'
        try:
            header = struct.unpack(header_format, packet[:Parser.header_size])
            if not header:
                raise ValueError("Empty header detected after successfully unpacking")
            return header
        except struct.error as e:
            raise ValueError(f"Unable to unpack header packet: {e}")

    @staticmethod
    def dec2hex(oui_dec: int) -> str:
        """
        Converts a decimal OUI to colon-separated hex format (e.g., AC:DE:48).

        Args:
            oui_dec (int): Decimal value of OUI.

        Returns:
            str: Formatted OUI.
        """
        max_ = 16777215
        min_ = 0
        if oui_dec < min_ or oui_dec > max_:
            return "00:00:00"
        oui_raw = hex(oui_dec)[2:].zfill(6)
        return f"{oui_raw[0:2]}:{oui_raw[2:4]}:{oui_raw[4:]}".upper()

    @staticmethod
    def bytes_to_hex_str(oui_bytes: bytes) -> str:
        """
        Converts a 3-byte OUI into colon-separated hex string.

        Args:
            oui_bytes (bytes): 3-byte OUI.

        Returns:
            str: OUI in hex format.
        """
        return ':'.join([f"{b:02X}" for b in oui_bytes])

    @staticmethod
    def from_wifi(packet: bytes, oui: str) -> Optional[MessageModel]:
        """
        Abstract method to parse vendor-specific element. Should be implemented by vendor-specific parsers.

        Args:
            packet (bytes): Wi-Fi packet payload.
            oui (str): Extracted OUI string.

        Returns:
            Optional[MessageModel]: Parsed result if applicable.
        """
        raise NotImplementedError("Subclasses must implement parse method")

