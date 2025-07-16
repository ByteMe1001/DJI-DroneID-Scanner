from typing import Optional, Type, List
from droneID_parser import DroneIDPacketParser
from parser import Parser
from droneID_model import MessageModel

class ParserService:
    # Register additional parsers here
    PARSER_REGISTRY: List[Type[Parser]] = [
        DroneIDPacketParser
    ]

    @staticmethod
    def dispatch_vendor_parser(packet: bytes) -> Optional[MessageModel]:
        """
        Dispatches a vendor-specific packet to the appropriate parser based on OUI.

        Args:
            packet (bytes): The vendor-specific payload.

        Returns:
            Optional[MessageModel]: Parsed object from a matching parser, or None.
        """
        try:
            for parser_cls in ParserService.PARSER_REGISTRY:
                oui_bytes, _, _ = parser_cls.extract_header(packet)
                oui_str = Parser.bytes_to_hex_str(oui_bytes)

                if oui_str.lower() in [o.lower() for o in parser_cls.oui]:
                    return parser_cls.from_wifi(packet, oui_str)

        except Exception as e:
            print(f"[!] Dispatcher error: {e}")

        return None

    @staticmethod
    def is_supported_protocol(oui: str) -> bool:
        """
        Check if a given OUI is supported by any of the parsers.

        Args:
            oui: The Organizationally Unique Identifier to check

        Returns:
            bool: True if the OUI is supported, False otherwise
        """
        return any(oui.lower() in [o.lower() for o in parser_cls.oui] for parser_cls in ParserService.PARSER_REGISTRY)


# Singleton instance
parser = ParserService()