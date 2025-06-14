import struct
from typing import Optional
from parser import Parser
from droneID_model import DroneIDPacketModel

DRONEID_DRONE_TYPES = {
    "1": "Inspire 1",
    "2": "Phantom 3 Series",
    "3": "Phantom 3 Series",
    "4": "Phantom 3 Std",
    "5": "M100",
    "6": "ACEONE",
    "7": "WKM",
    "8": "NAZA",
    "9": "A2",
    "10": "A3",
    "11": "Phantom 4",
    "12": "MG1",
    "14": "M600",
    "15": "Phantom 3 4k",
    "16": "Mavic Pro",
    "17": "Inspire 2",
    "18": "Phantom 4 Pro",
    "20": "N2",
    "21": "Spark",
    "23": "M600 Pro",
    "24": "Mavic Air",
    "25": "M200",
    "26": "Phantom 4 Series",
    "27": "Phantom 4 Adv",
    "28": "M210",
    "30": "M210RTK",
    "31": "A3_AG",
    "32": "MG2",
    "34": "MG1A",
    "35": "Phantom 4 RTK",
    "36": "Phantom 4 Pro V2.0",
    "38": "MG1P",
    "40": "MG1P-RTK",
    "41": "Mavic 2",
    "44": "M200 V2 Series",
    "51": "Mavic 2 Enterprise",
    "53": "Mavic Mini",
    "58": "Mavic Air 2",
    "59": "P4M",
    "60": "M300 RTK",
    "61": "DJI FPV",
    "63": "Mini 2",
    "64": "AGRAS T10",
    "65": "AGRAS T30",
    "66": "Air 2S",
    "67": "M30",
    "68": "DJI Mavic 3",
    "69": "Mavic 2 Enterprise Advanced",
    "70": "Mini SE"
}

# Contains the OUI 26:37:12
class DroneIDPacketParser(Parser):
    oui = ["26:37:12", "60:60:1F", "48:1C:B9", "34:D2:62"]
    @staticmethod
    def _le_uint32(b):
        return struct.unpack("<I", b)[0]
    @staticmethod
    def _le_int16(b):
        return struct.unpack("<h", b)[0]
    @staticmethod
    def _le_uint64(b):
        return struct.unpack("<Q", b)[0]
    @staticmethod
    def _to_coord(val):
        return round(val / 174533.0, 6)
    @staticmethod
    def _to_speed(val):
        return round(val / 100.0, 2)
    @staticmethod
    def _to_alt(val):
        return round(val / 3.281, 2)
    @staticmethod
    def _to_yaw(val):
        return round(val / 100.0, 2)
    @staticmethod
    def _decode_serial(b):
        return b.decode('ascii', errors='replace').rstrip('\x00')

    @staticmethod
    def parse_header(data: bytes) -> tuple[int, int] | None:
        if len(data) < 5:
            return None
        return data[3], data[4]  # packet_type, version

    @staticmethod
    def parse_version_flight(data: bytes) -> DroneIDPacketModel:
        serial = DroneIDPacketParser._decode_serial(data[9:25])
        drone_lon = DroneIDPacketParser._to_coord(DroneIDPacketParser._le_uint32(data[25:29]))
        drone_lat = DroneIDPacketParser._to_coord(DroneIDPacketParser._le_uint32(data[29:33]))
        alt = DroneIDPacketParser._to_alt(DroneIDPacketParser._le_int16(data[33:35]))
        height = DroneIDPacketParser._to_alt(DroneIDPacketParser._le_int16(data[35:37]))
        x = DroneIDPacketParser._to_speed(DroneIDPacketParser._le_int16(data[37:39]))
        y = DroneIDPacketParser._to_speed(DroneIDPacketParser._le_int16(data[39:41]))
        z = DroneIDPacketParser._to_speed(DroneIDPacketParser._le_int16(data[41:43]))
        yaw = DroneIDPacketParser._to_yaw(DroneIDPacketParser._le_int16(data[43:45]))
        gps_raw = DroneIDPacketParser._le_uint64(data[45:53]) / 1000.0
        pilot_lat = DroneIDPacketParser._to_coord(DroneIDPacketParser._le_uint32(data[53:57]))
        pilot_lon = DroneIDPacketParser._to_coord(DroneIDPacketParser._le_uint32(data[57:61]))
        home_lon = DroneIDPacketParser._to_coord(DroneIDPacketParser._le_uint32(data[61:65]))
        home_lat = DroneIDPacketParser._to_coord(DroneIDPacketParser._le_uint32(data[65:69]))
        drone_type_id = data[69]
        drone_type = DRONEID_DRONE_TYPES.get(str(drone_type_id), f"Unknown (ID: {drone_type_id})")

        return DroneIDPacketModel(
            serial_number=serial,
            drone_lat=drone_lat,
            drone_lon=drone_lon,
            altitude_m=alt,
            height_m=height,
            x_speed_mps=x,
            y_speed_mps=y,
            z_speed_mps=z,
            yaw_deg=yaw,
            gps_time=gps_raw,
            pilot_lat=pilot_lat,
            pilot_lon=pilot_lon,
            home_lat=home_lat,
            home_lon=home_lon,
            drone_type=drone_type
        )

    @staticmethod
    def parse_version_license(data: bytes) -> None:
        # Placeholder for license parser (0x11)
        return None

    @staticmethod
    def parse(hex_str: str) -> DroneIDPacketModel | None:
        try:
            data = bytes.fromhex(hex_str.strip())
            header = DroneIDPacketParser.parse_header(data)
            if header is None:
                return None

            ptype, version = header

            if ptype == 0x10:
                return DroneIDPacketParser.parse_version_flight(data)
            elif ptype == 0x11:
                return DroneIDPacketParser.parse_version_license(data)
            else:
                return None
        except Exception as e:
            print(f"[!] Failed to parse DroneID packet: {e}")
            return None

    @staticmethod
    def from_wifi(packet: bytes, oui: str) -> Optional[DroneIDPacketModel]:
        """
        Converts the packet bytes to a hex string and parses it using the standard parser.

        Args:
            packet (bytes): The raw vendor-specific Wi-Fi payload.
            oui (str): The expected OUI in the form "26:37:12".

        Returns:
            Optional[DroneIDPacketModel]: Parsed model or None if the OUI doesn't match or parsing fails.
        """
        try:
            # Strip first 3 OUI bytes
            stripped = packet[3:]

            # Convert to hex string
            hex_str = stripped.hex()
            return DroneIDPacketParser.parse(hex_str)
        except Exception as e:
            print(f"[!] from_wifi error: {e}")
            return None

if __name__ == "__main__":
    with open("hex.txt", "r") as file:
        hex_str = file.read().strip().replace(" ", "").replace("\n", "")
    # Parse the DroneID packet from the hex string
    packet = DroneIDPacketParser.parse(hex_str)
    if packet:
        print(packet.model_dump_json(indent=2))