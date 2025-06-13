import struct
from datetime import datetime, UTC
from zoneinfo import ZoneInfo

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
class DroneIDPacket:
    def __init__(self, hex_str):
        self.data = bytes.fromhex(hex_str)
        self.packet_len = self.data[0]
        self.unknown_val = self.data[1]
        self.packet_type = self.data[3]
        self.version_desc = "N/A"

    def print_header(self):
        print("Packet Header:")
        print(f"  Packet Length      : {self.packet_len:02x} in hex → {self.packet_len}")
        print(f"  Unknown Field      : {self.unknown_val:02x} → {self.unknown_val}")
        print(f"  DroneID Packet Type: {self.packet_type:02x} → {self.__class__.__name__}")

    # def print_coord(self, label, raw_bytes, raw_val, value):
    #     print(f"\n{label}:")
    #     print(f"  Raw bytes      : {' '.join(f'{b:02x}' for b in raw_bytes)}")
    #     print(f"  Little-endian  : 0x{raw_val:08x} = {raw_val}")
    #     print(f"  Converted value: {value:.6f}")

    # This fields are all unsigned integer in 32bits -> 4 bytes
    def le_uint32(self, b):
        return struct.unpack("<I", b)[0]

    # This fields are all unsigned integer in 16bits -> 2 bytes
    def le_int16(self, b):
        return struct.unpack("<h", b)[0]


class DroneIDPacketFlight(DroneIDPacket):
    def __init__(self, hex_str):
        super().__init__(hex_str)
        self.version = self.data[4]
        self.version_desc = {
            0x01: "V1",
            0x02: "V2"
        }.get(self.version, f"Unknown (0x{self.version:02x})")
        self.parse()

    def parse(self):

        self.sequence_number = self.data[5]
        self.state_info = self.data[6]
        self.serial_number = self.data[9:25].decode("ascii", errors="replace").rstrip('\x00')   # Strip any trailing null bytes

        # Drone location (after serial)
        self.drone_lon_bytes = self.data[25:29]
        self.drone_lat_bytes = self.data[29:33]
        self.drone_lon_raw = self.le_uint32(self.drone_lon_bytes)
        self.drone_lat_raw = self.le_uint32(self.drone_lat_bytes)
        self.drone_lon = self.drone_lon_raw / 174533.0
        self.drone_lat = self.drone_lat_raw / 174533.0

        # Altitude and Height (2 bytes each)
        self.altitude_bytes = self.data[33:35]
        self.height_bytes = self.data[35:37]
        self.altitude_raw = self.le_int16(self.altitude_bytes)
        self.height_raw = self.le_int16(self.height_bytes)
        self.altitude = round(self.altitude_raw / 3.281, 2)  # ft → m
        self.height = round(self.height_raw / 3.281, 2)  # ft → m

        # Speed (X, Y, Z) — 2 bytes each
        self.x_speed_bytes = self.data[37:39]
        self.y_speed_bytes = self.data[39:41]
        self.z_speed_bytes = self.data[41:43]
        self.x_speed_raw = self.le_int16(self.x_speed_bytes)
        self.y_speed_raw = self.le_int16(self.y_speed_bytes)
        self.z_speed_raw = self.le_int16(self.z_speed_bytes)

        self.x_speed = round(self.x_speed_raw / 100.0, 2)  # cm/s → m/s
        self.y_speed = round(self.y_speed_raw / 100.0, 2)
        self.z_speed = round(self.z_speed_raw / 100.0, 2)

        # Yaw Angle (2 bytes, signed)
        self.yaw_bytes = self.data[43:45]
        self.yaw_raw = self.le_int16(self.yaw_bytes)
        self.yaw_angle = round(self.yaw_raw / 100.0, 2)  # Assuming it's in centi-degrees

        # Pilot GPS clock time (8 bytes, little-endian unsigned 64-bit int)
        self.pilot_gps_time_bytes = self.data[45:53]
        self.pilot_gps_time_raw = struct.unpack("<Q", self.pilot_gps_time_bytes)[0] / 1000.0 # <Q = little-endian unsigned long long

        self.pilot_gps_time = datetime.fromtimestamp(self.pilot_gps_time_raw, UTC)

        # Convert UTC datetime to Singapore timezone
        self.pilot_gps_time_local = self.pilot_gps_time.astimezone(ZoneInfo("Asia/Singapore"))

        # Format the local time as "13 Jun 2025, 03:45 AM"
        self.pilot_gps_time_formatted = self.pilot_gps_time_local.strftime("%d %b %Y, %I:%M %p")

        self.app_lat_bytes = self.data[53:57]
        self.app_lon_bytes = self.data[57:61]
        self.app_lat_raw = self.le_uint32(self.app_lat_bytes)
        self.app_lon_raw = self.le_uint32(self.app_lon_bytes)
        self.app_lat = self.app_lat_raw / 174533.0
        self.app_lon = self.app_lon_raw / 174533.0

        self.home_lon_bytes = self.data[61:65]
        self.home_lat_bytes = self.data[65:69]
        self.home_lat_raw = self.le_uint32(self.home_lat_bytes)
        self.home_lon_raw = self.le_uint32(self.home_lon_bytes)
        self.home_lat = self.home_lat_raw / 174533.0
        self.home_lon = self.home_lon_raw / 174533.0

        # Drone Type ID (1 byte after pilot latitude)
        self.drone_type_id = self.data[69]
        self.drone_type = DRONEID_DRONE_TYPES.get(str(self.drone_type_id), f"Unknown (ID: {self.drone_type_id})")

    def print_packet_info(self):
        print(f"  Sequence Number    : {self.sequence_number:02x} → {self.sequence_number}")
        print(f"  State Information  : {self.state_info:02x} → {self.state_info}")
        print(f"  Serial Number      : {self.serial_number}")

    def print_drone_telemetry(self):
        self.print_coord("Drone Latitude", self.drone_lat_bytes, self.drone_lat_raw, self.drone_lat)
        self.print_coord("Drone Longitude", self.drone_lon_bytes, self.drone_lon_raw, self.drone_lon)
        print(f"\nAltitude (ft→m): {self.altitude_raw} ft → {self.altitude} m")
        print(f"Height   (ft→m): {self.height_raw} ft → {self.height} m")
        print(f"\nX Speed: {self.x_speed_raw} cm/s → {self.x_speed} m/s")
        print(f"Y Speed: {self.y_speed_raw} cm/s → {self.y_speed} m/s")
        print(f"Z Speed: {self.z_speed_raw} cm/s → {self.z_speed} m/s")
        print(f"\nYaw Angle: {self.yaw_raw} (×0.01°) → {self.yaw_angle}°")
        print(f"\nPilot GPS Time:")
        print(f"  Epoch Seconds : {self.pilot_gps_time_raw}")
        print(f"  UTC Timestamp : {self.pilot_gps_time.isoformat()}")
        print(f"  Singapore Time: {self.pilot_gps_time_formatted}")

    def print_coord(self, label, raw_bytes, raw_val, value):
        print(f"\n{label}:")
        print(f"  Raw bytes      : {' '.join(f'{b:02x}' for b in raw_bytes)}")
        print(f"  Little-endian  : 0x{raw_val:08x} = {raw_val}")
        print(f"  Converted value: {value:.6f}")

    def print_info(self):
        self.print_header()
        print(f"  Flight Info Version: {self.version:02x} → {self.version_desc}")
        self.print_packet_info()
        self.print_drone_telemetry()
        self.print_coord("App Latitude", self.app_lat_bytes, self.app_lat_raw, self.app_lat)
        self.print_coord("App Longitude", self.app_lon_bytes, self.app_lon_raw, self.app_lon)
        self.print_coord("Home Latitude", self.home_lat_bytes, self.home_lat_raw, self.home_lat)
        self.print_coord("Home Longitude", self.home_lon_bytes, self.home_lon_raw, self.home_lon)
        print(f"\nDrone Type     : {self.drone_type}")


class DroneIDPacketLicense(DroneIDPacket):
    def __init__(self, hex_str):
        super().__init__(hex_str)
        # Placeholder: real license info parsing would go here

    def print_info(self):
        self.print_header()
        print("  License Info: (parsing not yet implemented)")


if __name__ == "__main__":
    with open("hex.txt", "r") as file:
        hex_str = file.read().strip().replace(" ", "").replace("\n", "")


    packet_type = bytes.fromhex(hex_str)[3]

    if packet_type == 0x10:
        packet = DroneIDPacketFlight(hex_str)
    elif packet_type == 0x11:
        packet = DroneIDPacketLicense(hex_str)
    else:
        raise ValueError(f"Unsupported packet type: 0x{packet_type:02x}")

    packet.print_info()
