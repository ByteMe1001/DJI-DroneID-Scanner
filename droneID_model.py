from pydantic import BaseModel
from parser import MessageModel

class DroneIDPacketModel(BaseModel, MessageModel):
    provider: str = "DJI"
    serial_number: str
    drone_lat: float
    drone_lon: float
    altitude_m: float
    height_m: float
    x_speed_mps: float
    y_speed_mps: float
    z_speed_mps: float
    yaw_deg: float
    gps_time: float  # Raw Unix timestamp in seconds
    pilot_lat: float
    pilot_lon: float
    home_lat: float
    home_lon: float
    drone_type: str

    # To amend this abstract function
    def __str__(self):
        return (
            f"[{self.provider}] {self.drone_type} (S/N: {self.serial_number}) "
            f"at ({self.drone_lat}, {self.drone_lon}) "
            f"Pilot Location: ({self.pilot_lat}, {self.pilot_lon})"
        )