from pydantic import BaseModel, Field, validator
from parser import MessageModel

class DroneIDPacketModel(BaseModel, MessageModel):
    provider: str = "DJI"
    serial_number: str
    drone_lat: float = Field(..., ge=-90, le=90)
    drone_lon: float = Field(..., ge=-180, le=180)
    altitude_m: float
    height_m: float
    x_speed_mps: float
    y_speed_mps: float
    z_speed_mps: float
    yaw_deg: float
    gps_time: float                                     # Raw Unix timestamp in seconds
    pilot_lat: float = Field(..., ge=-90, le=90)
    pilot_lon: float = Field(..., ge=-180, le=180)
    home_lat: float = Field(..., ge=-90, le=90)
    home_lon: float = Field(..., ge=-180, le=180)
    drone_type: str


    # For string printing only
    def __str__(self):
        return (
            f"[{self.provider}] {self.drone_type} (S/N: {self.serial_number}) "
            f"at ({self.drone_lat}, {self.drone_lon}) "
            f"Pilot Location: ({self.pilot_lat}, {self.pilot_lon})"
        )

    # Payload for WebSocket or JSON API
    def to_payload(self) -> dict:
        return {
            "drone_sn": self.serial_number,
            "drone_lat": self.drone_lat,
            "drone_lon": self.drone_lon,
            "pilot_lat": self.pilot_lat,
            "pilot_lon": self.pilot_lon,
        }
