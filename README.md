# DJIDroneIDScanner
This repository contains the source code for a DJI DroneID Scanner using Enhanced Wi-Fi for Individual Team Project (ITP)

## Background
DJI DroneID is a protocol that transmits a drone's information and telemetry via 2.4/5.8 GHZ RF & WiFi beacons.
### Properties
- Broadcasted every 200ms
- Bandwidth of 5 MHz
- 802.11 Beacon Frames or Wi-Fi NaN
- Fields: Drone Serial Number, Position, Home Location

Capture using Kismet
```
sudo kismet -c 'wlan0:type=linuxwifi,channels="1W5,2W5,3W5,4W5,5W5,6W5,7W5,8W5,9W5,10W5,11W5,12W5,13W5,14W5"'
```
#### DJI OUIs
- 60:60:1F
- 48:1C:B9
- 34:D2:62


