const socket = io();
const map = L.map('map').setView([1.3521, 103.8198], 11);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors'
}).addTo(map);

const droneMarkers = {};
const pilotMarkers = {};

socket.on("connect", () => {
    console.log("[SocketIO] Connected to server!");
});

socket.on('update_drone', data => {
    const { drone_sn, drone_lat, drone_lon, pilot_lat, pilot_lon } = data;

    if (!droneMarkers[drone_sn]) {
        droneMarkers[drone_sn] = L.marker([drone_lat, drone_lon], { icon: blueIcon() })
            .addTo(map)
            .bindPopup(`Drone: ${drone_sn}`);
    } else {
        droneMarkers[drone_sn].setLatLng([drone_lat, drone_lon]);
    }

    if (!pilotMarkers[drone_sn]) {
        pilotMarkers[drone_sn] = L.marker([pilot_lat, pilot_lon], { icon: redIcon() })
            .addTo(map)
            .bindPopup(`Pilot of ${drone_sn}`);
    } else {
        pilotMarkers[drone_sn].setLatLng([pilot_lat, pilot_lon]);
    }
});

document.getElementById('pcapForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    const formData = new FormData(this);
    formData.append("mode", "pcap");

    const res = await fetch('/start', {
        method: 'POST',
        body: formData
    });

    const json = await res.json();
    document.getElementById("status").innerText = "Status: " + (json.message || json.status);
});

function startLive() {
    fetch('/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'mode=live'
    })
    .then(res => res.json())
    .then(data => {
        document.getElementById("status").innerText = "Status: " + (data.message || data.status);
    });
}

function stopSniff() {
    fetch('/stop', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            document.getElementById("status").innerText = "Status: " + (data.message || data.status);
        });
}

function blueIcon() {
    return new L.Icon({
        iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-blue.png',
        shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
        iconSize: [25, 41],
        iconAnchor: [12, 41],
        popupAnchor: [1, -34],
        shadowSize: [41, 41]
    });
}

function redIcon() {
    return new L.Icon({
        iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-red.png',
        shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
        iconSize: [25, 41],
        iconAnchor: [12, 41],
        popupAnchor: [1, -34],
        shadowSize: [41, 41]
    });
}
