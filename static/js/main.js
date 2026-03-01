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
    const {
        drone_sn,
        drone_type,
        drone_lat,
        drone_lon,
        pilot_lat,
        pilot_lon,
        altitude_m,
        height_m,
        x_speed_mps,
        y_speed_mps,
        z_speed_mps
    } = data;

    const dronePopupContent = `
        <b>Drone Type:</b> ${drone_type || 'Unknown'}<br>
        <b>Serial No:</b> ${drone_sn}<br>
        <hr>
        <b>Latitude:</b> ${drone_lat?.toFixed(6) || 'N/A'}<br>
        <b>Longitude:</b> ${drone_lon?.toFixed(6) || 'N/A'}<br>
        <b>Altitude:</b> ${altitude_m?.toFixed(2) || 'N/A'} m<br>
        <b>Height:</b> ${height_m?.toFixed(2) || 'N/A'} m<br>
        <hr>
        <b>X Speed:</b> ${x_speed_mps?.toFixed(2) || 'N/A'} m/s<br>
        <b>Y Speed:</b> ${y_speed_mps?.toFixed(2) || 'N/A'} m/s<br>
        <b>Z Speed:</b> ${z_speed_mps?.toFixed(2) || 'N/A'} m/s
    `;

    if (!droneMarkers[drone_sn]) {
        droneMarkers[drone_sn] = L.marker([drone_lat, drone_lon], { icon: blueIcon() })
            .addTo(map)
            .bindPopup(dronePopupContent);
    } else {
        droneMarkers[drone_sn].setLatLng([drone_lat, drone_lon]);
        droneMarkers[drone_sn].getPopup().setContent(dronePopupContent);
    }

    const pilotPopupContent = `
        <b>Pilot of:</b> ${drone_sn}<br>
        <b>Lat:</b> ${pilot_lat?.toFixed(6) || 'N/A'}<br>
        <b>Lon:</b> ${pilot_lon?.toFixed(6) || 'N/A'}
    `;

    if (!pilotMarkers[drone_sn]) {
        pilotMarkers[drone_sn] = L.marker([pilot_lat, pilot_lon], { icon: redIcon() })
            .addTo(map)
            .bindPopup(pilotPopupContent);
    } else {
        pilotMarkers[drone_sn].setLatLng([pilot_lat, pilot_lon]);
        pilotMarkers[drone_sn].getPopup().setContent(pilotPopupContent);
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
