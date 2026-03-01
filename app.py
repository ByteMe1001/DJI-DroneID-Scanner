import logging
import os
import signal
import sys
from datetime import datetime

from flask import Flask, render_template, request, redirect
from flask_socketio import emit

from extensions import socketio  # no circular import
from process_packet import process_packet
from sniffer_manager import SniffManager
from werkzeug.utils import secure_filename

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
)

app = Flask(__name__)
socketio.init_app(app)
print(f"SocketIO async_mode: {socketio.async_mode}")
# In-memory store for demonstration
drone_messages = {}

# File upload config
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Global Variables
sniffer_instance = None
sniffer_started = False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/start', methods=['POST'])
def start_sniffing():
    global sniffer_started, sniffer_instance

    mode = request.form.get('mode')
    if sniffer_started:
        return {"status": "already_running"}, 200

    if mode == 'live':

        # Read password from password.txt
        with open('files/password.txt', 'r') as f:
            password = f.read().strip()

        sniffer_instance = SniffManager(process_packet)
        socketio.start_background_task(
            sniffer_instance.start_sniffing,
            "192.168.1.1",  # host
            "root",  # username
            password,  # password
            None  # key_filename (optional)
        )
        sniffer_started = True
        return {"status": "started"}, 200

    elif mode == 'pcap':
        uploaded_file = request.files.get('pcap_file')
        if uploaded_file and uploaded_file.filename.endswith('.pcap'):
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(filepath)
            sniffer_instance = SniffManager(process_packet)
            socketio.start_background_task(sniffer_instance.parse_file, filepath)
            sniffer_started = True
            return {"status": "pcap_started"}, 200
        else:
            return {"status": "invalid_file"}, 400

    return {"status": "invalid_mode"}, 400


@app.route('/stop', methods=['POST'])
def stop_sniffing():
    global sniffer_started, sniffer_instance

    if sniffer_started and sniffer_instance:
        sniffer_instance.shutdown()
        sniffer_instance = None
        sniffer_started = False
        return {"status": "stopped"}, 200

    return {"status": "not_running"}, 400

@app.route('/map')
def map_view():
    return render_template('map.html')


@socketio.on('new_drone_data')
def handle_drone_data(data):
    required = ['drone_sn', 'drone_lat', 'drone_lon', 'pilot_lat', 'pilot_lon']
    if not all(k in data for k in required):
        emit('error', {'error': 'Missing required fields'})
        return

    # Add timestamp
    data['timestamp'] = datetime.utcnow().isoformat()

    # Store by drone_sn
    drone_messages[data['drone_sn']] = data

    # Broadcast updated info to all connected clients
    emit('update_drone', data, broadcast=True)

    print(f"[+] Received drone data: {data}")


# Attempt to fix issue where pcap is parsed too fast
# @socketio.on('connect')
# def send_latest_to_client():
#     global sniffer_started
#     sid = request.sid
#
#     if not sniffer_started:
#         sniffer_started = True
#         socketio.start_background_task(SniffManager.test)
#
#     # Send buffered messages if any
#     for drone_sn, data in drone_messages.items():
#         socketio.emit('update_drone', data, room=sid, namespace='/')

def handle_termination(signum, frame):
    logging.info(f"Received termination signal ({signum}). Running shutdown logic...")
    if sniffer_instance:
        try:
            sniffer_instance.shutdown()
            logging.info("Sniffer shutdown completed.")
        except Exception as e:
            logging.warning(f"[!] Error during sniffer shutdown: {e}")
    sys.exit(0)

# Register for SIGTERM (kill/IDE stop) and SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, handle_termination)
signal.signal(signal.SIGTERM, handle_termination)

if __name__ == '__main__':
#     socketio.run(app, debug=True, allow_unsafe_werkzeug=True)

    socketio.run(app, host='0.0.0.0', port=5050, allow_unsafe_werkzeug=True)

# if __name__ == '__main__':
#     from waitress import serve  # Optional: production-ready alternative to Werkzeug
#     # socketio.run(app, debug=False)  # Werkzeug, used by default
#     serve(app, host="0.0.0.0", port=5000)  # Use this line for production-ready `.exe`