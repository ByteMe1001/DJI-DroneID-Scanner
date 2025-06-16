import paramiko
import subprocess
import threading
import signal
import logging

# --- Setup Logger ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("Controller")


class SSHController:
    def __init__(self, host, username, password=None, key_filename=None):
        self.host = host
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        try:
            if self.key_filename:
                self.client.connect(hostname=self.host, username=self.username, key_filename=self.key_filename)
            else:
                self.client.connect(hostname=self.host, username=self.username, password=self.password)
            logger.info(f"Connected to {self.host}")
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            raise

    def run_commands(self, commands):
        self.connect()
        for cmd in commands:
            logger.info(f"Running: {cmd}")
            stdin, stdout, stderr = self.client.exec_command(cmd)
            out, err = stdout.read().decode(), stderr.read().decode()
            if out:
                logger.info(out.strip())
            if err:
                logger.warning(err.strip())
        self.close()

    # Note the channel number is 2 fixed here
    def setup_monitor_mode(self):
        setup_cmds = [
            "ip link set phy0-ap0 down",
            "iw dev phy0-ap0 set type monitor",
            "ip link set phy0-ap0 up",
            "iw dev phy0-ap0 set channel 2 5MHz",
            "iw phy phy0 interface add mon0 type monitor",
            "ip link set mon0 up"
        ]
        self.run_commands(setup_cmds)


    # Use paramiko instead of subprocess
    def start_tcpdump_stream(self):
        logger.info("Starting tcpdump over SSH...")
        self.connect()
        self.channel = self.client.get_transport().open_session()
        self.channel.exec_command("tcpdump -i mon0 -s 0 -U -w -")
        self.stdout = self.channel.makefile("rb")  # Save it as self.stdout
        return self.stdout

    def stop_tcpdump_stream(self):
        """
        Gracefully closes the SSH channel to stop the remote tcpdump stream.
        """
        logger.info("Stopping tcpdump stream...")
        try:
            if hasattr(self, 'channel') and self.channel and not self.channel.closed:
                self.channel.close()
                logger.info("TCPDUMP SSH channel closed.")
        except Exception as e:
            logger.warning(f"[!] Failed to close SSH channel: {e}")

    # Delete created monitor interface
    def shutdown(self):
        try:
            self.connect()
            self.run_commands(["iw dev mon0 del"])
        except Exception as e:
            logger.warning(f"Shutdown error: {e}")
        finally:
            self.close()


    def close(self):
        self.client.close()
        logger.info("SSH connection closed.")


# Test code
def read_raw_tcpdump_output(stdout):
    logger.info("[*] Reading packets from tcpdump stream...")
    try:
        total = 0
        while True:
            chunk = stdout.read(1024)
            if not chunk:
                logger.warning("[-] No more data from tcpdump.")
                break
            total += len(chunk)
            print(f"[+] Received {len(chunk)} bytes (Total: {total})")
    except Exception as e:
        logger.error(f"[!] Error while reading stream: {e}")


def main():
    ssh = SSHController(host="192.168.1.1", username="root", password="PUTPASSWORD")

    try:
        ssh.setup_monitor_mode()
    except Exception as e:
        logger.critical(f"Monitor mode setup failed: {e}")
        return

    stdout = ssh.start_tcpdump_stream()

    # Start reading raw traffic
    reader_thread = threading.Thread(target=read_raw_tcpdump_output, args=(stdout,))
    reader_thread.start()

    logger.info("Capture started. Commands: [p] Pause  [r] Resume  [q] Quit")
    try:
        while True:
            choice = input("Command (p/r/q): ").strip().lower()
            if choice == "p":
                logger.info("Pausing capture...")
                ssh.pause_capture()
            elif choice == "r":
                logger.info("Resuming capture...")
                ssh.resume_capture()
            elif choice == "q":
                logger.info("Stopping capture...")
                ssh.stop_capture()
                break
    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        ssh.stop_capture()

    reader_thread.join()

    try:
        ssh.shutdown()
    except Exception as e:
        logger.warning(f"Shutdown encountered an error: {e}")

    logger.info("All done.")


if __name__ == "__main__":
    main()

