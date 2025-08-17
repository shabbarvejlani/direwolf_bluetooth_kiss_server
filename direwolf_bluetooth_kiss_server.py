#!/usr/bin/env python3
"""
APRS Gateway Script - FULLY FEATURED with argparse
- Runs as a persistent Bluetooth RFCOMM server using the modern D-Bus API.
- Can also be used as a one-off command-line tool to send a single packet.
- Supports a 'debug' mode for both methods to prevent RF transmission (dry run).
"""
import os
import socket
import argparse
import pydbus
from gi.repository import GLib
import io

# --- USER CONFIGURATION ---
MY_CALLSIGN = 'KO6GFW-9'    # Your callsign with SSID
DIREWOLF_HOST = 'localhost'
DIREWOLF_KISS_PORT = 8001
APRS_DESTINATION = 'APRS'
APRS_PATH = ['WIDE1-1', 'WIDE2-1']
# --- END OF CONFIGURATION ---

# Global flag for debug mode
DEBUG_MODE = False


# --- AX.25 and KISS Encoding Functions ---
# (This section is unchanged)

def encode_ax25_address(callsign_str, is_destination=False, is_last=False, is_command=False):
  """Encodes a callsign string into a 7-byte AX.25 address field."""
  callsign_str = callsign_str.upper()
  parts = callsign_str.split('-')
  call = parts[0]
  ssid = int(parts[1]) if len(parts) > 1 else 0
  if len(call) > 6: raise ValueError("Callsign portion cannot be more than 6 characters")
  if not (0 <= ssid <= 15): raise ValueError("SSID must be between 0 and 15")
  padded_call = call.ljust(6, ' ')
  shifted_call_bytes = bytes([(ord(c) << 1) for c in padded_call])
  base_ssid_byte = 0xe0
  c_bit = 0x80 if (is_command or is_destination) else 0x00
  h_bit = 0x01 if is_last else 0x00
  ssid_byte = bytes([(ssid << 1) | base_ssid_byte | c_bit | h_bit])
  return shifted_call_bytes + ssid_byte

def escape_kiss_data(data_bytes):
  """Escapes special KISS characters FEND and FESC."""
  FEND, FESC = b'\xC0', b'\xDB'
  FESC_TFEND, FESC_TFESC = b'\xDC', b'\xDD'
  escaped = data_bytes.replace(FESC, FESC + FESC_TFESC)
  escaped = escaped.replace(FEND, FESC + FESC_TFEND)
  return escaped


# --- Core APRS Logic Functions ---
# (This section is unchanged)

def build_aprs_kiss_frame(dest_callsign, message_text):
  """Builds a complete APRS message packet and wraps it in a KISS frame."""
  addr_to = encode_ax25_address(APRS_DESTINATION, is_destination=True)
  addr_from = encode_ax25_address(MY_CALLSIGN, is_command=True)
  address_field = addr_to + addr_from
  for i, path_item in enumerate(APRS_PATH):
    is_last_in_path = (i == len(APRS_PATH) - 1)
    address_field += encode_ax25_address(path_item, is_last=is_last_in_path)
  control_field, pid_field = b'\x03', b'\xf0'
  info_field = f":{dest_callsign.upper():<9}:{message_text}".encode('latin-1')
  ax25_packet = address_field + control_field + pid_field + info_field
  FEND, CMD_DATA_FRAME = b'\xC0', b'\x00'
  kiss_payload = escape_kiss_data(ax25_packet)
  kiss_frame = FEND + CMD_DATA_FRAME + kiss_payload + FEND
  return kiss_frame, info_field

def send_to_direwolf(kiss_frame):
  """Connects to Direwolf and sends a pre-built KISS frame, unless in debug mode."""
  global DEBUG_MODE
  if DEBUG_MODE:
    print("\n[DEBUG] --- Packet to be Sent ---")
    print(f"[DEBUG] KISS Frame (hex): {kiss_frame.hex()}")
    print("[DEBUG] --- End of Packet ---")
    print("[DEBUG] In debug mode, packet was NOT sent to Direwolf.")
    return True
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.connect((DIREWOLF_HOST, DIREWOLF_KISS_PORT))
      s.sendall(kiss_frame)
      return True
  except Exception as e:
    print(f"\n[ERROR] Could not send to Direwolf: {e}")
    return False

def process_and_send_message(dest_callsign, message_text):
  """High-level function to build, process, and send a message to Direwolf."""
  print("-" * 20)
  print(f"Building packet for destination: {dest_callsign}...")
  kiss_frame, info_field = build_aprs_kiss_frame(dest_callsign, message_text)
  print(f"Packet Details: TO:{APRS_DESTINATION} VIA {','.join(APRS_PATH)} FROM:{MY_CALLSIGN}")
  print(f"Payload: {info_field.decode('latin-1')}")
  if send_to_direwolf(kiss_frame):
    print("Packet processed successfully.")
  else:
    print("Failed to process packet.")
  print("-" * 20)


# --- Modern D-Bus Bluetooth Service ---

# ... (rest of the script remains the same until SerialProfile class)

class SerialProfile(object):
    __dbus_xml__ = """
    <node>
        <interface name='org.bluez.Profile1'>
            <method name='Release' />
            <method name='NewConnection'>
                <arg type='o' name='device' direction='in' />
                <arg type='h' name='fd' direction='in' />
                <arg type='a{sv}' name='fd_properties' direction='in' />
            </method>
            <method name='RequestDisconnection'>
                <arg type='o' name='device' direction='in' />
            </method>
        </interface>
    </node>
    """
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.io_channel = None
        self.connections = {}  # Track active connections

    def NewConnection(self, device, fd, fd_properties):
        device_path = device.replace("/org/bluez/hci0/dev_", "").replace("_", ":")
        print(f"New connection from device: {device_path}")

        # Set socket to non-blocking
        try:
            import fcntl
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        except Exception as e:
            print(f"Error setting non-blocking: {e}")
            os.close(fd)
            return

        # Create IO channel and watch for input
        channel = GLib.IOChannel(fd)
        source_id = GLib.io_add_watch(
            channel,
            GLib.PRIORITY_DEFAULT,
            GLib.IO_IN | GLib.IO_HUP,
            self._handle_io,
            device_path
        )
        
        # Store connection info
        self.connections[fd] = {
            'device': device_path,
            'source_id': source_id,
            'channel': channel,
            'buffer': b''
        }

    def _handle_io(self, channel, condition, device_path):
        fd = channel.unix_get_fd()
        conn = self.connections.get(fd)
        if not conn:
            return False

        try:
            if condition & GLib.IO_HUP:
                print(f"Client {device_path} disconnected.")
                self._cleanup_connection(fd)
                return False

            if condition & GLib.IO_IN:
                data = os.read(fd, 1024)
                if not data:
                    print(f"Client {device_path} disconnected.")
                    self._cleanup_connection(fd)
                    return False

                conn['buffer'] += data
                print(f"[BT RX from {device_path}] Raw data: {data}")

                # Process complete lines
                while b'\n' in conn['buffer']:
                    line, _, remainder = conn['buffer'].partition(b'\n')
                    conn['buffer'] = remainder
                    self._process_message(line.decode('utf-8', errors='ignore').strip(), fd, device_path)

        except Exception as e:
            print(f"Communication error: {e}")
            self._cleanup_connection(fd)
            return False

        return True

    def _process_message(self, message, fd, device_path):
        print(f"[BT RX from {device_path}] Received: {message}")
        if ':' in message:
            dest, msg_text = message.split(':', 1)
            process_and_send_message(dest.strip(), msg_text.strip())
        else:
            try:
                os.write(fd, b"ERROR: Use 'DEST:Message\\n' format\n")
            except Exception as e:
                print(f"Write error: {e}")

    def _cleanup_connection(self, fd):
        if fd not in self.connections:
            return
            
        conn = self.connections.pop(fd)
        GLib.source_remove(conn['source_id'])
        try:
            conn['channel'].shutdown(True)
        except:
            pass
        os.close(fd)

    def RequestDisconnection(self, device):
        device_path = device.replace("/org/bluez/hci0/dev_", "").replace("_", ":")
        print(f"Requested disconnection from {device_path}")
        # Find and close connection
        for fd, conn in list(self.connections.items()):
            if conn['device'] == device_path:
                self._cleanup_connection(fd)

# ... (rest of the script remains the same)

def start_bluetooth_service():
  """Sets up and runs the D-Bus service."""
  # FIXED: Removed the deprecated GLib.threads_init() call
  loop = GLib.MainLoop()
  bus = pydbus.SystemBus()
  PROFILE_PATH, UUID = "/bluez/profiles/serial_port", "94f39d29-7d6d-437d-973b-fba39e49d4ee"
  UUID = "00001101-0000-1000-8000-00805F9B34FB"
  # The NEW, corrected dictionary
  opts = {
    "Name": GLib.Variant('s', "APRS RF Gateway"),
    "Service": GLib.Variant('s', UUID),
    "Role": GLib.Variant('s', "server"),
    "RequireAuthentication": GLib.Variant('b', False),
    "RequireAuthorization": GLib.Variant('b', False),
    "Channel": GLib.Variant('q', 1), # 'q' is the type for a 16-bit unsigned integer
  }
  profile = SerialProfile(bus, PROFILE_PATH)
  bus.register_object(PROFILE_PATH, profile, [profile.__dbus_xml__])
  print("Serial Profile service registered with D-Bus.")
  profile_manager = bus.get('org.bluez', '/org/bluez')['org.bluez.ProfileManager1']
  profile_manager.RegisterProfile(PROFILE_PATH, UUID, opts)
  print("APRS RF Gateway profile registered with BlueZ. Waiting for connections...")
  try:
    loop.run()
  except KeyboardInterrupt:
    print("\nShutting down Bluetooth service.")
    profile_manager.UnregisterProfile(PROFILE_PATH)
    loop.quit()


# --- Main Dispatcher ---
# (This section is unchanged from the last working version)

def main():
  """Parses command-line arguments to run in the desired mode."""
  global DEBUG_MODE
  
  parser = argparse.ArgumentParser(
    description="A tool to send APRS messages via Direwolf from the command line or a Bluetooth serial app.",
    formatter_class=argparse.RawTextHelpFormatter
  )
  
  # Add the global --dry-run argument back to the main parser for simplicity
  parser.add_argument(
    '-d', '--dry-run', 
    action='store_true', 
    help='Enable debug mode. Builds packets but does not send them to Direwolf.'
  )
  
  subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)
  
  parser_send = subparsers.add_parser('send', help='Send a single APRS message and exit.')
  parser_send.add_argument('destination', help='The destination callsign for the message (e.g., CQ).')
  parser_send.add_argument('message', help='The message text to send, in quotes.')
  
  subparsers.add_parser('bluetooth', help='Run as a persistent Bluetooth service to listen for messages.')
  
  args = parser.parse_args()
  
  if args.dry_run:
    DEBUG_MODE = True
    print("--- Dry Run / Debug Mode Enabled: No data will be sent to Direwolf ---")
  
  if args.command == 'send':
    process_and_send_message(args.destination, args.message)
  elif args.command == 'bluetooth':
    start_bluetooth_service()


if __name__ == '__main__':
  main()