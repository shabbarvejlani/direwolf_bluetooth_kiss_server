#!/usr/bin/env python3
"""
Bidirectional SPP server with APRS/Direwolf integration
- Reads/writes via /dev/rfcomm0
- Android -> rfcomm0 -> Python -> Direwolf
- Python -> rfcomm0 -> Android
"""

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import os
import termios
import threading
import socket
import select

# --- Configuration ---
SPP_UUID = '00001101-0000-1000-8000-00805F9B34FB'
RFCOMM_SYMLINK = '/dev/rfcomm0'

MY_CALLSIGN = 'KO6GFW-9'
DIREWOLF_HOST = 'localhost'
DIREWOLF_KISS_PORT = 8001
APRS_DESTINATION = 'APRS'
APRS_PATH = ['WIDE1-1', 'WIDE2-1']

DEBUG_MODE = False

# --- AX.25 / KISS helpers ---
def encode_ax25_address(callsign_str, is_destination=False, is_last=False, is_command=False):
    callsign_str = callsign_str.upper()
    parts = callsign_str.split('-')
    call = parts[0]
    ssid = int(parts[1]) if len(parts) > 1 else 0
    padded_call = call.ljust(6, ' ')
    shifted_call_bytes = bytes([(ord(c)<<1) for c in padded_call])
    base_ssid_byte = 0xe0
    c_bit = 0x80 if (is_command or is_destination) else 0x00
    h_bit = 0x01 if is_last else 0x00
    ssid_byte = bytes([(ssid << 1)|base_ssid_byte|c_bit|h_bit])
    return shifted_call_bytes + ssid_byte

def escape_kiss_data(data_bytes):
    FEND, FESC = b'\xC0', b'\xDB'
    FESC_TFEND, FESC_TFESC = b'\xDC', b'\xDD'
    escaped = data_bytes.replace(FESC, FESC+FESC_TFESC)
    escaped = escaped.replace(FEND, FESC+FESC_TFEND)
    return escaped

def build_aprs_kiss_frame(dest_callsign, message_text):
    addr_to = encode_ax25_address(APRS_DESTINATION, is_destination=True)
    addr_from = encode_ax25_address(MY_CALLSIGN, is_command=True)
    address_field = addr_to + addr_from
    for i, path_item in enumerate(APRS_PATH):
        is_last_in_path = (i==len(APRS_PATH)-1)
        address_field += encode_ax25_address(path_item, is_last=is_last_in_path)
    control_field, pid_field = b'\x03', b'\xf0'
    info_field = f":{dest_callsign.upper():<9}:{message_text}".encode('latin-1')
    ax25_packet = address_field + control_field + pid_field + info_field
    FEND, CMD_DATA_FRAME = b'\xC0', b'\x00'
    kiss_payload = escape_kiss_data(ax25_packet)
    return FEND + CMD_DATA_FRAME + kiss_payload + FEND

def send_to_direwolf(kiss_frame):
    if DEBUG_MODE:
        print("[DEBUG] Packet:", kiss_frame.hex())
        return True
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((DIREWOLF_HOST,DIREWOLF_KISS_PORT))
            s.sendall(kiss_frame)
            return True
    except Exception as e:
        print("[ERROR] Direwolf send failed:", e)
        return False

def process_and_send_message(dest, msg):
    print(f"[APRS] {dest}:{msg}")
    frame = build_aprs_kiss_frame(dest, msg)
    send_to_direwolf(frame)

# --- Read from /dev/rfcomm0 ---
def start_rfcomm_reader():
    if not os.path.exists(RFCOMM_SYMLINK):
        print(f"[ERROR] {RFCOMM_SYMLINK} does not exist. Wait for Android connection first.")
        return

    def reader():
        buffer = b''
        with open(RFCOMM_SYMLINK, 'rb', buffering=0) as rf:
            while True:
                rlist, _, _ = select.select([rf], [], [])
                if rf in rlist:
                    data = rf.read(1024)
                    if not data:
                        continue
                    buffer += data
                    while b'\n' in buffer:
                        line, _, buffer = buffer.partition(b'\n')
                        line_str = line.decode(errors='ignore').strip()
                        if line_str:
                            print(f"[ANDROID] {line_str}")
                            if ':' in line_str:
                                dest,msg = line_str.split(':',1)
                                process_and_send_message(dest.strip(), msg.strip())
    t = threading.Thread(target=reader, daemon=True)
    t.start()

# --- Bluetooth SerialProfile ---
class SerialProfile(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)

    @dbus.service.method('org.bluez.Profile1', in_signature="", out_signature="")
    def Release(self):
        print("Profile released")

    @dbus.service.method('org.bluez.Profile1', in_signature="oha{sv}", out_signature="")
    def NewConnection(self, path, fd, properties):
        print(f"New SPP connection from {path}")
        sock_fd = fd.take()

        # PTY setup
        import pty
        master, slave = pty.openpty()
        slave_name = os.ttyname(slave)
        print(f"PTY created at {slave_name}")
        os.chmod(slave_name, 0o666)
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG)
        attrs[1] &= ~termios.OPOST
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        # update /dev/rfcomm0 symlink
        if os.path.islink(RFCOMM_SYMLINK) or os.path.exists(RFCOMM_SYMLINK):
            os.unlink(RFCOMM_SYMLINK)
        os.symlink(slave_name, RFCOMM_SYMLINK)
        print(f"{RFCOMM_SYMLINK} -> {slave_name}")

        # start rfcomm reader thread
        start_rfcomm_reader()

        # fork bridge for bidirectional flow
        pid = os.fork()
        if pid==0:
            while True:
                rlist, _, _ = select.select([master,sock_fd],[],[])
                if master in rlist:
                    data = os.read(master,1024)
                    if data: os.write(sock_fd,data)
                if sock_fd in rlist:
                    data = os.read(sock_fd,1024)
                    if data: os.write(master,data)
            os._exit(0)
        else:
            print(f"Bridge process started (pid={pid})")

    @dbus.service.method('org.bluez.Profile1', in_signature="o", out_signature="")
    def RequestDisconnection(self, path):
        print(f"RequestDisconnection {path}")

# --- Main ---
def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object('org.bluez','/org/bluez'),'org.bluez.ProfileManager1')

    profile_path = "/aprs/spp/profile"
    profile = SerialProfile(bus, profile_path)
    opts = {
        "Name":"APRS Gateway",
        "Role":"server",
        "Channel": dbus.UInt16(1),
        "Service": SPP_UUID,
        "AutoConnect": True
    }
    print("Registering SPP profile on channel 1...")
    manager.RegisterProfile(profile_path, SPP_UUID, opts)
    loop = GLib.MainLoop()
    loop.run()

if __name__=='__main__':
    main()
