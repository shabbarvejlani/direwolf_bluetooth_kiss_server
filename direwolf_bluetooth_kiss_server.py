#!/usr/bin/env python3
import socket
import sys
import bluetooth

# --- USER CONFIGURATION ---
MY_CALLSIGN = 'KO6GFW-9'    # Your callsign with SSID
DIREWOLF_HOST = 'localhost'
DIREWOLF_KISS_PORT = 8001

# APRS-IS destination and path for messaging
# This is standard for sending messages via RF to the APRS-IS network
APRS_DESTINATION = 'APRS'
APRS_PATH = ['WIDE1-1', 'WIDE2-1']
# --- END OF CONFIGURATION ---

# --- AX.25 and KISS Encoding Functions ---

def encode_ax25_address(callsign_str, is_destination=False, is_last=False, is_command=False):
    """Encodes a callsign string into a 7-byte AX.25 address field."""
    callsign_str = callsign_str.upper()
    parts = callsign_str.split('-')
    call = parts[0]
    ssid = int(parts[1]) if len(parts) > 1 else 0

    if len(call) > 6:
        raise ValueError("Callsign portion cannot be more than 6 characters")
    if not (0 <= ssid <= 15):
        raise ValueError("SSID must be between 0 and 15")

    padded_call = call.ljust(6, ' ')
    shifted_call_bytes = bytes([(ord(c) << 1) for c in padded_call])

    base_ssid_byte = 0xe0 # Repeater/Destination SSID bits
    c_bit = 0x80 if (is_command or is_destination) else 0x00
    h_bit = 0x01 if is_last else 0x00
    ssid_byte = bytes([(ssid << 1) | base_ssid_byte | c_bit | h_bit])
    
    return shifted_call_bytes + ssid_byte

def escape_kiss_data(data_bytes):
    """Escapes special KISS characters FEND and FESC."""
    FEND = b'\xC0'
    FESC = b'\xDB'
    FESC_TFEND = b'\xDC'
    FESC_TFESC = b'\xDD'
    
    escaped = data_bytes.replace(FESC, FESC + FESC_TFESC)
    escaped = escaped.replace(FEND, FESC + FESC_TFEND)
    
    return escaped

# --- Core Logic Functions ---

def build_aprs_kiss_frame(dest_callsign, message_text):
    """Builds a complete APRS message packet and wraps it in a KISS frame."""
    # Encode the TO, FROM, and PATH addresses
    addr_to = encode_ax25_address(APRS_DESTINATION, is_destination=True)
    addr_from = encode_ax25_address(MY_CALLSIGN, is_command=True)
    
    address_field = addr_to + addr_from

    for i, path_item in enumerate(APRS_PATH):
        is_last_in_path = (i == len(APRS_PATH) - 1)
        address_field += encode_ax25_address(path_item, is_last=is_last_in_path)
    
    # Define control, protocol, and information fields
    control_field = b'\x03' # UI-Frame
    pid_field = b'\xf0'     # No layer 3 protocol
    info_field = f":{dest_callsign.upper():<9}:{message_text}".encode('latin-1')

    ax25_packet = address_field + control_field + pid_field + info_field
    
    # Wrap in KISS frame
    FEND = b'\xC0'
    CMD_DATA_FRAME = b'\x00'
    kiss_payload = escape_kiss_data(ax25_packet)
    kiss_frame = FEND + CMD_DATA_FRAME + kiss_payload + FEND
    
    return kiss_frame, info_field

def send_to_direwolf(kiss_frame):
    """Connects to Direwolf and sends a pre-built KISS frame."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((DIREWOLF_HOST, DIREWOLF_KISS_PORT))
            s.sendall(kiss_frame)
            return True
    except Exception as e:
        print(f"\n[ERROR] Could not send to Direwolf: {e}")
        return False

def process_and_send_message(dest_callsign, message_text):
    """High-level function to process and send a message."""
    print("-" * 20)
    print(f"Preparing message for {dest_callsign}...")
    
    kiss_frame, info_field = build_aprs_kiss_frame(dest_callsign, message_text)
    
    print(f"Sending Packet: TO:{APRS_DESTINATION} VIA {','.join(APRS_PATH)} FROM:{MY_CALLSIGN}")
    print(f"Payload: {info_field.decode('latin-1')}")

    if send_to_direwolf(kiss_frame):
        print("Packet sent successfully to Direwolf for RF transmission.")
    else:
        print("Failed to send packet.")
    print("-" * 20)

# --- Bluetooth Listener Function ---

def start_bluetooth_listener():
    """Starts a server to listen for messages over Bluetooth RFCOMM."""
    server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    server_sock.bind(("", bluetooth.PORT_ANY))
    server_sock.listen(1)

    port = server_sock.getsockname()[1]
    uuid = "94f39d29-7d6d-437d-973b-fba39e49d4ee" # Standard SerialPort UUID

    bluetooth.advertise_service(server_sock, "APRSGateway", service_id=uuid,
                                service_classes=[uuid, bluetooth.SERIAL_PORT_CLASS],
                                profiles=[bluetooth.SERIAL_PORT_PROFILE])
    
    print(f"Bluetooth listener started. Waiting for connection on RFCOMM channel {port}...")

    while True:
        try:
            client_sock, client_info = server_sock.accept()
            print(f"[BT] Accepted connection from {client_info[0]}")

            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                
                message = data.decode('utf-8').strip()
                print(f"[BT] Received: {message}")

                if ':' in message:
                    dest, msg_text = message.split(':', 1)
                    process_and_send_message(dest.strip(), msg_text.strip())
                else:
                    print("[BT] Invalid format. Use: DESTINATION:Your message")

        except IOError:
            print("[BT] Client disconnected.")
        except KeyboardInterrupt:
            print("\nShutting down Bluetooth listener.")
            break
        except Exception as e:
            print(f"[BT-ERROR] An error occurred: {e}")

    client_sock.close()
    server_sock.close()

# --- Main Entry Point ---

def main():
    """Parses command-line arguments to run in the desired mode."""
    if len(sys.argv) == 2 and sys.argv[1].lower() == 'bluetooth':
        start_bluetooth_listener()
    elif len(sys.argv) == 3:
        dest_callsign = sys.argv[1]
        message_text = sys.argv[2]
        process_and_send_message(dest_callsign, message_text)
    else:
        print("--- APRS RF Gateway Script ---")
        print(f"Usage (Command-line mode): {sys.argv[0]} <DEST_CALLSIGN> \"Your message\"")
        print(f"Usage (Bluetooth mode):    {sys.argv[0]} bluetooth")
        sys.exit(1)

if __name__ == '__main__':
    main()