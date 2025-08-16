#!/usr/bin/env python3
import socket
import sys

# --- USER CONFIGURATION ---
MY_CALLSIGN = 'KO6GFW-9'   # Your callsign with SSID
DIREWOLF_HOST = 'localhost'
DIREWOLF_KISS_PORT = 8001
# --- END OF CONFIGURATION ---

def encode_ax25_address(callsign_str, is_destination=False, is_last=False, is_command=False):
    """
    Encodes a callsign string (e.g., 'N0CALL-1') into a 7-byte AX.25 address field.
    """
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

    base_ssid_byte = 0xe0 if is_destination else 0x60
    c_bit = 0x80 if is_command else 0x00
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

def main():
    """Builds an AX.25 frame manually, wraps it in KISS, and sends for RF."""
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <DESTINATION_CALLSIGN> \"Your message text\"")
        sys.exit(1)

    dest_callsign = sys.argv[1]
    message_text = sys.argv[2]
    
    # --- THIS IS THE CORRECTED PART ---
    # Define the AX.25 addresses and path.
    # The path is now a Python list, which can hold multiple items.
    AX25_DESTINATION = 'APX218'
    AX25_PATH = ['WIDE1-1', 'WIDE2-1']

    # Encode the TO and FROM addresses first
    addr_to = encode_ax25_address(AX25_DESTINATION, is_destination=True)
    addr_from = encode_ax25_address(MY_CALLSIGN, is_command=True)
    
    address_field = addr_to + addr_from

    # Now, loop through the path list and encode each item
    for i, path_item in enumerate(AX25_PATH):
        # Check if this is the last item in the list to set the "last address" bit
        is_last_in_path = (i == len(AX25_PATH) - 1)
        address_field += encode_ax25_address(path_item, is_last=is_last_in_path)
    # --- END OF CORRECTION ---
    
    control_field = b'\x03'
    pid_field = b'\xf0'
    info_field = f":{dest_callsign.upper():<9}:{message_text}".encode('latin-1')

    ax25_packet = address_field + control_field + pid_field + info_field
    
    FEND = b'\xC0'
    CMD_DATA_FRAME = b'\x00'
    kiss_payload = escape_kiss_data(ax25_packet)
    kiss_frame = FEND + CMD_DATA_FRAME + kiss_payload + FEND
    
    print("Connecting to Direwolf's KISS port...")
    print(f"Sending Packet: TO:{AX25_DESTINATION} VIA {','.join(AX25_PATH)} FROM:{MY_CALLSIGN} INFO:{info_field.decode('latin-1')}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((DIREWOLF_HOST, DIREWOLF_KISS_PORT))
            s.sendall(kiss_frame)
            print("Packet sent successfully to Direwolf for RF transmission.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == '__main__':
    main()