#!/usr/bin/env python3
"""
Bluetooth SPP server for Direwolf
- Exposes /dev/rfcomm0 when phone connects
- Use in direwolf.conf: SERIALKISSPOLL /dev/rfcomm0 9600
"""

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import os, termios, select

# --- Config ---
SPP_UUID = '00001101-0000-1000-8000-00805F9B34FB'
RFCOMM_SYMLINK = '/dev/rfcomm0'


class SerialProfile(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)

    @dbus.service.method('org.bluez.Profile1', in_signature="", out_signature="")
    def Release(self):
        print("Profile released")

    @dbus.service.method('org.bluez.Profile1', in_signature="oha{sv}", out_signature="")
    def NewConnection(self, path, fd, properties):
        print(f"[BT] New SPP connection from {path}")
        sock_fd = fd.take()

        # PTY setup
        import pty
        master, slave = pty.openpty()
        slave_name = os.ttyname(slave)
        os.chmod(slave_name, 0o666)

        # Disable echo/canonical mode
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG)
        attrs[1] &= ~termios.OPOST
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        # Update symlink /dev/rfcomm0
        if os.path.islink(RFCOMM_SYMLINK) or os.path.exists(RFCOMM_SYMLINK):
            os.unlink(RFCOMM_SYMLINK)
        os.symlink(slave_name, RFCOMM_SYMLINK)
        print(f"[BT] Created symlink {RFCOMM_SYMLINK} -> {slave_name}")

        # Bridge loop (pass data both ways)
        pid = os.fork()
        if pid == 0:
            while True:
                rlist, _, _ = select.select([master, sock_fd], [], [])
                if master in rlist:
                    data = os.read(master, 1024)
                    if data:
                        os.write(sock_fd, data)
                if sock_fd in rlist:
                    data = os.read(sock_fd, 1024)
                    if data:
                        os.write(master, data)
            os._exit(0)
        else:
            print(f"[BT] Bridge process started (pid={pid})")

    @dbus.service.method('org.bluez.Profile1', in_signature="o", out_signature="")
    def RequestDisconnection(self, path):
        print(f"[BT] RequestDisconnection {path}")


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'),
                             'org.bluez.ProfileManager1')

    profile_path = "/aprs/spp/profile"
    profile = SerialProfile(bus, profile_path)
    opts = {
        "Name": "Direwolf SPP",
        "Role": "server",
        "Channel": dbus.UInt16(1),
        "Service": SPP_UUID,
        "AutoConnect": True
    }
    print("[BT] Registering SPP profile on channel 1...")
    manager.RegisterProfile(profile_path, SPP_UUID, opts)

    print("[BT] Waiting for APRSdroid to connect...")
    loop = GLib.MainLoop()
    loop.run()


if __name__ == '__main__':
    main()
