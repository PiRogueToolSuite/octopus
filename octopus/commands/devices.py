# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from ppadb.client import Client as AdbClient

from octopus.android.device import AndroidDeviceUsb


def list_local_devices(adb_host="127.0.0.1", adb_port=5037):
    client = AdbClient(adb_host, adb_port)
    device_serials = [d.serial for d in client.devices()]
    print(f"{len(device_serials)} device(s) found:")
    for serial in device_serials:
        d = AndroidDeviceUsb(device_id=serial)
        frida_server_installed = d.check_frida_server_installed()
        if frida_server_installed:
            print(f"- {serial}: Frida server {d.get_frida_server_version()}")
        else:
            print(f"- {serial}: Frida server is not installed")
        pass
