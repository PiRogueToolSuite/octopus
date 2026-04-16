# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from functools import cached_property
from importlib import resources
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Any, Optional

import frida
from frida.core import Device
from ppadb.client import Client as AdbClient
from ppadb.device import Device as PPDevice

from octopus.frida.server import FridaServer

logger = logging.getLogger(__name__)


class AndroidDevice:
    """
    Represents an Android device and provides methods for device management.

    This class encapsulates operations such as rooting, property retrieval,
    and Frida server management for an Android device.

    Attributes:
        adb: Instance of :class:`~octopus.android.adb.ADB` used for device communication.
        is_root: Indicates if the device is running as root.
        requires_su: Indicates if :textmono:`su` access is required for root operations.
        rooted: Indicates if the device is rooted or has `su` access.
        adb_device: The connected ADB device instance.
    """

    # device_tmp_dir = Path("/sdcard/")
    device_tmp_dir = Path("/data/local/tmp/")

    def __init__(self, adb_device: PPDevice):
        """
        Initializes the AndroidDevice instance.

        Connects to the device using the provided ADB instance, attempts to
        root the device, checks root status, and verifies Frida server installation.

        Args:
            adb: An instance of :class:`~octopus.android.adb.ADB` for device communication.
        """
        self.adb_device = adb_device
        self.is_root = False
        self.requires_su = False
        self.rooted = False
        self.tcpdump_binaries_dir = resources.files("octopus") / "assets" / "tcpdump_binaries"
        self.root()
        self.is_rooted()
        self._check_frida_server_installed()
        self.tcpdump_path = self.device_tmp_dir / "tcpdump"

    def root(self):
        """
        Attempts to root the Android device using ADB.

        Raises:
            RuntimeError: If root access is disabled on the device.

        Uses the internal ADB service to request root access. If the device is not already running as root,
        attempts to reconnect.
        """
        logger.info("Rooting the device")
        try:
            self.adb_device.root()
        except RuntimeError as e:
            if "adbd is already running as root" in str(e):
                pass
            else:
                raise e

    def get_device_properties(self) -> Dict[str, str]:
        """
        Retrieves key properties and identifiers from the Android device.

        Returns:
            A dictionary containing device properties such as
            fingerprint, brand, device, manufacturer, model, name, serial number,
            Android version, API level, and IMEI.

        Notes:
            Uses the :meth:`get_property` method to fetch system properties.
            IMEI is retrieved using a shell command that parses the output of
            :textmono:`service call iphonesubinfo`.
            Handles missing or empty property values gracefully.
        """
        props = [
            ("fingerprint", "ro.vendor.build.fingerprint"),
            ("brand", "ro.product.brand"),
            ("device", "ro.product.device"),
            ("manufacturer", "ro.product.manufacturer"),
            ("model", "ro.product.model"),
            ("name", "ro.product.name"),
            ("serialno", "ro.serialno"),
            ("android_version", "ro.build.version.release"),
            ("api_level", "ro.build.version.sdk"),
        ]
        device_properties = {}
        for name, key in props:
            device_properties[name] = self.get_property(key).strip()
        # Get IMEI
        imei = self.adb_shell(
            """service call iphonesubinfo 1|awk -F "'" '{print $2}'|sed '1 d'|tr -d '.'|awk '{print}' ORS="""
        )
        device_properties["imei"] = imei.strip()
        return device_properties

    def _get_system_properties(self) -> Dict[str, Any]:
        return self.get_frida_device().query_system_parameters()

    @cached_property
    def system_properties(self) -> Dict[str, Any]:
        return self._get_system_properties()

    @cached_property
    def architecture(self):
        return self._get_architecture()

    def _get_architecture(self) -> str:
        """
        Returns the device CPU architecture.

        Returns:
            The CPU architecture string, such as 'arm64', 'x86_64', 'arm', or 'x86'.
            Raises a RuntimeError if the architecture cannot be determined.
        """
        arch = self.system_properties["arch"]
        if arch == "arm64":
            return "arm64"
        elif arch == "arm":
            return "arm32"
        elif arch == "ia32":
            return "x86"
        elif arch == "x64":
            return "x86_64"
        elif "x86" in arch:
            return "x86"
        else:
            raise RuntimeError(f"Unknown architecture: {arch}")

    def get_tcpdump_version(self):
        return f"tcpdump_{self.architecture}_android"

    def is_rooted(self) -> bool:
        """
        Checks if the device is rooted.

        Returns:
            True if the device is rooted or has :textmono:`su` access, False otherwise.
        """
        # Check user is root
        self.is_root = "root" in self.adb_device.shell("whoami")
        # Check su
        if not self.is_root:
            self.requires_su = "inaccessible or not found" not in self.adb_device.shell('su -c "echo 1"')
        self.rooted = self.is_root or self.requires_su
        return self.rooted

    def adb_shell(self, command) -> str:
        """
        Executes a shell command on the device via ADB.

        Args:
            command: The shell command to execute.

        Returns:
            The output of the shell command as a string.

        Raises:
            Exception: If the command execution fails.

        Uses :textmono:`su` if root access is required and sets :textmono:`timeout=30`.
        """
        if self.requires_su:
            command = f'su -c "{command}"'
        return self.adb_device.shell(command, timeout=30)

    def adb_shell_no_wait(self, command):
        """
        Executes a shell command on the device without waiting for output.

        Args:
            command: The shell command to execute.

        Uses :textmono:`su` if root access is required. Opens the shell command with short
        timeouts for non-blocking execution.
        """

        def dummy_handler(_):
            pass

        if self.requires_su:
            command = f'su -c "{command}"'
        cmd = f"{command} &"
        self.adb_device.shell(cmd, handler=dummy_handler)

    def adb_push(self, local_path, device_path):
        """
        Pushes a file from the local system to the device.

        Args:
            local_path: Path to the local file.
            device_path: Destination path on the device.

        Raises:
            Exception: If the push operation fails.

        Uses the ADB push method to transfer files.
        """
        try:
            self.adb_device.push(local_path, device_path)
        except (Exception,) as e:
            raise Exception(f"Failed to push {local_path} to {device_path}") from e

    def adb_pull(self, device_path, local_path):
        """
        Pulls a file from the device to the local system.

        Args:
            device_path: Path to the file on the device.
            local_path: Destination path on the local system.

        Raises:
            Exception: If the pull operation fails.

        Uses the ADB pull method to transfer files.
        """
        try:
            self.adb_device.pull(str(device_path), str(local_path))
        except (Exception,) as e:
            raise Exception(f"Failed to pull {device_path} to {local_path}") from e

    def get_property(self, key: str) -> str:
        """
        Retrieves a system property from the device.

        Args:
            key: The property key to retrieve.

        Returns:
            The value of the system property as a string.

        Uses the :textmono:`getprop` shell command.
        """
        value = self.adb_shell(f"getprop {key}") or ""
        return value

    def _check_frida_server_running(self) -> bool:
        """
        Checks if the Frida server process is running on the device.

        Returns:
            True if the Frida server is running, False otherwise.

        This method uses the :textmono:`ps` command to search for the Frida server process.
        """
        value = self.adb_shell(f"ps -A | grep {FridaServer.executable}")
        value = value.strip()
        return bool(value)

    def _check_frida_server_installed(self) -> bool:
        """
        Checks if the Frida server binary is installed on the device.

        Returns:
            True if the Frida server binary exists, False otherwise.

        Uses the :textmono:`ls` command to verify the presence of the Frida server binary.
        """
        status = self.adb_shell(f"ls {FridaServer.executable_path}")
        return "No such file or directory" not in status

    def get_frida_server_version(self) -> str:
        """
        Retrieves the version of the installed Frida server.

        Returns:
            The version string of the Frida server, or '0.0.0' if not found.

        Executes the Frida server binary with the :textmono:`--version` flag.
        """
        return self.adb_shell(f"{FridaServer.executable_path} --version").strip() or "0.0.0"

    def get_frida_device(self) -> Device:
        raise NotImplementedError()

    def start_frida_server(self, force_stop: bool = True):
        """
        Starts the Frida server on the device if it is not already running.

        Args:
            force_stop: Forces stopping the Frida server before starting it.

        If the server is already running, just logs an informational message.
        Otherwise, starts the server in daemon mode.
        """
        if force_stop:
            self.stop_frida_server()
        if self._check_frida_server_running():
            logger.info("Frida server is already running...")
        else:
            logger.info("Starting Frida server...")
            self.adb_shell(f"{FridaServer.executable_path} -l 0.0.0.0 --daemonize")

    def stop_frida_server(self):
        """
        Stops the Frida server process on the device.

        Uses the :textmono:`pkill` command to terminate the Frida server process.
        """
        logger.info("Stopping Frida server...")
        self.adb_shell(f"pkill -f -l 9 {FridaServer.executable}")

    def install_frida_server(self, version: Optional[str] = None):
        """Installs the Frida server binary on the device.

        Downloads the specified version of the Frida server binary,
        pushes it to the device, and sets the executable permission.
        Uses a temporary file for the download.

        Args:
            version: The version of the Frida server to install.
                Defaults to the currently installed ``frida`` Python
                package version.
        """
        target_version = version or frida.__version__
        logger.info(f"Installing frida-server {target_version} on device ({FridaServer.executable})...")

        # Stop any running Frida server instance before replacing the binary
        self.stop_frida_server()

        with NamedTemporaryFile(mode="wb") as frida_server:
            # Download the appropriate binary for this device's architecture
            FridaServer.download_frida_server(
                self.architecture,
                frida_server.name,
                "android",
                target_version,
            )
            frida_server.seek(0)

            # Push the binary to the device and make it executable
            self.adb_push(frida_server.name, FridaServer.executable_path)
            self.adb_shell(f"chmod +x {FridaServer.executable_path}")

        logger.info(f"frida-server version {target_version} successfully installed.")

    def install_tcpdump(self):
        logger.info(f"Installing tcpdump on device {self.tcpdump_path}...")
        tcpdump_version = self.get_tcpdump_version()
        tcpdump_binary = self.tcpdump_binaries_dir / tcpdump_version
        self.adb_device.push(tcpdump_binary, str(self.tcpdump_path))
        self.adb_shell(f"chmod +x {self.tcpdump_path}")


class AndroidDeviceUsb(AndroidDevice):
    """
    Android device connected via USB.

    Inherits from :class:`~octopus.android.device.AndroidDevice` and
    initializes the device using a default :class:`~octopus.android.adb.ADB`
    instance for USB communication.
    """

    def __init__(self, device_id: Optional[str] = None):
        """Instantiate an AndroidDeviceUsb instance.

        Connects to an ADB client and selects the appropriate device.
        If a ``device_id`` is provided, connects to that specific device.
        If only one device is connected, selects it automatically.

        Args:
            device_id: Optional ADB device serial number. If omitted and
                exactly one device is connected, it is selected
                automatically. Raises :exc:`RuntimeError` if no device
                can be determined.

        Raises:
            RuntimeError: If no device is found and ``device_id`` is not
                provided, or if more than one device is connected without
                specifying a ``device_id``.
        """
        client = AdbClient(host="127.0.0.1", port=5037)
        client.devices()
        if device_id:
            device = client.device(device_id)
        elif len(client.devices()) == 1:
            device = client.devices()[0]
        else:
            raise RuntimeError("No device found.")
        super().__init__(device)

    def get_frida_device(self) -> Device:
        return frida.get_usb_device()


class AndroidDeviceTcp(AndroidDevice):
    """
    Android device connected via TCP/IP.

    Inherits from :class:`~octopus.android.device.AndroidDevice` and
    initializes the device using a :class:`~octopus.android.adb.ADB` instance
    configured for TCP/IP communication.
    """

    def __init__(self, host: str, port: int = 5555):
        """
        Initializes an AndroidDeviceTcp instance.

        Args:
            host: The IP address or hostname of the device.
            port: The TCP port for ADB connection. Defaults to 5555.
        """
        client = AdbClient(host="127.0.0.1", port=5037)
        client.remote_connect(host, port)
        device = client.device(f"{host}:{port}")
        super().__init__(device)
        self.host = host
        self.port = port

    def get_frida_device(self) -> Device:
        return frida.get_device_manager().add_remote_device(self.host)
