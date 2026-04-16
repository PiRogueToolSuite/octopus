# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from octopus.android.device import AndroidDevice
from octopus.capture import AbstractCapture

logger = logging.getLogger(__name__)


class OnDeviceNetworkCapture(AbstractCapture):
    """Network capture performed directly on an Android device using tcpdump.

    This class manages the full lifecycle of an on-device network capture:
    installing tcpdump, running it via ADB, retrieving the resulting PCAP
    file, and cleaning up temporary files on the device.

    Attributes:
        device: The Android device on which the capture is performed.
        output_dir: Local directory where the PCAP file will be saved.
        output_filename: Name of the output PCAP file.
        output_path: Full local path to the output PCAP file.
        on_device_output_path: Full path to the PCAP file on the device.
        start_capture_time: Timestamp (ms) when the capture started.
        end_capture_time: Timestamp (ms) when the capture stopped.
    """

    def __init__(
        self,
        device: AndroidDevice,
        output_dir: Path,
        output_filename: Optional[str] = "traffic.pcap",
    ):
        """Initializes an OnDeviceNetworkCapture instance.

        Args:
            device: The Android device on which capture will run.
            output_dir: Local directory where the PCAP file will be saved.
            output_filename: Name of the output PCAP file. Defaults to
                ``traffic.pcap``.
        """
        self.device: AndroidDevice = device
        self.output_dir: Path = output_dir
        self.output_filename: str = output_filename
        if not self.output_filename.endswith(".pcap"):
            self.output_filename += ".pcap"
        self.output_path = output_dir / self.output_filename
        self.on_device_output_path = self.device.device_tmp_dir / self.output_filename
        self.start_capture_time: float = 0
        self.end_capture_time: float = 0

    def start_capture(self):
        """Starts the on-device network capture.

        Ensures the Frida server is running and tcpdump is installed on the
        device, then launches tcpdump via a non-blocking ADB shell command.
        ADB (port 5555) and Frida (port 27042) traffic is excluded from the
        capture to avoid noise. Records the start timestamp.

        Raises:
            Exception: If the ADB shell command fails to launch, the capture
                is stopped and the error is logged.
        """
        logger.info("Starting on device network capture...")
        self.device.start_frida_server(force_stop=False)
        self.device.install_tcpdump()
        self.start_capture_time = time.time() * 1000
        tcpdump_filter = "not \\(tcp port 5555 or tcp port 27042\\)"
        capture_cmd = f"{self.device.tcpdump_path} -U -i any -s 0 -w {self.on_device_output_path} '{tcpdump_filter}'"
        logger.debug(capture_cmd)
        try:
            self.device.adb_shell_no_wait(capture_cmd)
        except Exception as e:
            self.stop_capture()
            logger.error(e)
        return

    def stop_capture(self):
        """Stops the on-device network capture and retrieves the PCAP file.

        Sends a ``SIGKILL`` signal to the tcpdump process on the device via
        ``pkill``, waits briefly for the process to terminate, then pulls the
        PCAP file to the local output directory and removes the temporary file
        from the device. Records the end timestamp.

        Raises:
            Exception: Errors during process termination or file retrieval are
                caught and logged individually.
        """
        logger.info("Stopping on device network capture...")
        self.end_capture_time = time.time() * 1000
        try:
            self.device.adb_shell(f"pkill -f -l 9 {self.device.tcpdump_path}")
        except Exception as e:
            logger.error(e)
        time.sleep(2)
        try:
            logger.info("Retrieving the PCAP file from the device...")
            self.device.adb_shell(f"chmod 604 {self.on_device_output_path}")
            self.device.adb_pull(self.on_device_output_path, self.output_path)
            self.device.adb_shell(f"rm -f {self.on_device_output_path}")
        except Exception as e:
            logger.error(e)

    def get_output_file(self):
        """Returns the local path to the captured PCAP file.

        Returns:
            The :class:`~pathlib.Path` to the output PCAP file.
        """
        return self.output_path

    def get_result(self):
        """Returns a summary of the capture session.

        Returns:
            A dictionary with the following keys:

            - ``file``: output filename.
            - ``start_capture_time``: capture start timestamp in ms.
            - ``end_capture_time``: capture end timestamp in ms.
            - ``capture_duration``: total capture duration in ms.
        """
        return {
            "file": self.output_filename,
            "start_capture_time": self.start_capture_time,
            "end_capture_time": self.end_capture_time,
            "capture_duration": self.end_capture_time - self.start_capture_time,
        }


class NetworkCapture(AbstractCapture):
    """
    Network traffic capture class.

    This class provides functionality to capture network traffic using :textmono:`tcpdump`
    or a custom command. It manages the capture process, handles permissions, and stores the output in a PCAP file.

    Attributes:
        interface: The network interface to capture traffic from.
        tcpdump_path: Optional path to the tcpdump binary. If not provided, will attempt to locate it.
        capture_command: Optional custom capture command as a string. If provided, overrides the default command.
        output_path: Path to the output directory or file.
        output_filename: Name of the output file.
        start_capture_time: Timestamp when capture starts.
        end_capture_time: Timestamp when capture ends.

    Example:
        >>> from pathlib import Path # doctest: +SKIP
        >>> from octopus.capture.network import NetworkCapture
        >>> capture = NetworkCapture(interface="eth0", output_dir=Path("/tmp/"))
        >>> capture.start_capture() # doctest: +SKIP
        >>> capture.stop_capture() # doctest: +SKIP
        >>> print(capture.get_output_file())
        '/tmp/traffic.pcap'
    """

    name = "network"

    def __init__(
        self,
        interface: str,
        output_dir: Path,
        output_filename: Optional[str] = "traffic.pcap",
        tcpdump_path: Optional[Path] = None,
        capture_command: Optional[str] = None,
    ):
        """
        Initializes a NetworkCapture instance.

        Args:
            interface: The network interface to capture traffic from.
            output_dir: The directory where the output PCAP file will be stored.
            output_filename: The name of the output PCAP file. Defaults to :textmono:`traffic.pcap`.
            tcpdump_path: Optional path to the tcpdump binary. If not provided, will attempt to locate it.
            capture_command: Optional custom capture command as a string. If provided, overrides the default command.

        Raises:
            Exception: If the output filename is invalid or other initialization errors occur.
        """
        self.interface: str = interface
        self.output_filename: str = output_filename
        self.has_user_provided_cmd: bool = capture_command is not None
        self.start_capture_time: float = 0
        self.end_capture_time: float = 0

        if not self.output_filename.endswith(".pcap"):
            self.output_filename += ".pcap"

        if self.has_user_provided_cmd:
            self.capture_command = capture_command.split()
        else:
            if tcpdump_path is None:
                self.tcpdump_path = shutil.which("tcpdump")
            else:
                self.tcpdump_path = tcpdump_path
            self.capture_command = f"{self.tcpdump_path} -U -w - -i {self.interface}".split()

        self.output_path = output_dir / self.output_filename
        self.process = None

    def get_output_file(self) -> Path:
        """
        Returns the path to the output PCAP file.

        Returns:
            The path to the pcap file where captured network traffic is stored.
        """
        return self.output_path

    def get_result(self) -> dict:
        """
        Returns a dictionary with the capture result details.

        Returns:
            A dictionary containing the capture command, interface, output file name,
            start and end capture times, and capture duration in milliseconds.
        """
        return {
            "command": " ".join(self.capture_command),
            "interface": self.interface,
            "file": self.output_filename,
            "start_capture_time": self.start_capture_time,
            "end_capture_time": self.end_capture_time,
            "capture_duration": self.end_capture_time - self.start_capture_time,
        }

    def check_user_permissions(self):
        """
        Checks if the user has permission to capture network traffic.

        This method attempts to run a test :textmono:`tcpdump` command to verify that the
        current user has the necessary permissions to capture network traffic on
        the specified interface. If the user lacks permission, an exception is
        raised with instructions for granting the required rights.

        Raises:
            Exception: If the user does not have permission to capture network traffic.

        Notes:
            To grant your user's permission to capture network traffic, use:

              - Linux: :textmono:`sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump`
              - Mac OS: :textmono:`sudo chown <username>:admin /dev/bpf*`
        """
        try:
            subprocess.check_call(
                f"{self.tcpdump_path} -c 1 -i {self.interface}".split(),
                timeout=5,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            raise Exception(
                "You do not have the permission to dump network traffic. Re-run with sudo.\n"
                "Or, run the following command to grant your user the right to capture network traffic:\n"
                f"- Linux: sudo setcap cap_net_raw,cap_net_admin+eip {self.tcpdump_path}\n"
                f"- Mac OS: sudo chown <username>:admin /dev/bpf*"
            ) from e
        except (Exception,) as e:
            logger.error(e)

    def start_capture(self):
        """
        Starts the network capture process.

        Checks user permissions if needed and launches the capture process using
        the specified command. Records the start time of the capture. If an exception
        occurs during process startup, attempts to stop the process,
        logs the error, and re-raises the exception.

        Raises:
            Exception: If the capture process fails to start.
        """
        logger.info("Starting network interception...")
        logger.debug(f"Command: {self.capture_command}")
        self.start_capture_time = time.time() * 1000
        if not self.has_user_provided_cmd:
            self.check_user_permissions()
        try:
            self.process = subprocess.Popen(
                self.capture_command,
                stdout=self.output_path.open(mode="w"),
                stderr=subprocess.PIPE,
            )
        except (Exception,) as e:
            self.stop_capture()
            logger.error(e)
            raise e

    def stop_capture(self):
        """
        Stops the network capture process.

        This method sends a :textmono:`SIGINT` signal to the capture process to gracefully
        terminate it, waits briefly, then attempts to kill the process group and
        the process itself if it is still running.

        The end capture time is recorded.

        Raises:
            Exception: Any exception raised during the process termination is caught and suppressed.
        """
        logger.info("Stopping network interception...")
        self.end_capture_time = time.time() * 1000
        try:
            self.process.send_signal(signal.SIGINT)
            time.sleep(1)
            os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            self.process.kill()
        except (Exception,):
            pass
