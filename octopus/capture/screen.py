# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time
from pathlib import Path
from typing import Optional

from octopus.android.device import AndroidDevice
from octopus.capture import AbstractCapture

logger = logging.getLogger(__name__)


class ScreenCapture(AbstractCapture):
    """
    ScreenCapture handles screen recording on an Android device.

    This class provides methods to start and stop screen recording
    and to retrieve the recorded file from the device.

    Attributes:
        device: The Android device to capture from.
        output_filename: Name of the output file.
        output_path: Path to the output directory or file.
        start_capture_time: Timestamp when capture starts.
        end_capture_time: Timestamp when capture ends.
    """

    name = "screen"
    """The name identifier for this capture type."""

    path_on_device = "/data/local/tmp/screen.mp4"
    """The file path on the device where the recording is stored."""

    def __init__(
        self,
        device: AndroidDevice,
        output_dir: Path,
        output_filename: Optional[str] = "screen.mp4",
    ):
        """
        Initializes ScreenCapture with device and output settings.

        Args:
            device: Instance of :class:`~octopus.android.device.AndroidDevice`.
            output_dir: Directory to store the output file.
            output_filename: Name of the output file (default: "screen.mp4").

        Sets up the output path and initializes capture timestamps.
        """
        self.device: AndroidDevice = device
        self.output_filename: str = output_filename
        self.output_path: Path = output_dir / self.output_filename
        self.start_capture_time: float = 0
        self.end_capture_time: float = 0

    def get_output_file(self) -> Path:
        """
        Returns the path to the output file.

        Returns:
            The path to the screen recording file.
        """
        return self.output_path

    def get_result(self) -> dict:
        """
        Returns a dictionary with capture result details.

        Returns:
            A dictionary containing the output file name, start and end capture times, and
            capture duration in milliseconds.
        """
        return {
            "file": self.output_filename,
            "start_capture_time": self.start_capture_time,
            "end_capture_time": self.end_capture_time,
            "capture_duration": self.end_capture_time - self.start_capture_time,
        }

    def start_capture(self):
        """
        Starts screen recording on the Android device.

        This method initiates the screen recording process using the
        :textmono:`screenrecord` command via ADB. The start timestamp is recorded
        in milliseconds.

        Raises:
            Exception: If the screen recording fails to start.

        Notes:
            The command :textmono:`screenrecord` limits the capture duration to 3 minutes.
        """
        logger.info("Starting screen recording...")
        self.start_capture_time = time.time() * 1000
        capture_cmd = f"screenrecord --bugreport --size 1280x720 --bit-rate 2000000 {self.path_on_device}"
        try:
            self.device.adb_shell_no_wait(capture_cmd)
        except Exception as e:
            self.stop_capture()
            logger.error(e)
        return

    def stop_capture(self):
        """
        Stops screen recording and retrieves the recorded file.

        This method sends a :textmono:`SIGINT` to terminate the screen recording,
        waits for the process to finish, and then pulls the recorded
        file from the device. The end timestamp is recorded in
        milliseconds.

        Handles exceptions during stopping and file retrieval.
        """
        logger.info("Stopping screen recording...")
        self.end_capture_time = time.time() * 1000
        try:
            self.device.adb_shell("pkill -SIGINT screenrecord")
        except Exception as e:
            logger.error(e)
        time.sleep(2)
        try:
            logger.info("Retrieving the screencast from the device...")
            self.device.adb_shell(f"chmod 604 {self.path_on_device}")
            self.device.adb_pull(self.path_on_device, self.output_path)
            self.device.adb_shell(f"rm -f {self.path_on_device}")
        except Exception as e:
            logger.error(e)
