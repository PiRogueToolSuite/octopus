# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import time
from pathlib import Path
from typing import Optional

from octopus.android.device import AndroidDevice
from octopus.capture import AbstractCapture

logger = logging.getLogger(__name__)


class DevicePropertiesCapture(AbstractCapture):
    """
    Class to capture and save device properties.
    """

    name = "device"
    """The name of the capture type."""

    def __init__(
        self,
        device: AndroidDevice,
        output_dir: Path,
        output_filename: Optional[str] = "device.json",
    ):
        """
        Initializes the capture of device properties.

        Args:
            device: Instance of AndroidDevice to capture properties from.
            output_dir: Directory to save the output file.
            output_filename: Name of the `output file`, defaults to :textmono:`device.json`.
        """
        self.device: AndroidDevice = device
        self.output_filename: str = output_filename
        self.output_file: Path = output_dir / self.output_filename
        self.start_capture_time: float = 0
        self.end_capture_time: float = 0

    def get_output_file(self) -> Path:
        """
        Returns the full path to the output file.

        Returns:
            The output file path.
        """
        return self.output_file

    def get_result(self) -> dict:
        """
        Returns a dictionary with capture result details.

        Returns:
            Dictionary containing file name, start/end times, and capture duration.
        """
        return {
            "file": self.output_filename,
            "start_capture_time": self.start_capture_time,
            "end_capture_time": self.end_capture_time,
            "capture_duration": self.end_capture_time - self.start_capture_time,
        }

    def start_capture(self):
        """
        Starts the device properties capture process.

        This method records the start time, retrieves device properties using the
        :py:obj:`~octopus.android.device.AndroidDevice` instance, and saves them to the output file
        in JSON format. The end time is recorded after saving.
        """
        logger.info("Saving device properties")
        self.start_capture_time = time.time() * 1000
        props = self.device.get_device_properties()
        logger.debug(props)
        with self.output_file.open(mode="w") as out:
            json.dump(props, out, indent=2)
        self.end_capture_time = time.time() * 1000

    def stop_capture(self):
        """
        Does nothing
        """
        pass
