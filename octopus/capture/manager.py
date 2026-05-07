# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import shutil
from pathlib import Path
from typing import Optional

from octopus.android.device import AndroidDevice
from octopus.capture.device import DevicePropertiesCapture
from octopus.capture.frida import FridaCapture
from octopus.capture.network import OnDeviceNetworkCapture
from octopus.capture.screen import ScreenCapture

logger = logging.getLogger(__name__)


class CaptureManager:
    def __init__(
        self,
        device: AndroidDevice,
        output_path: Path,
        no_screen_record: bool,
        no_network_capture: bool,
        no_instrumentation: bool,
        overwrite: bool,
    ) -> None:
        self.device = device
        self.output_path = output_path
        self.no_screen_record = no_screen_record
        self.no_network_capture = no_network_capture
        self.no_instrumentation = no_instrumentation
        self.device_properties: Optional[DevicePropertiesCapture] = None
        self.network_capture: Optional[OnDeviceNetworkCapture] = None
        self.frida_instrumentation: Optional[FridaCapture] = None
        self.screen_recording: Optional[ScreenCapture] = None
        self.overwrite = overwrite
        self.ready = False
        self.__init()

    def __init(self) -> None:
        """Initialize the capture manager components.

        Sets up the output directory and initializes capture components
        based on the provided configuration flags. If the output path
        already exists and contains files, initialization will abort
        unless the overwrite flag is set.

        Args:
            self: The CaptureManager instance.

        Note:
            Sets :attr:`ready` to ``True`` only if initialization
            succeeds. Each capture component is conditionally
            instantiated based on the corresponding ``no_*`` flags.
        """
        if self.output_path.is_dir() and any(self.output_path.iterdir()) and not self.overwrite:
            logger.error("Output path already contains files, use -w option to overwrite the output directory")
            return

        # Remove the existing output directory if overwrite is requested.
        if self.overwrite:
            shutil.rmtree(self.output_path, ignore_errors=True)

        self.output_path.mkdir(parents=True, exist_ok=True)

        self.ready = True

        # Always capture device properties.
        self.device_properties = DevicePropertiesCapture(self.device, self.output_path)
        # Conditionally initialize network capture.
        if not self.no_network_capture:
            self.network_capture = OnDeviceNetworkCapture(self.device, self.output_path)
        # Conditionally initialize Frida instrumentation.
        if not self.no_instrumentation:
            self.frida_instrumentation = FridaCapture(self.device, self.output_path)
        # Conditionally initialize screen recording.
        if not self.no_screen_record:
            self.screen_recording = ScreenCapture(self.device, self.output_path)

    def start(self) -> None:
        """Start all enabled capture components.

        Iterates over each initialized capture component and calls
        :meth:`start_capture`. Components that were disabled via
        ``no_*`` flags will be ``None`` and are safely skipped.

        Args:
            self: The CaptureManager instance.

        Note:
            Does nothing if :attr:`ready` is ``False``.
        """
        if not self.ready:
            return

        self.device_properties.start_capture()

        if self.network_capture:
            self.network_capture.start_capture()
        if self.frida_instrumentation:
            self.frida_instrumentation.start_capture()
        if self.screen_recording:
            self.screen_recording.start_capture()

    def stop(self) -> None:
        """Stop all enabled capture components and save results.

        Stops each initialized capture component, collects their results
        into a dictionary, and writes the aggregated experiment data to
        ``experiment.json`` in the output directory.

        Note:
            Does nothing if :attr:`ready` is ``False``. Components that
            were disabled via ``no_*`` flags are safely skipped.
        """
        if not self.ready:
            return

        experiment_data = {}

        # Stop device properties capture and store result.
        self.device_properties.stop_capture()
        experiment_data["device"] = self.device_properties.get_result()

        # Stop network capture and store the result if enabled.
        if self.network_capture:
            self.network_capture.stop_capture()
            experiment_data["network"] = self.network_capture.get_result()

        # Stop Frida instrumentation and merge the result if enabled.
        if self.frida_instrumentation:
            self.frida_instrumentation.stop_capture()
            experiment_data.update(self.frida_instrumentation.get_result())

        # Stop screen recording and store the result if enabled.
        if self.screen_recording:
            self.screen_recording.stop_capture()
            experiment_data["screen"] = self.screen_recording.get_result()

        # Write all collected experiment data to a JSON file.
        with open(self.output_path.joinpath("experiment.json"), "w") as outfile:
            json.dump(experiment_data, outfile, indent=2)
