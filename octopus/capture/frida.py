# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from importlib import resources
from pathlib import Path
from typing import List, Any

from octopus.android.device import AndroidDevice
from octopus.capture import AbstractCapture
from octopus.frida.instrument_gated import FridaGatedInstrumentation

logger = logging.getLogger(__name__)


class FridaCapture(AbstractCapture):
    """Captures data from an Android device using Frida instrumentation.

    Manages Frida scripts, dynamic hooks, and data collection during
    an instrumentation session on a connected Android device.

    Attributes:
        device: The Android device to instrument.
        output_dir: Directory where captured data files are saved.
        gated: Whether to use gated instrumentation.
        debug: Whether to enable debug mode (e.g., write the agent script to disk).
        dynamic_hook_dir: Path to the directory containing dynamic hook
            JSON definitions.
        frida_scripts_dir: Path to the directory containing Frida JS scripts.
        output_files: Mapping of output filenames to their captured records.
        captured_data: Mapping of data types to their output file metadata.
        agent_script: The concatenated Frida agent JS script content.
        frida_instrumentation: The :class:`~octopus.frida.instrument_gated\
.FridaGatedInstrumentation` instance managing the Frida session.
    """

    name = "frida"

    def __init__(
        self,
        device: AndroidDevice,
        output_dir: Path,
        gated: bool = True,
        debug: bool = False,
    ):
        """Initializes FridaCapture with device and output configuration.

        Args:
            device: The Android device to capture data from.
            output_dir: Directory path where output files will be written.
            gated: Whether to use gated instrumentation mode.
                Defaults to True.
            debug: Whether to enable debug output, such as writing the
                agent script to a temporary file. Defaults to False.
        """
        self.device: AndroidDevice = device
        self.output_dir: Path = output_dir
        self.gated: bool = gated
        self.debug: bool = debug
        self.dynamic_hook_dir = resources.files("octopus") / "frida-dynamic-hooks"
        self.frida_scripts_dir = resources.files("octopus") / "frida-scripts"
        self.output_files = {}
        self.captured_data = {}
        self.agent_script = ""
        self.frida_instrumentation = FridaGatedInstrumentation(self.device.get_frida_device(), self)

    def get_dynamic_hooks_definitions(self):
        """Loads all dynamic hook definitions from JSON files.

        Iterates over all ``.json`` files in the dynamic hooks directory
        and aggregates their contents into a single list.

        Returns:
            A tuple of (hook_definitions, success) where hook_definitions
            is a list of hook definition dicts and success is False if no
            hook files were found, True otherwise.
        """
        hook_definitions = []
        hook_files = [f for f in self.dynamic_hook_dir.iterdir() if f.name.endswith(".json")]
        if len(hook_files) == 0:
            return hook_definitions, False
        for hook_file in hook_files:
            with hook_file.open("r") as file:
                hook_definitions.extend(json.load(file))
        return hook_definitions, True

    def get_agent_script(
        self,
        extra_scripts_dir: Path = None,
        reload: bool = False,
    ):
        """Builds and returns the concatenated Frida agent JS script.

        Reads all ``.js`` files from the default Frida scripts directory
        and optionally from an additional directory. The result is cached
        in ``self.agent_script`` and can be reloaded by setting
        ``reload=True``.

        When debug mode is enabled, the assembled script is also written
        to ``/tmp/octopus_agent.js`` for inspection.

        Args:
            extra_scripts_dir: Optional path to a directory containing
                additional JS scripts to append to the agent.
            reload: If True, forces regeneration of the script even if
                it was previously built. Defaults to False.

        Returns:
            The full Frida agent script as a string.
        """
        # Return the cached script unless a reload is explicitly requested
        if self.agent_script and not reload:
            return self.agent_script

        self.agent_script = ""

        # List the default scripts
        js_files: List[Any] = [f for f in self.frida_scripts_dir.iterdir() if f.name.endswith(".js")]

        # List the extra scripts
        if extra_scripts_dir:
            other_files: List[Any] = [f for f in extra_scripts_dir.iterdir() if f.name.endswith(".js")]
            js_files.extend(other_files)

        # Load the content of the scripts
        for js_file in js_files:
            logger.info(f"Loading {js_file}")
            with js_file.open("r", encoding="utf-8", newline="\n") as js:
                self.agent_script += js.read()

        # Write the script to a file for debugging
        if self.debug or True:
            agent_script_path = Path("/tmp/octopus_agent.js")
            logger.debug(f"Writing agent script to {agent_script_path} for debugging")
            with agent_script_path.open(mode="w") as f:
                f.write(self.agent_script)

        return self.agent_script

    def capture_data(self, data):
        """Processes and stores a single data record received from Frida.

        Handles console log messages for debug output and accumulates
        data records into ``self.output_files`` keyed by their target
        filename. Records without a ``dump`` field are ignored.

        Args:
            data: A dict payload sent by the Frida agent, expected to
                contain keys such as ``contentType``, ``dump``,
                ``type``, and ``data``.
        """
        logger.debug("Capturing data")
        logger.debug(data)
        logger.debug("Capturing data")

        # Log console messages emitted by the Frida agent
        message = None
        if data.get("contentType", "") == "console":
            message = data.get("console")
        if data.get("contentType", "") == "console_dev":
            message = data.get("console_dev")
        if message:
            logger.debug(message)

        # Capture data sent by Frida; skip records without a target file
        output_file = data.get("dump")
        if output_file is None:
            return
        if output_file not in self.output_files:
            self.output_files[output_file] = []
        if output_type := data.get("type"):
            self.captured_data[output_type] = {"file": output_file}
        self.output_files[output_file].append(data)

    def save_data_files(self):
        """Writes all captured data records to their respective output files.

        Iterates over ``self.output_files`` and serializes each collection
        of records. JSON records are pretty-printed; other records are
        written one per line using their ``data`` field. An
        ``experiment.json`` summary file is also written to the output
        directory.
        """
        logger.info("Saving the data captured by Frida")
        for filename, elt in self.output_files.items():
            # Write an empty JSON array for files with no records
            if len(elt) == 0:
                with open(f"{self.output_dir}/{filename}", mode="w") as out:
                    out.write("[]")
            data_type = elt[0].get("data_type")
            with open(f"{self.output_dir}/{filename}", mode="w") as out:
                if data_type == "json":
                    json.dump(elt, out, indent=2)
                else:
                    # Write plain-text records one per line
                    for record in elt:
                        data = record.get("data")
                        out.write(f"{data}\n")

        # Save the details of the experiment
        with open(f"{self.output_dir}/experiment.json", mode="w") as out:
            json.dump(self.captured_data, out, indent=2)

    def start_capture(self):
        """Starts the Frida capture session on the device.

        Disables USAP pool pre-forking on Android 10+ (API 29) to ensure
        Frida can attach correctly, starts the Frida server on the device,
        and begins instrumentation.
        """
        # Prevent Zygote from pre-forking, Android >= 10 (API 29)
        if int(self.device.get_property("ro.build.version.sdk").strip()) >= 29:
            self.device.adb_shell("setprop persist.device_config.runtime_native.usap_pool_enabled false")
        self.device.start_frida_server(force_stop=False)
        self.frida_instrumentation.start()

    def stop_capture(self):
        """Stops the Frida capture session and persists collected data.

        Stops the instrumentation, shuts down the Frida server on the
        device, and flushes all captured data to disk with :meth:`save_data_files`.
        """
        self.frida_instrumentation.stop()
        self.device.stop_frida_server()
        self.save_data_files()

    def get_result(self) -> dict:
        """Not applicable for Frida captures.

        Raises:
            Exception: Always raised as this method is not applicable
                for this capture type.
        """
        raise Exception("Not applicable")

    def get_output_file(self) -> Path:
        """Not applicable for Frida captures.

        Raises:
            Exception: Always raised as this method is not applicable
                for this capture type.
        """
        raise Exception("Not applicable")
