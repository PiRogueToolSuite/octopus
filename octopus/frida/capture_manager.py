# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import os
import time
from importlib import resources
from pathlib import Path
from typing import List, Any

from octopus.android.device import AndroidDevice
from octopus.android.screen import ScreenRecorder
from octopus.network.packet_capture import TcpDump

logger = logging.getLogger(__name__)


class CaptureManager:
    def __init__(self, output_dir: Path, iface=None, record_screen=True):
        self.output_dir = output_dir
        self.dynamic_hook_dir = resources.files("octopus") / "frida-dynamic-hooks"
        self.frida_scripts_dir = resources.files("octopus") / "frida-scripts"
        self._output_files = {}
        self.captured_data = {}
        self.tcp_dump = None
        self.device = None
        self._js_script = None
        self.screen_recorder = None
        self.record_screen = record_screen
        default_iface = "wlan0"
        if iface:
            self.iface = iface
        else:
            self.iface = default_iface

    def start_capture(self, capture_cmd=None):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.tcp_dump = TcpDump(
            interface=self.iface,
            output_dir=self.output_dir,
            pcap_file_name="traffic.pcap",
            capture_cmd=capture_cmd,
        )
        self.device = AndroidDevice()
        if self.record_screen:
            self.screen_recorder = ScreenRecorder(self.device, self.output_dir)
        self.save_device_properties()
        device_capture_ts = time.time() * 1000
        # Prevent Zygote from pre-forking, Android >= 10 (API 29)
        if int(self.device.get_property("ro.build.version.sdk").strip()) >= 29:
            self.device.adb_shell("setprop persist.device_config.runtime_native.usap_pool_enabled false")
        self.device.start_frida_server()
        self.tcp_dump.start_capture()
        net_capture_ts = time.time() * 1000
        self.captured_data = {
            "network": {"start_capture_time": net_capture_ts, "file": "traffic.pcap"},
            "device": {"start_capture_time": device_capture_ts, "file": "device.json"},
            "socket_traces": {"file": "socket_trace.json"},
            "crypto_traces": {"file": "aes_info.json"},
            "sslkeylog": {"file": "sslkeylog.txt"},
        }
        if self.record_screen:
            self.screen_recorder.start_recording()
            screen_capture_ts = time.time() * 1000
            self.captured_data["screen"] = {
                "start_capture_time": screen_capture_ts,
                "file": "screen.mp4",
            }

    def get_dynamic_hooks_definitions(self):
        hook_definitions = []
        hook_files = [f for f in self.dynamic_hook_dir.iterdir() if f.name.endswith(".json")]
        if len(hook_files) == 0:
            return hook_definitions, False
        for hook_file in hook_files:
            with hook_file.open("r") as file:
                hook_definitions.extend(json.load(file))
        return hook_definitions, True

    def get_agent_script(self, extra_scripts_dir: Path = None):
        if self._js_script:
            return self._js_script

        self._js_script = ""
        # List the default scripts
        js_files: List[Any] = [f for f in self.frida_scripts_dir.iterdir() if f.name.endswith(".js")]
        # List the extra scripts
        if extra_scripts_dir:
            other_files: List[Any] = [f for f in extra_scripts_dir.iterdir() if f.name.endswith(".js")]
            js_files.extend(other_files)
        # Load the content of the scripts
        for js_file in js_files:
            self._js_script += js_file.read_text()
        # Write the script to a file for debugging
        with open("/tmp/script.js", "w") as f:
            f.write(self._js_script)

        return self._js_script

    def capture_data(self, data):
        # Redirection of console.log()
        if data.get("contentType", "") == "console":
            message = data.get("console")
            logger.debug(f"{message}")
        if data.get("contentType", "") == "console_dev":
            message = data.get("console_dev")
            logger.debug(f"{message}")
        # Save the data that comes from frida
        output_file = data.get("dump")
        if output_file is None:
            return
        if output_file not in self._output_files:
            self._output_files[output_file] = []
        if output_type := data.get("type"):
            self.captured_data[output_type] = {"file": output_file}
        self._output_files[output_file].append(data)

    def save_device_properties(self):
        props = self.device.get_device_properties()
        logger.info("Saving device properties")
        logger.info(props)
        with open(f"{self.output_dir}/device.json", mode="w") as out:
            json.dump(props, out, indent=2)

    def save_data_files(self):
        logger.info("Saving the data captured by Frida")
        for filename, elt in self._output_files.items():
            if len(elt) == 0:
                with open(f"{self.output_dir}/{filename}", mode="w") as out:
                    out.write("[]")
            data_type = elt[0].get("data_type")
            with open(f"{self.output_dir}/{filename}", mode="w") as out:
                if data_type == "json":
                    json.dump(elt, out, indent=2)
                else:
                    for record in elt:
                        data = record.get("data")
                        out.write(f"{data}\n")
        # Save the details of the experiment
        with open(f"{self.output_dir}/experiment.json", mode="w") as out:
            json.dump(self.captured_data, out, indent=2)

    def stop_capture(self):
        self.save_data_files()
        if self.record_screen:
            self.screen_recorder.stop_recording()
        self.device.stop_frida_server()
        self.tcp_dump.stop_capture()
