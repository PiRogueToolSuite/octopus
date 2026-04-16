# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import time

from frida_tools.application import ConsoleApplication
from octopus.capture.manager import CaptureManager

log = logging.getLogger(__name__)


class FridaSingleInstrumentation(ConsoleApplication):
    SESSION_ID_LENGTH = 32
    MASTER_KEY_LENGTH = 48

    def __init__(self, frida_device, capture_manager):
        self.frida_device = frida_device
        self.capture_manager = capture_manager
        super(FridaSingleInstrumentation, self).__init__()

    def _add_options(self, parser):
        parser.add_argument(
            "--capture-command",
            help=(
                "Specify directly a capture command instead of building it from interface. "
                "Useful for remote capture over SSH. Example: "
                "ssh root@openwrt \"tcpdump -U -n -w - -i wlan0 'host PHONE_IP'\""
            ),
        )
        parser.add_argument("-o", "--output", help="The output directory")
        parser.add_argument("-i", "--iface", help="The network interface to capture", default=None)
        parser.add_argument(
            "--disable-screenrecord",
            action="store_false",
            help="Use to disable screen recording",
        )

    def _initialize(self, parser, options, args):
        self.capture_manager = CaptureManager(
            options.output,
            iface=options.iface,
            record_screen=options.disable_screenrecord,
        )
        self.capture_manager.start_capture(capture_cmd=options.capture_command)

    def _needs_target(self):
        return True

    def _start(self):
        self._output_files = {}
        self._update_status("Attached")

        self._script = self._session.create_script(self.capture_manager.get_agent_script())

        def on_message(message, data):
            self._reactor.schedule(lambda: self._on_message(message, data))

        self._script.on("message", on_message)
        self._session_cache = set()
        self._update_status("Loading script...")
        self._script.load()
        self._update_status("Loaded script")
        api = self._script.exports
        api.socket_trace("unknown", "unknown")
        try:
            api.log_aes_info("unknown", "unknown")
        except Exception:
            pass
        api.log_ad_ids()
        api.no_root()
        hook_definitions, success = self.capture_manager.get_dynamic_hooks_definitions()
        if success:
            api.inject_dynamic_hooks("unknown", "unknown", hook_definitions)
        self._update_status("Loaded script")
        self._resume()
        time.sleep(1)

    def _usage(self):
        return ""

    def save_data(self):
        self.capture_manager.stop_capture()

    def _on_message(self, message, data):
        data = message.get("payload")
        # Pass options to friTap hooks
        if data == "experimental":
            self._script.post({"type": "experimental", "payload": False})
            return
        if data == "defaultFD":
            self._script.post({"type": "defaultFD", "payload": False})
            return
        if data == "anti":
            self._script.post({"type": "antiroot", "payload": False})
            return
        # Received data from the Frida hooks
        if message["type"] == "send" and data:
            # Specific handling for friTap data
            if data.get("contentType", "") == "keylog":
                data["dump"] = "sslkeylog.txt"
                data["type"] = "sslkeylog"
                data["data"] = data.get("keylog")
            self.capture_manager.capture_data(data)
