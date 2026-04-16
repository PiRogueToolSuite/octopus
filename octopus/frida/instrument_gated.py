# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import threading
from threading import Thread

logger = logging.getLogger(__name__)


def on_spawned(spawn):
    logger.info(f"New process spwaned {spawn}")
    FridaGatedInstrumentation.pending.append(spawn)
    FridaGatedInstrumentation.event.set()


def on_message(capture_manager, spawn, message, script):
    if message["type"] == "error":
        logger.debug(message.get("description", message))
        return
    if message["type"] == "send":
        payload = message.get("payload", {})
        if payload == "offset_hooking":
            script.post({"type": "offset_hooking", "payload": None})
            return
        if payload == "pattern_hooking":
            script.post({"type": "pattern_hooking", "payload": None})
            return
        if payload == "socket_tracing":
            script.post({"type": "socket_tracing", "payload": False})
            return
        if payload == "defaultFD":
            script.post({"type": "defaultFD", "payload": False})
            return
        if payload == "experimental":
            script.post({"type": "experimental", "payload": False})
            return
        if payload == "anti":
            script.post({"type": "antiroot", "payload": True})
            return
        if payload == "install_lsass_hook":
            script.post({"type": "install_lsass_hook", "payload": False})
            return
        # Received data from the Frida hooks
        # Specific handling for friTap data
        if payload.get("contentType", "") == "keylog":
            payload["dump"] = "sslkeylog.txt"
            payload["type"] = "sslkeylog"
            payload["data"] = payload.get("keylog")
        logger.debug(payload)
        capture_manager.capture_data(payload)


class FridaGatedInstrumentation(Thread):
    pending = []
    sessions = []
    scripts = []
    event = threading.Event()

    def __init__(self, frida_device, capture_manager):
        super().__init__()
        self.daemon = True
        self.frida_device = frida_device
        self.capture_manager = capture_manager
        self._stop = False

    def run(self):
        self.start_instrumentation()

    def stop(self):
        self._stop = True

    def start_instrumentation(self):
        self.frida_device.enable_spawn_gating()
        self.frida_device.on("spawn-added", on_spawned)

        FridaGatedInstrumentation.event = threading.Event()

        logger.info("Enabled spawn gating")
        for spawn in self.frida_device.enumerate_pending_spawn():
            self.frida_device.resume(spawn.pid)

        while True:
            while len(FridaGatedInstrumentation.pending) == 0:
                logger.info("Waiting for data")
                FridaGatedInstrumentation.event.wait(timeout=2)
                if self._stop:
                    return
                FridaGatedInstrumentation.event.clear()

            spawn = FridaGatedInstrumentation.pending.pop()
            if spawn.identifier:
                logger.info(f"Instrumenting {spawn}")
                session = self.frida_device.attach(spawn.pid)
                script = session.create_script(self.capture_manager.get_agent_script(), runtime="qjs")
                script.on(
                    "message",
                    lambda message, data: on_message(self.capture_manager, spawn, message, script),
                )
                script.load()
                api = script.exports
                logger.debug(f"API: {dir(api)}")
                api.socket_trace(spawn.pid, spawn.identifier)
                api.log_aes_info(spawn.pid, spawn.identifier)
                api.log_ad_ids()
                api.no_root()
                hook_definitions, success = self.capture_manager.get_dynamic_hooks_definitions()
                if success:
                    api.inject_dynamic_hooks(spawn.pid, spawn.identifier, hook_definitions)
                FridaGatedInstrumentation.sessions.append(session)
                FridaGatedInstrumentation.scripts.append(script)
            self.frida_device.resume(spawn.pid)
