# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import threading
from threading import Thread

logger = logging.getLogger(__name__)


def on_spawned(spawn: object) -> None:
    """Handle a newly spawned process detected by Frida's spawn gating.

    Appends the spawn to the pending list and signals the instrumentation
    thread to process it.

    Args:
        spawn: The spawn object provided by Frida containing process info.
    """
    logger.info(f"New process spawned {spawn}")
    FridaGatedInstrumentation.pending.append(spawn)
    FridaGatedInstrumentation.event.set()


def on_message(
    capture_manager: object,
    spawn: object,
    message: dict,
    script: object,
) -> None:
    """Handle messages received from an injected Frida script.

    Processes control messages (e.g. offset_hooking, pattern_hooking) by
    posting the appropriate response back to the script. Captures data
    payloads via the capture manager, with special handling for friTap
    SSL keylog data.

    Args:
        capture_manager: Manager responsible for capturing and storing data.
        spawn: The spawn object associated with the instrumented process.
        message: The message dict received from the Frida script.
        script: The Frida script instance used to post responses.
    """
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
    """Thread that manages Frida-based gated instrumentation of spawned processes.

    Uses Frida's spawn gating mechanism to intercept newly spawned processes,
    attach to them, inject an agent script, and invoke tracing APIs before
    resuming execution.

    Attributes:
        pending: List of spawned processes waiting to be instrumented.
        sessions: List of active Frida sessions for instrumented processes.
        scripts: List of loaded Frida scripts for instrumented processes.
        event: Threading event used to signal new pending spawns.
    """

    pending = []
    """List of spawned processes pending instrumentation."""

    sessions = []
    """List of active Frida attach sessions."""

    scripts = []
    """List of loaded Frida script instances."""

    event = threading.Event()
    """Event signaled when a new spawn is added to the pending list."""

    def __init__(self, frida_device: object, capture_manager: object) -> None:
        """Initialize the instrumentation thread.

        Args:
            frida_device: The Frida device to attach and enable spawn gating on.
            capture_manager: Manager responsible for capturing intercepted data.
        """
        super().__init__()
        self.daemon = True
        self.frida_device = frida_device
        self.capture_manager = capture_manager
        self._stop = False

    def run(self) -> None:
        """Entry point for the instrumentation thread.

        Delegates to :meth:`start_instrumentation`.
        """
        self.start_instrumentation()

    def stop(self) -> None:
        """Signal the instrumentation loop to stop gracefully."""
        self._stop = True

    def start_instrumentation(self) -> None:
        """Enable spawn gating and instrument each intercepted process.

        Enables Frida spawn gating on the target device, then enters a loop
        waiting for new spawns. For each spawn with a known identifier, it
        attaches a Frida session, loads the agent script, invokes available
        tracing APIs, and resumes the process.
        """
        self.frida_device.enable_spawn_gating()
        self.frida_device.on("spawn-added", on_spawned)

        FridaGatedInstrumentation.event = threading.Event()

        logger.info("Enabled spawn gating")
        # Resume any processes that were already pending before gating started
        for spawn in self.frida_device.enumerate_pending_spawn():
            self.frida_device.resume(spawn.pid)

        while True:
            # Block until a new spawn is signaled or the stop flag is set
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

                # Invoke each tracing API independently; failures are non-fatal
                try:
                    api.socket_trace(spawn.pid, spawn.identifier)
                except (Exception,):
                    pass
                try:
                    api.log_aes_info(spawn.pid, spawn.identifier)
                except (Exception,):
                    pass
                try:
                    api.log_ad_ids()
                except (Exception,):
                    pass
                try:
                    api.no_root()
                except (Exception,):
                    pass

                # Inject dynamic hooks if definitions are available
                hook_definitions, success = self.capture_manager.get_dynamic_hooks_definitions()
                if success:
                    try:
                        api.inject_dynamic_hooks(spawn.pid, spawn.identifier, hook_definitions)
                    except (Exception,):
                        pass

                FridaGatedInstrumentation.sessions.append(session)
                FridaGatedInstrumentation.scripts.append(script)
            self.frida_device.resume(spawn.pid)
