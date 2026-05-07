# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import signal
import threading
import time

from octopus.android.device import AndroidDeviceUsb, AndroidDeviceTcp
from octopus.capture.manager import CaptureManager


def common(device, output_path, no_screen_record, no_network_capture, no_instrumentation, duration, overwrite):
    """Run the capture session for a given device.

    Sets up signal handlers for graceful shutdown, initializes the
    :class:`~octopus.capture.manager.CaptureManager`, and runs the
    capture session for the specified duration or until interrupted.

    Args:
        device: The Android device instance to capture from.
        output_path: Path to the directory where output will be saved.
        no_screen_record: If True, disables screen recording.
        no_network_capture: If True, disables network traffic capture.
        no_instrumentation: If True, disables app instrumentation.
        duration: Duration in seconds to run the capture. If 0 or less,
            runs until a stop signal is received.
        overwrite: If True, allows overwriting existing output files.
    """
    stop_event = threading.Event()

    def _handle_stop(signum: int, frame) -> None:
        """Handle OS stop signals by setting the stop event."""
        stop_event.set()

    # Register signal handlers for graceful shutdown on SIGINT and SIGTERM
    signal.signal(signal.SIGINT, _handle_stop)
    signal.signal(signal.SIGTERM, _handle_stop)

    capture_manager = CaptureManager(
        device, output_path, no_screen_record, no_network_capture, no_instrumentation, overwrite
    )

    # Abort early if the capture manager failed to initialize
    if not capture_manager.ready:
        return

    capture_manager.start()

    if duration > 0:
        # Run for the specified duration, then signal stop
        time.sleep(duration)
        stop_event.set()
    else:
        # Wait indefinitely until a stop signal is received
        stop_event.wait()

    capture_manager.stop()


def usb_mode(
    adb_host,
    adb_port,
    device_id,
    output_path,
    no_screen_record,
    no_network_capture,
    no_instrumentation,
    duration,
    overwrite,
):
    """Start a capture session using a USB-connected Android device.

    Creates an :class:`~octopus.android.device.AndroidDeviceUsb` instance
    and delegates to :func:`common` to run the capture session.

    Args:
        adb_host: Hostname or IP address of the ADB server.
        adb_port: Port number of the ADB server.
        device_id: The serial ID of the USB-connected Android device.
        output_path: Path to the directory where output will be saved.
        no_screen_record: If True, disables screen recording.
        no_network_capture: If True, disables network traffic capture.
        no_instrumentation: If True, disables app instrumentation.
        duration: Duration in seconds to run the capture. If 0 or less,
            runs until a stop signal is received.
        overwrite: If True, allows overwriting existing output files.
    """
    device = AndroidDeviceUsb(device_id, adb_host, adb_port)
    common(device, output_path, no_screen_record, no_network_capture, no_instrumentation, duration, overwrite)


def tcp_mode(
    adb_host,
    adb_port,
    device_host,
    device_port,
    output_path,
    no_screen_record,
    no_network_capture,
    no_instrumentation,
    duration,
    overwrite,
):
    """Start a capture session using a TCP-connected Android device.

    Creates an :class:`~octopus.android.device.AndroidDeviceTcp` instance
    and delegates to :func:`common` to run the capture session.

    Args:
        adb_host: Hostname or IP address of the ADB server.
        adb_port: Port number of the ADB server.
        device_host: Hostname or IP address of the Android device.
        device_port: Port number used to connect to the Android device.
        output_path: Path to the directory where output will be saved.
        no_screen_record: If True, disables screen recording.
        no_network_capture: If True, disables network traffic capture.
        no_instrumentation: If True, disables app instrumentation.
        duration: Duration in seconds to run the capture. If 0 or less,
            runs until a stop signal is received.
        overwrite: If True, allows overwriting existing output files.
    """
    device = AndroidDeviceTcp(device_host, device_port, adb_host, adb_port)
    common(device, output_path, no_screen_record, no_network_capture, no_instrumentation, duration, overwrite)
