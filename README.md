<!--
SPDX-FileCopyrightText: 2026 Defensive Lab Agency
SPDX-FileContributor: u039b <git@0x39b.fr>

SPDX-License-Identifier: GPL-3.0-or-later
-->

<div align="center">
<img width="60px" src="https://pts-project.org/android-chrome-512x512.png">
<h1>Octopus</h1>
<p>
Dynamic analysis framework for Android apps.
</p>
<p>
<img src="https://img.shields.io/badge/License-GPL_v3-8A2BE2">
</p>
<p>
<a href="https://pts-project.org">Website</a> |
<a href="https://pts-project.org/octopus/">Documentation</a> |
<a href="https://github.com/PiRogueToolSuite/octopus">GitHub</a> |
<a href="https://discord.gg/qGX73GYNdp">Support</a>
</p>
</div>

# Octopus
Octopus is a dynamic analysis framework for Android applications, part of the
[PiRogue Tool Suite](https://pts-project.org). It instruments Android app behavior
using [Frida](https://frida.re) and provides the following capabilities:

* Screen recording
* Full network capture (on device)
* TLS interception with [friTap](https://github.com/fkie-cad/friTap)
* Socket operations tracing
* Cryptographic operations logging

Octopus communicates with a running `adb-server`, either locally or remotely.
The target device can be a physical Android phone or an emulator, accessible
via USB or TCP.

## Requirements
* **Python** 3.11 or newer
* A **rooted** Android device (emulator, phone, or tablet)

## Installation
```bash
pip install pirogue-octopus
```

## Usage
The main entry point is the `octopus` CLI.

```bash
# List available Android devices (local only)
octopus device list

# Start instrumentation over USB
octopus instrument usb

# Start instrumentation over network
octopus instrument tcp --device-host <DEVICE_IP>
```

Octopus instruments processes when they spawn. To instrument an application, start `octopus` then launch the application 
to be analyzed when Octopus is *Waiting for data*. Press `CTRL + C` to stop.

Common options for `instrument`:
* `-o, --output-path`: directory to save capture results (default: `./output`).
* `-d, --device-id`: serial number of the device connected to ADB (USB mode only).
* `-ns, --no-screen-record`: disable screen recording.
* `-ni, --no-instrumentation`: disable Frida instrumentation.
* `-nn, --no-network-capture`: disable network capture.
* `--duration`: capture duration in seconds to wait before it's automatically stopped (default: unlimited).
* `-w, --overwrite`: to overwrite the output files

### Outputs
* `ad_ids.txt`: the list of Android Advertising IDs 
* `device.json`: the list of device properties (*e.g.* IMEI, brand, fingerprint)
* `dynamic_hook.json`: the output of dynamically injected hooks
* `experiment.json`: the summary and timings of the capture and instrumentation
* `screen.mp4`: the screen recording
* `socket_trace.json`: the trace of every operation on sockets
* `sslkeylog.txt`: the list of TLS client randoms
* `traffic.pcap`: the network capture

### Remote ADB server
The following options let you specify the ADB server to use:
* `-ah, --adb-host`: ADB server IP address (default: `127.0.0.1`)
* `-ap, --adb-port`: ADB server port (default: `5037`)

```bash
octopus device list --adb-host 127.0.0.1 --adb-port 5037
```

### Remote Android device
The following options let you specify the device to use:
* `-dh, --device-host`: device IP address
* `-dp, --device-port`: device port (default: `5555`)

**ADB over network** must be enabled.

```bash
octopus instrument tcp --device-host <DEVICE_IP>
```

## Development
It is recommended to use [uv](https://github.com/astral-sh/uv) for managing the Python environment.

1.  Clone the repository:
    ```bash
    git clone https://github.com/PiRogueToolSuite/octopus.git
    cd octopus
    ```

2.  Install Python dependencies:
    ```bash
    uv sync
    ```

3.  Install Node.js dependencies and build Frida agents:
    ```bash
    npm install
    npm run build
    ```
    
### Scripts
The project uses `tox` for automation:
* `tox -e fix`: Format code using Ruff and run pre-commit hooks.
* `tox -e docs`: Generate HTML documentation.

Frida agent development:
* `npm run build`: Compile TypeScript agent to JavaScript.
* `npm run watch`: Continuously compile agent on changes.

### Project Structure
* `octopus/`: Core Python package.
  * `capture/`: Modules for device, network, screen, and Frida management.
  * `commands/`: CLI command definitions.
  * `frida/`: Frida instrumentation logic.
* `frida-scripts-src/`: TypeScript source for Frida agents.
* `debian/`: Debian packaging configuration.

## License
This project is licensed under the **GPL-3.0-or-later**. See the LICENSES directory for details.
