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

> ⚠️ *This project is currently under active development and is not suitable for production use. Breaking changes may occur without notice. A stable release will be published to PyPI once development stabilizes.*


## Example
```python
import time
from pathlib import Path

from octopus.android.device import AndroidDeviceTcp
from octopus.capture.frida import FridaCapture
from octopus.capture.network import OnDeviceNetworkCapture

device = AndroidDeviceTcp("192.168.0.92", 5555)
output_path = Path("/tmp/output")
output_path.mkdir(parents=True, exist_ok=True)
device.start_frida_server(force_stop=True)
network = OnDeviceNetworkCapture(device, output_path)
frida = FridaCapture(device, output_path)
network.start_capture()
frida.start_capture()
time.sleep(10)
network.stop_capture()
frida.stop_capture()
```