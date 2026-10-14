.. _rooted-avd:

=====================================
Android emulator
=====================================

This guide explains how to create and launch a rooted Android Virtual Device
(AVD) using the command line only, on Windows, Linux and macOS.

.. note::

   Only emulator images tagged ``google_apis`` (or ``default``) can be rooted
   with ``adb root``. Images tagged ``google_apis_playstore`` are production
   builds and **cannot** be rooted this way.

Prerequisites
=============

* A 64-bit machine with hardware virtualization enabled in the BIOS/UEFI.
* A JDK (version 17 or later) available in your ``PATH``.
* Roughly 10 GB of free disk space.

.. tabs::

   .. group-tab:: Windows

      Open **PowerShell** and verify Java:

      .. code-block:: powershell

         java -version

      Hardware acceleration on Windows uses the Windows Hypervisor Platform
      (WHPX). Enable it from an elevated PowerShell, then reboot:

      .. code-block:: powershell

         Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform

   .. group-tab:: Linux

      Verify Java and KVM support:

      .. code-block:: bash

         java -version
         ls -l /dev/kvm

      If you do not have access to ``/dev/kvm``, add yourself to the ``kvm``
      group, then log out and back in:

      .. code-block:: bash

         sudo usermod -aG kvm "$USER"

   .. group-tab:: macOS

      Verify Java:

      .. code-block:: bash

         java -version

      macOS uses the built-in Hypervisor framework, so no extra setup is
      required for hardware acceleration.

Install the Android command-line tools
==============================================

Manually download the **Command line tools only** archive for your operating
system from the
`Android Studio downloads page <https://developer.android.com/studio#command-line-tools-only>`_
(scroll to the "Command line tools only" section). Accept the license terms and
save the ZIP file to your ``Downloads`` folder.

The tools must end up in ``<SDK_ROOT>/cmdline-tools/latest/``. The commands
below extract the archive there. Replace ``<version>`` with the version number
in the name of the file you downloaded.

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         $Sdk = "$env:LOCALAPPDATA\Android\Sdk"
         New-Item -ItemType Directory -Force -Path "$Sdk\cmdline-tools" | Out-Null
         Expand-Archive "$env:USERPROFILE\Downloads\commandlinetools-win-<version>_latest.zip" `
           -DestinationPath "$Sdk\cmdline-tools"
         Rename-Item "$Sdk\cmdline-tools\cmdline-tools" "latest"

   .. group-tab:: Linux

      .. code-block:: bash

         SDK="$HOME/Android/Sdk"
         mkdir -p "$SDK/cmdline-tools"
         unzip ~/Downloads/commandlinetools-linux-<version>_latest.zip \
           -d "$SDK/cmdline-tools"
         mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"

   .. group-tab:: macOS

      .. code-block:: bash

         SDK="$HOME/Library/Android/sdk"
         mkdir -p "$SDK/cmdline-tools"
         unzip ~/Downloads/commandlinetools-mac-<version>_latest.zip \
           -d "$SDK/cmdline-tools"
         mv "$SDK/cmdline-tools/cmdline-tools" "$SDK/cmdline-tools/latest"

.. note::

   The ``$Sdk`` / ``SDK`` variable defined here is used by all the following
   commands, which call each tool by its full path so that no change to
   ``PATH`` is needed. The variable only lives in the current terminal
   session: if you open a new one, define it again with the same value.

Verify the installation:

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & "$Sdk\cmdline-tools\latest\bin\sdkmanager.bat" --version

   .. group-tab:: Linux

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/sdkmanager" --version

   .. group-tab:: macOS

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/sdkmanager" --version

Install the emulator and a system image
===============================================

Accept the licenses first:

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & "$Sdk\cmdline-tools\latest\bin\sdkmanager.bat" --licenses

   .. group-tab:: Linux

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/sdkmanager" --licenses

   .. group-tab:: macOS

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/sdkmanager" --licenses

Then install the platform tools, the emulator and a ``google_apis`` system
image. Choose the ABI that matches your CPU:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Host CPU
     - System image ABI
   * - Intel / AMD (Windows, Linux, macOS)
     - ``x86_64``
   * - Apple Silicon (macOS), ARM Linux or Windows on ARM
     - ``arm64-v8a``

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & "$Sdk\cmdline-tools\latest\bin\sdkmanager.bat" "platform-tools" "emulator" "system-images;android-34;google_apis;x86_64"

   .. group-tab:: Linux

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "emulator" "system-images;android-34;google_apis;x86_64"

   .. group-tab:: macOS

      .. code-block:: bash

         # Apple Silicon
         "$SDK/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "emulator" "system-images;android-34;google_apis;arm64-v8a"

         # Intel
         "$SDK/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "emulator" "system-images;android-34;google_apis;x86_64"

To list all available system images (for another API level or ABI):

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & "$Sdk\cmdline-tools\latest\bin\sdkmanager.bat" --list | Select-String system-images

   .. group-tab:: Linux

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/sdkmanager" --list | grep system-images

   .. group-tab:: macOS

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/sdkmanager" --list | grep system-images

Create the AVD
======================

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & "$Sdk\cmdline-tools\latest\bin\avdmanager.bat" create avd `
           --name rooted_avd `
           --package "system-images;android-34;google_apis;x86_64" `
           --device "pixel_6"

   .. group-tab:: Linux

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/avdmanager" create avd \
           --name rooted_avd \
           --package "system-images;android-34;google_apis;x86_64" \
           --device "pixel_6"

   .. group-tab:: macOS

      .. code-block:: bash

         # Replace x86_64 with arm64-v8a on Apple Silicon
         "$SDK/cmdline-tools/latest/bin/avdmanager" create avd \
           --name rooted_avd \
           --package "system-images;android-34;google_apis;arm64-v8a" \
           --device "pixel_6"

Answer ``no`` if prompted to create a custom hardware profile. Verify that the
AVD exists:

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & "$Sdk\cmdline-tools\latest\bin\avdmanager.bat" list avd

   .. group-tab:: Linux

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/avdmanager" list avd

   .. group-tab:: macOS

      .. code-block:: bash

         "$SDK/cmdline-tools/latest/bin/avdmanager" list avd

Launch the AVD
======================

Start the emulator. The ``-writable-system`` flag is optional but required if
you want to modify the ``/system`` partition later.

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & "$Sdk\emulator\emulator.exe" -avd rooted_avd -writable-system -no-snapshot

   .. group-tab:: Linux

      .. code-block:: bash

         "$SDK/emulator/emulator" -avd rooted_avd -writable-system -no-snapshot

   .. group-tab:: macOS

      .. code-block:: bash

         "$SDK/emulator/emulator" -avd rooted_avd -writable-system -no-snapshot

.. tip::

   Add ``-no-window`` to run the emulator headless (useful for CI), and
   ``-gpu swiftshader_indirect`` if you encounter graphics problems.

On Windows, the emulator runs in the foreground and keeps the PowerShell
window busy. Open a second PowerShell window for the next step (and define
``$Sdk`` again there).

Obtain root access
==========================

Wait for the device to finish booting, then restart ``adbd`` as root:

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         $Adb = "$Sdk\platform-tools\adb.exe"
         & $Adb wait-for-device
         & $Adb root
         & $Adb shell id

   .. group-tab:: Linux

      .. code-block:: bash

         ADB="$SDK/platform-tools/adb"
         "$ADB" wait-for-device
         "$ADB" root
         "$ADB" shell id

   .. group-tab:: macOS

      .. code-block:: bash

         ADB="$SDK/platform-tools/adb"
         "$ADB" wait-for-device
         "$ADB" root
         "$ADB" shell id

The last command should print something like:

.. code-block:: text

   uid=0(root) gid=0(root) groups=0(root),...


Stopping the emulator
=====================

.. tabs::

   .. group-tab:: Windows

      .. code-block:: powershell

         & $Adb emu kill

   .. group-tab:: Linux

      .. code-block:: bash

         "$ADB" emu kill

   .. group-tab:: macOS

      .. code-block:: bash

         "$ADB" emu kill

Troubleshooting
===============

``adbd cannot run as root in production builds``
   The system image is a ``google_apis_playstore`` image. Create a new AVD
   from a ``google_apis`` image instead.

``PANIC: Missing emulator engine program``
   The ``emulator`` package is not installed, or ``$Sdk`` / ``SDK`` points to
   the wrong directory. Re-run the second step and check the variable's value.

``x86_64 emulation currently requires hardware acceleration``
   Hardware virtualization is disabled or unavailable. Enable VT-x/AMD-V in
   the BIOS/UEFI and, on Windows, enable the Windows Hypervisor Platform. On
   Linux, check your access to ``/dev/kvm``.

``adb: device offline``
   Wait for the boot to complete (``adb shell getprop sys.boot_completed``
   returns ``1``), or restart the server with ``adb kill-server`` followed by
   ``adb start-server``.