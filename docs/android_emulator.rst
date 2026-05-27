Android emulator
================

This page explains how to create a rooted Android emulator using command line tools, how to verify it is rooted, and how to use it with Octopus.

Prerequisites
-------------

You must have the Android SDK installed and the following tools in your ``PATH``:

- ``sdkmanager``
- ``avdmanager``
- ``emulator``
- ``adb``

These are typically found in ``$ANDROID_HOME/cmdline-tools/latest/bin/`` and ``$ANDROID_HOME/platform-tools/``.

Creating a rooted emulator
--------------------------

To have a rooted emulator that works easily with Frida and Octopus, it is recommended to use a **Google APIs** system image instead of a **Google Play** image. Google Play images are production builds and are much harder to root.

1. **List and install a system image**

   First, identify and install a suitable system image.

   For **x86_64** hosts:

   .. code-block:: bash

      sdkmanager "system-images;android-33;google_apis;x86_64"

   For **arm64** hosts:

   .. code-block:: bash

      sdkmanager "system-images;android-33;google_apis;arm64-v8a"

2. **Create the Android Virtual Device (AVD)**

   Create a new AVD using the installed image.

   For **x86_64**:

   .. code-block:: bash

      avdmanager create avd -n octopus-x86_64 -k "system-images;android-33;google_apis;x86_64" -d pixel_c

   For **arm64**:

   .. code-block:: bash

      avdmanager create avd -n octopus-arm64 -k "system-images;android-33;google_apis;arm64-v8a" -d pixel_c

3. **Launch the emulator**

   Launch the emulator (replace ``<avd-name>`` with ``octopus-x86_64`` or ``octopus-arm64``).

   .. code-block:: bash

      emulator -avd <avd-name> -no-snapshot-load

Rooting the emulator
--------------------

Once the emulator is running, you can gain root access using ADB:

.. code-block:: bash

   adb root

If successful, ADB will restart as root. You can also remount the system partition as writable if needed:

.. code-block:: bash

   adb remount

Checking root status
--------------------

To verify that the emulator is rooted and accessible by Octopus:

1. **Check ADB user**

   Run the following command:

   .. code-block:: bash

      adb shell whoami

   It should return ``root``.

2. **Check SU availability**

   If you are not running as root by default but have a ``su`` binary installed:

   .. code-block:: bash

      adb shell su -c "id"

   This should return information about the root user.