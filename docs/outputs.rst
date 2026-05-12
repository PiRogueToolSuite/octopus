Outputs
=======================
.. toctree::
   :maxdepth: 1

.. _pcapng-utils: https://pts-project.org/pcapng-utils/

.. hint::

    Use pcapng-utils_ to combine the output files and generate an enriched HAR file that can be opened
    in the network inspector of any web browser.


TLS keys
---------
Extracted TLS keys are stored in ``sslkeylog.txt``.

..  code-block:: txt

    CLIENT_HANDSHAKE_TRAFFIC_SECRET AFA8B1F7F897E626B5F72C0F 7D0BEC98C67EA92EF0CE25FCE04F336B22ED0A94684
    SERVER_HANDSHAKE_TRAFFIC_SECRET AFA8B1F7F897E626B5F72C0F C032C056B02DBB371E470D41433B2BD9A552BEB379F
    CLIENT_HANDSHAKE_TRAFFIC_SECRET FBD911D347AD94BEDEA3A8AA 702A36A51CF81787A8F9E78D95C539E0059E9236219
    SERVER_HANDSHAKE_TRAFFIC_SECRET FBD911D347AD94BEDEA3A8AA 15A6C5BFC475345671CFEE797C0E6388EBF05F9EC4A

Network traffic
---------------
The file ``traffic.pcap`` contains the captured network traffic.

Screen recording
-----------------
The file ``screen.mp4`` contains the video recording of the device’s screen.

.. warning::

    Octopus uses ``screenrecord`` to capture the video of the screen, the recording is limited to 3 minutes.


Session details
-------------------------
The file ``experiment.json`` contains timing information such as the start and end date of the instrumentation session.

..  code-block:: json

    {
      "device": {
        "file": "device.json",
        "start_capture_time": 1778171698483.5752,
        "end_capture_time": 1778171698789.002,
        "capture_duration": 305.4267578125
      },
      "network": {
        "file": "traffic.pcap",
        "start_capture_time": 1778171699946.72,
        "end_capture_time": 1778171725205.205,
        "capture_duration": 25258.485107421875
      },
      "socket_traces": {
        "file": "socket_trace.json"
      },
      "sslkeylog": {
        "file": "sslkeylog.txt"
      },
      "dynamic_hook_log": {
        "file": "dynamic_hook.json"
      },
      "advertising_id_log": {
        "file": "ad_ids.txt"
      },
      "screen": {
        "file": "screen.mp4",
        "start_capture_time": 1778171700183.307,
        "end_capture_time": 1778171729493.512,
        "capture_duration": 29310.205078125
      }
    }

Device properties
-------------------------
The file ``device.json`` contains various information about the device such as IMEI and Android version.

..  code-block:: json

    {
      "fingerprint": "samsung/star2ltexx/star2lte:10/QP1A.130711.020/GFFFFB4:user/release-keys",
      "brand": "samsung",
      "device": "star2lte",
      "manufacturer": "samsung",
      "model": "SM-G965F",
      "name": "star2ltexx",
      "serialno": "229bbb7ece",
      "android_version": "10",
      "api_level": "29",
      "imei": "3000000005"
    }

Android Advertising IDs
-----------------------
The file ``ad_ids.txt`` contains all Android advertising IDs issued during the session.

..  code-block:: txt

    a9a39e8a-333d-40ce-bc6c-73473cf454c0
    30998a51-c909-43cb-acc8-6aef014061c8
    1a872b9a-80f5-44d1-a4e4-82f49f7bd93f

Cryptographic operations
-------------------------
The file ``aes_info.json`` contains all AES and RSA encryption-decryption operation with both cleartext and ciphertext.

..  code-block:: json

    [
      {
        "type": "aes_info_log",
        "dump": "aes_info.json",
        "data_type": "json",
        "timestamp": 1679484118638,
        "data": {
          "iv": "",
          "alg": "AES",
          "in": "",
          "out": "",
          "key": "b7370c641d97532c61e50fc414883331471ecb671850f0d1cd753f9087c8f539"
        },
        "pid": 7289,
        "process": "com.example.android"
      }
    ]

Operations on sockets
----------------------
All the operations on sockets are logged in ``socket_trace.json``. It contains the stacktrace of every
socket operations. Use pcapng-utils_ to add the stacktrace information to each HTTP request and response.

..  code-block:: json

    [
      {
        "type": "socket_traces",
        "dump": "socket_trace.json",
        "pid": 20415,
        "process": "com.example.android",
        "data_type": "json",
        "timestamp": 1778171707798,
        "data": {
          "socket_fd": 56,
          "socket_type": "tcp6",
          "pid": 20415,
          "thread_id": 20500,
          "socket_event_type": "write",
          "dest_ip": "::ffff:185.60.219.3",
          "dest_port": 443,
          "local_ip": "::ffff:192.168.0.92",
          "local_port": 40788,
          "stack": [
            {
              "class": "com.android.org.conscrypt.NativeCrypto",
              "file": "NativeCrypto.java",
              "line": -2,
              "method": "SSL_do_handshake",
              "is_native": true,
              "str": "com.android.org.conscrypt.NativeCrypto.SSL_do_handshake(Native Method)"
            },
            {
              "class": "com.android.org.conscrypt.NativeSsl",
              "file": "NativeSsl.java",
              "line": 387,
              "method": "doHandshake",
              "is_native": false,
              "str": "com.android.org.conscrypt.NativeSsl.doHandshake(NativeSsl.java:387)"
            },
            {
              "class": "com.android.org.conscrypt.ConscryptFileDescriptorSocket",
              "file": "ConscryptFileDescriptorSocket.java",
              "line": 226,
              "method": "startHandshake",
              "is_native": false,
              "str": "com.android.org.conscrypt.ConscryptFileDescriptorSocket.startHandshake(ConscryptFileDescriptorSocket.java:226)"
            }
          ]
        }
      }
    ]