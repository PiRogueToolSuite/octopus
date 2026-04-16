# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import lzma
from pathlib import Path

import requests

FRIDA_SERVER_LATEST_RELEASE_URL = "https://api.github.com/repos/frida/frida/releases/latest"
FRIDA_SERVER_RELEASE_BY_TAG_URL = "https://api.github.com/repos/frida/frida/releases/tags/{TAG}"
logger = logging.getLogger(__name__)


class FridaServer:
    """
    Class for downloading Frida server.
    """

    executable = "frydaxx-server"
    executable_path = Path(f"/data/local/tmp/{executable}")

    @staticmethod
    def download_frida_server(arch: str, output_file: str, platform: str, client_version: str):
        """
        Downloads and extracts the Frida server binary for the specified architecture.

        Args:
            arch: Device architecture (e.g., 'arm64', 'x86').
            output_file: Path to save the extracted server binary.
            platform: Platform name (e.g., 'android').
            client_version: Frida server version tag.

        Raises:
            FileNotFoundError: If the server binary for the specified parameters is not found.
            Exception: If unable to find the specified Frida server version in GitHub releases.
        """
        if not arch:
            logger.error(
                f"Unable to determine device ABI, install Frida server manually in {FridaServer.executable_path}"
            )
            return
        resp = requests.get(FRIDA_SERVER_RELEASE_BY_TAG_URL.format(TAG=client_version))
        try:
            resp.raise_for_status()
            release = resp.json()
            assert release.get("tag_name") == client_version
            for asset in release["assets"]:
                asset_name = asset["name"]
                if "server" in asset_name and f"{platform}-{arch}.xz" in asset_name:
                    logger.info(f"Downloading {asset['browser_download_url']}...")
                    xz_file = requests.get(asset["browser_download_url"])
                    xz_file.raise_for_status()
                    logger.info(f"Extracting {asset_name}...")
                    server_binary = lzma.decompress(xz_file.content)
                    logger.info(f"Writing {asset_name} to {output_file}...")
                    with open(output_file, mode="wb") as out:
                        out.write(server_binary)
                        out.flush()
                    return
            raise FileNotFoundError((arch, platform, client_version))
        except Exception as e:
            logger.error(
                f"Unable to find frida-server version {client_version} in GitHub releases. "
                f"Install it manually {FridaServer.executable_path} and make it executable with chmod +x."
            )
            raise Exception(f"Unable to find frida-server version {client_version} in GitHub releases.") from e
