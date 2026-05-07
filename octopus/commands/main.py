# SPDX-FileCopyrightText: 2026 Defensive Lab Agency
# SPDX-FileContributor: u039b <git@0x39b.fr>
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from pathlib import Path

import click

from octopus.commands.devices import list_local_devices
from octopus.commands.instrument import usb_mode, tcp_mode


def setup_logging(level_name):
    level = getattr(logging, level_name.upper())
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-8s %(name)s: %(message)s")


def adb_options(func):
    func = click.option(
        "--adb-host", "-ah", type=str, default="127.0.0.1", help="ADB server IP address, defaults to 127.0.0.1"
    )(func)
    func = click.option("--adb-port", "-ap", type=int, default=5037, help="ADB server port, defaults to 5037")(func)
    return func


def usb_device_options(func):
    func = click.option("--device-id", "-d", type=str, default=None, help="USB Android device ID")(func)
    return func


def tcp_device_options(func):
    func = click.option("--device-host", "-dh", type=str, required=True, help="Remote Android device IP address")(func)
    func = click.option(
        "--device-port", "-dp", type=int, default=5555, help="Remote Android device ADB port, defaults to 5555"
    )(func)
    return func


def common_options(func):
    func = click.option(
        "--duration", type=int, default=-1, help="Duration of the capture in seconds, defaults to -1 (unlimited)"
    )(func)
    func = click.option("--no-screen-record", "-ns", is_flag=True, help="Disables the screen recording")(func)
    func = click.option("--no-instrumentation", "-ni", is_flag=True, help="Disables the instrumentation")(func)
    func = click.option("--no-network-capture", "-nn", is_flag=True, help="Disables the network capture")(func)
    func = click.option("--overwrite", "-w", is_flag=True, help="Overwrite the output files")(func)
    func = click.option(
        "--output-path",
        "-o",
        type=click.Path(),
        default=Path("./output"),
        help="Output directory path, defaults to ./output. Will be created if it doesn't exist.",
    )(func)
    return func


@click.group()
@click.option("--log-level", default="INFO", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]))
@click.pass_context
def octopus(ctx, log_level):
    ctx.ensure_object(dict)
    ctx.obj["LOG_LEVEL"] = log_level
    setup_logging(log_level)


@octopus.group()
def device():
    pass


@device.command(name="list")
@adb_options
# octopus device list
def list_devices(adb_host, adb_port):
    list_local_devices(adb_host, adb_port)
    pass


@octopus.group()
def instrument():
    pass


@instrument.command(name="tcp")
@adb_options
@tcp_device_options
@common_options
# octopus instrument tcp
def instrument_tcp(
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
    tcp_mode(
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
    )


@instrument.command(name="usb")
@adb_options
@usb_device_options
@common_options
# octopus instrument usb
def instrument_usb(
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
    usb_mode(
        adb_host,
        adb_port,
        device_id,
        output_path,
        no_screen_record,
        no_network_capture,
        no_instrumentation,
        duration,
        overwrite,
    )
