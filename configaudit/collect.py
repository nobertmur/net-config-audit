"""Collect running configs from devices, then redact, normalise and store them (optionally in Git).

Credentials are never read from the inventory file. The file names two environment variables per
device, and the values are read from the environment at run time.

The default connection uses Netmiko, imported lazily so the rest of the tool works without it.
Tests inject a fake connection. The live-device path has not been exercised from this repository.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

import yaml

from .prepare import prepare
from .vendors import COLLECT_COMMANDS

NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HOST = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")
ENV = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")


class Connection(Protocol):
    def send_command(self, command: str) -> str: ...

    def disconnect(self) -> None: ...


Connect = Callable[[dict], Connection]


def load_inventory(path: Path) -> list[dict]:
    devices = (yaml.safe_load(Path(path).read_text()) or {}).get("devices", [])
    seen: set[str] = set()
    for device in devices:
        for key in ("name", "host", "device_type", "username_env", "password_env"):
            if key not in device:
                raise ValueError(f"inventory: device {device.get('name', '?')} is missing '{key}'")
        if not NAME.match(device["name"]) or device["name"] in seen:
            raise ValueError(f"inventory: bad or duplicate device name {device['name']!r}")
        seen.add(device["name"])
        if not HOST.match(str(device["host"])):
            raise ValueError(f"inventory: device {device['name']} has an unsafe host value")
        if device["device_type"] not in COLLECT_COMMANDS:
            raise ValueError(
                f"inventory: device {device['name']} has unsupported device_type {device['device_type']!r}"
            )
        for key in ("username_env", "password_env"):
            if not ENV.match(device[key]):
                raise ValueError(f"inventory: device {device['name']}: {key} must be an environment variable name")
    return devices


def netmiko_connect(device: dict) -> Connection:
    try:
        from netmiko import ConnectHandler  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - depends on the optional package
        raise RuntimeError("netmiko is not installed; run `pip install netmiko`") from exc
    username, password = os.environ.get(device["username_env"]), os.environ.get(device["password_env"])
    if not username or not password:
        raise RuntimeError(f"set {device['username_env']} and {device['password_env']} in the environment")
    return ConnectHandler(device_type=device["device_type"], host=device["host"], username=username, password=password)


def collect(
    inventory: list[dict], out_dir: Path, connect: Connect = netmiko_connect
) -> tuple[dict[str, str], dict[str, str]]:
    """Return (changed-or-new device -> status, failed device -> error). Failures never abort the run."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    failed: dict[str, str] = {}
    for device in inventory:
        name = device["name"]
        try:
            connection = connect(device)
            try:
                raw = connection.send_command(COLLECT_COMMANDS[device["device_type"]])
            finally:
                connection.disconnect()
        except Exception as exc:  # one unreachable device must not stop the others
            failed[name] = f"{type(exc).__name__}: {exc}"
            continue
        _, stored = prepare(raw)
        path = out_dir / f"{name}.cfg"
        previous = path.read_text() if path.exists() else None
        if previous != stored:
            path.write_text(stored)
            written[name] = "new" if previous is None else "changed"
    return written, failed


def commit(out_dir: Path, message: str) -> bool:
    """Commit everything under out_dir to its own Git repository. Returns True if a commit was made."""
    out_dir = Path(out_dir)
    git = ["git", "-C", str(out_dir), "-c", "user.name=net-config-audit", "-c", "user.email=net-config-audit@localhost"]
    if not (out_dir / ".git").exists():
        subprocess.run(["git", "-C", str(out_dir), "init", "-q", "-b", "main"], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    if subprocess.run([*git, "diff", "--cached", "--quiet"]).returncode == 0:
        return False
    subprocess.run([*git, "commit", "-q", "-m", message], check=True)
    return True
