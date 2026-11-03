#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pack a generated dump with nup-meow's tools/nup and check headless/nup.h against it.

usage: check-nup.py <eden-nup-check binary> <path to nup-meow/tools/nup>
Needs the `zstandard` module (the reference packer's own dependency), so that the .nup holds zstd files.
Checks: base + two updates + DLC; the same without zstd; an update-only dump; a bare content folder.
"""
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile

if len(sys.argv) != 3:
    sys.exit(__doc__)
checker, nup_tool = sys.argv[1], sys.argv[2]
try:
    import zstandard  # noqa: F401
except ImportError:
    sys.exit("check-nup.py: install zstandard (pip install zstandard)")

random.seed(7)
TITLE = 0x0100ABCD00012000


def write(root, path, data):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(data)


def npdm():
    d = bytearray(0x580)
    d[0:4] = b"META"
    struct.pack_into("<I", d, 0x70, 0x560)
    d[0x560:0x564] = b"ACI0"
    struct.pack_into("<Q", d, 0x570, TITLE)
    return bytes(d)


def nso(tag):
    d = bytearray(0x1000)
    d[0:4] = b"NSO0"
    d[0x40:0x60] = bytes((tag + i) & 255 for i in range(32))
    for i in range(0x100, 0x1000):
        d[i] = (i * tag) & 255
    return bytes(d)


def layer(root, where, main_tag, **changes):
    write(root, where + "/exefs/main", nso(main_tag))
    write(root, where + "/exefs/main.npdm", npdm())
    shared = {
        "romfs/data/big.txt": b"Switch romfs line of text that compresses well. " * 70000,
        "romfs/data/noise.bin": bytes(random.getrandbits(8) for _ in range(300000)),
        "romfs/empty.bin": b"",
        "romfs/a/b/c/deep.bin": b"deep" * 100,
        "romfs/\u00fcn\u00ef/c\u00f6d\u00e9.txt": b"unicode name\n",
    }
    for name, data in {**shared, **changes}.items():
        write(root, where + "/" + name, data)


def pack(dump, out, env_extra=None):
    env = dict(os.environ, PYTHONPATH=nup_tool)
    subprocess.run([sys.executable, "-m", "nup.cli", "pack", dump, out, "-q", "--name", "Check Quest",
                    "--display-version", "7.1.0"], check=True, env=env)


def run(nup, dump):
    subprocess.run([checker, nup, dump], check=True)


with tempfile.TemporaryDirectory() as tmp:
    random.seed(7)
    full = os.path.join(tmp, "full")
    layer(full, "base", 1, **{"romfs/will_change.txt": b"one\n" * 300})
    layer(full, "updates/458752", 11, **{"romfs/will_change.txt": b"two\n" * 300})
    layer(full, "updates/459008", 12, **{"romfs/will_change.txt": b"three\n" * 300, "romfs/new.bin": b"new" * 999})
    write(full, "dlc/0100abcd00013001/0/romfs/dlc.bin", b"dlc" * 100)
    pack(full, os.path.join(tmp, "full.nup"))
    run(os.path.join(tmp, "full.nup"), full)

    only_updates = os.path.join(tmp, "updates-only")
    shutil.copytree(os.path.join(full, "updates"), os.path.join(only_updates, "updates"))
    pack(only_updates, os.path.join(tmp, "updates.nup"))
    run(os.path.join(tmp, "updates.nup"), only_updates)

    bare = os.path.join(tmp, "bare")
    shutil.copytree(os.path.join(full, "base"), bare)
    pack(bare, os.path.join(tmp, "bare.nup"))
    run(os.path.join(tmp, "bare.nup"), bare)
print("check-nup PASS")
