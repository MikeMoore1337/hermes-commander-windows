"""Inventory the actual unsigned candidate without running or distributing it."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import sys

MAX_BINARY = 256 * 1024 * 1024
MAX_ENTRY = 128 * 1024 * 1024
# .NET apphost bundle signature, as defined by Microsoft.NET.HostModel.
MARKER = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")


def _safe_name(name):
    text = name.replace("\\", "/")
    parts = PurePosixPath(text)
    if not text or parts.is_absolute() or any(ord(c) < 32 for c in text) or any(x in {"", ".", ".."} or ":" in x for x in text.split("/")):
        raise ValueError("unsafe bundle name")
    return str(parts)


def _string(data, position):
    length = 0
    for shift in range(0, 35, 7):
        if position >= len(data):
            raise ValueError("truncated string length")
        b = data[position]
        position += 1
        length |= (b & 127) << shift
        if not b & 128:
            break
    else:
        raise ValueError("invalid string length")
    if length > 4096 or position + length > len(data):
        raise ValueError("invalid string")
    return data[position:position + length].decode("utf-8"), position + length


def inspect_dotnet(data):
    if not 40 <= len(data) <= MAX_BINARY or data.count(MARKER) != 1:
        raise ValueError("invalid bundle marker")
    marker = data.index(MARKER)
    if marker < 8:
        raise ValueError("invalid bundle offset")
    offset = struct.unpack_from("<q", data, marker - 8)[0]
    if offset < marker + len(MARKER) or offset + 12 > len(data):
        raise ValueError("invalid manifest offset")
    major, minor, count = struct.unpack_from("<IIi", data, offset)
    if major != 6 or minor != 0 or not 1 <= count <= 2048:
        raise ValueError("unsupported bundle format")
    _, pos = _string(data, offset + 12)
    pos += 40  # .NET 6+ deps, runtime config, and flags
    entries = []
    names = set()
    runtime_config = None
    for _ in range(count):
        if pos + 25 > len(data):
            raise ValueError("truncated manifest")
        start, size, compressed, kind = struct.unpack_from("<qqqB", data, pos)
        name, pos = _string(data, pos + 25)
        name = _safe_name(name)
        if name.casefold() in names:
            raise ValueError("duplicate bundle name")
        names.add(name.casefold())
        stored = compressed or size
        if start < 0 or not 0 <= size <= MAX_ENTRY or compressed < 0 or stored > MAX_ENTRY or start + stored > offset:
            raise ValueError("invalid bundle entry")
        digest = hashlib.sha256(data[start:start + size]).hexdigest() if not compressed else None
        if name.endswith(".runtimeconfig.json") and not compressed:
            if runtime_config is not None or size > 1024 * 1024:
                raise ValueError("invalid runtime configuration")
            runtime_config = json.loads(data[start:start + size])
        entries.append({"name": name, "type": kind, "size": size, "compressed": compressed, "sha256": digest})
    return {"format": f"{major}.{minor}", "runtime_config": runtime_config, "entries": entries}


def inspect_worker(path, expected):
    from PyInstaller.archive.readers import CArchiveReader

    reader = CArchiveReader(str(path))
    entries = []
    for name, (_, _, unpacked, _, kind) in reader.toc.items():
        safe = _safe_name(name)
        if not safe.lower().endswith((".dll", ".pyd")):
            continue
        if not 0 <= unpacked <= MAX_ENTRY:
            raise ValueError("unsafe worker entry")
        content = reader.extract(name)
        if len(content) != unpacked:
            raise ValueError("invalid worker entry size")
        entries.append({"name": safe, "type": kind, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    comparisons = []
    for item in expected:
        name = PurePosixPath(item["name"].replace("\\", "/")).name
        hits = [e["sha256"] for e in entries if PurePosixPath(e["name"]).name.casefold() == name.casefold()]
        if len(hits) > 1:
            raise ValueError("ambiguous worker input")
        actual = hits[0] if hits else None
        comparisons.append({"name": name, "expected": item["sha256"], "actual": actual, "matches": bool(actual and actual == item["sha256"])})
    return {"entries": entries, "input_comparisons": comparisons}


def main(service, worker, inputs, output):
    service_path, worker_path = Path(service), Path(worker)
    if service_path.stat().st_size > MAX_BINARY or worker_path.stat().st_size > MAX_BINARY:
        raise ValueError("candidate too large")
    report = {
        "dotnet_bundle": inspect_dotnet(service_path.read_bytes()),
        "worker": inspect_worker(worker_path, json.loads(Path(inputs).read_text(encoding="utf-8-sig"))),
    }
    Path(output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("expected service, worker, input metadata, and output")
    main(*sys.argv[1:])
