"""Inventory the actual unsigned candidate without running or distributing it."""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import struct
import sys
import zlib

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
    dependency_libraries = None
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
        if name.endswith(".deps.json") and not compressed:
            if dependency_libraries is not None or size > 4 * 1024 * 1024:
                raise ValueError("invalid dependency metadata")
            libraries = json.loads(data[start:start + size]).get("libraries")
            if not isinstance(libraries, dict):
                raise ValueError("invalid dependency libraries")
            dependency_libraries = sorted(libraries)
        entries.append({"name": name, "type": kind, "size": size, "compressed": compressed, "sha256": digest})
    return {"format": f"{major}.{minor}", "runtime_config": runtime_config,
            "dependency_libraries": dependency_libraries, "entries": entries}


def _worker_bytes(reader, entry):
    offset, stored, unpacked, compressed, _ = entry
    start = reader._start_offset + offset
    size = Path(reader._filename).stat().st_size
    if offset < 0 or stored < 0 or stored > MAX_ENTRY or compressed not in (0, 1) or start < 0 or start + stored > size:
        raise ValueError("invalid worker entry bounds")
    with open(reader._filename, "rb") as source:
        source.seek(start)
        data = source.read(stored)
    if compressed:
        inflater = zlib.decompressobj()
        data = inflater.decompress(data, unpacked + 1)
        if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
            raise ValueError("invalid compressed worker entry")
    if len(data) != unpacked:
        raise ValueError("invalid worker entry size")
    return data


def inspect_worker(path, expected, extracted=None):
    from PyInstaller.archive.readers import CArchiveReader

    reader = CArchiveReader(str(path))
    if len(reader.toc) > 4096:
        raise ValueError("too many worker entries")
    if extracted is not None:
        extracted.mkdir()
    entries = []
    total = 0
    for name, entry in reader.toc.items():
        _, _, unpacked, _, kind = entry
        safe = _safe_name(name)
        if not safe.lower().endswith((".dll", ".pyd")):
            continue
        if not 0 <= unpacked <= MAX_ENTRY:
            raise ValueError("unsafe worker entry")
        total += unpacked
        if total > MAX_BINARY:
            raise ValueError("worker entries too large")
        content = _worker_bytes(reader, entry)
        digest = hashlib.sha256(content).hexdigest()
        if extracted is not None:
            output = extracted / (digest + Path(safe).suffix.lower())
            if not output.exists():
                output.write_bytes(content)
        entries.append({"name": safe, "type": kind, "size": len(content), "sha256": digest})
    comparisons = []
    for item in expected:
        name = PurePosixPath(item["name"].replace("\\", "/")).name
        hits = [e["sha256"] for e in entries if PurePosixPath(e["name"]).name.casefold() == name.casefold()]
        if len(hits) > 1:
            raise ValueError("ambiguous worker input")
        actual = hits[0] if hits else None
        comparisons.append({"name": name, "expected": item["sha256"], "actual": actual, "matches": bool(actual and actual == item["sha256"])})
    return {"entries": entries, "input_comparisons": comparisons}


def _toc_rows(value, depth=0):
    if depth > 64:
        raise ValueError("TOC nesting too deep")
    if isinstance(value, (tuple, list)):
        if len(value) == 3 and all(isinstance(x, str) for x in value) and value[2] in {"BINARY", "EXTENSION"}:
            yield value
        else:
            for child in value:
                yield from _toc_rows(child, depth + 1)
    elif isinstance(value, dict):
        for child in value.values():
            yield from _toc_rows(child, depth + 1)


def map_worker_sources(entries, toc_text, roots):
    if len(toc_text) > 16 * 1024 * 1024:
        raise ValueError("TOC too large")
    rows = list(_toc_rows(ast.literal_eval(toc_text)))
    if len(rows) > 10000:
        raise ValueError("too many TOC entries")
    by_name = {}
    for dest, source, _ in rows:
        by_name.setdefault(_safe_name(dest).casefold(), []).append(source)
    results = []
    for entry in entries:
        candidates = by_name.get(entry["name"].casefold(), [])
        matches = []
        diagnostics = []
        for raw in candidates:
            path = Path(raw)
            try:
                resolved = path.resolve(strict=True)
                match = next(((label, root) for label, root in roots if resolved.is_relative_to(root.resolve())), None)
                category = match[0] if match else None
                if category == "runner_tool_cache":
                    relative = resolved.relative_to(match[1].resolve())
                    family = relative.parts[0].casefold() if relative.parts else "other"
                    category += "/" + (family if family in {"python", "dotnet", "msvc", "windows"} else "other")
                if not category:
                    top = resolved.parts[1].casefold() if len(resolved.parts) > 1 else "unknown"
                    known = {"windows", "users", "program files", "program files (x86)",
                             "programdata", "hostedtoolcache", "a", "actions", "tools"}
                    diagnostics.append({"category": "unapproved-root", "status": "not-read",
                                        "top_level": top if top in known else "other"})
                    continue
                if resolved.suffix.lower() not in {".dll", ".pyd"} or resolved.stat().st_size > MAX_ENTRY:
                    diagnostics.append({"category": category, "status": "unsafe-input"})
                    continue
                if hashlib.sha256(resolved.read_bytes()).hexdigest() == entry["sha256"]:
                    matches.append(category)
                    diagnostics.append({"category": category, "status": "match"})
                else:
                    diagnostics.append({"category": category, "status": "different-bytes"})
            except (OSError, ValueError):
                diagnostics.append({"category": "unknown", "status": "unavailable"})
                continue
        results.append({"name": entry["name"], "toc_candidates": len(candidates),
                        "matching_sources": sorted(set(matches)), "diagnostics": diagnostics})
    return results


def map_dotnet_sources(entries, pack_dir):
    candidates = {}
    root = pack_dir.resolve(strict=True)
    for path in pack_dir.rglob("*.dll"):
        if (path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root)
                and path.stat().st_size <= MAX_ENTRY):
            candidates.setdefault(path.name.casefold(), []).append(path)
    results = []
    for entry in entries:
        if not entry["name"].lower().endswith(".dll"):
            continue
        name = PurePosixPath(entry["name"]).name
        paths = candidates.get(name.casefold(), [])
        matched = bool(entry["sha256"]) and any(hashlib.sha256(p.read_bytes()).hexdigest() == entry["sha256"] for p in paths)
        results.append({"name": name, "pack_candidates": len(paths), "matches_pack": matched})
    return results


def main(service, worker, inputs, toc, pack_dir, extracted, output):
    service_path, worker_path = Path(service), Path(worker)
    if service_path.stat().st_size > MAX_BINARY or worker_path.stat().st_size > MAX_BINARY:
        raise ValueError("candidate too large")
    report = {
        "dotnet_bundle": inspect_dotnet(service_path.read_bytes()),
        "worker": inspect_worker(worker_path, json.loads(Path(inputs).read_text(encoding="utf-8-sig")), Path(extracted)),
    }
    roots = [("venv", Path(sys.prefix)), ("python", Path(sys.base_prefix))]
    for key, label in (("SystemRoot", "windows"), ("ProgramFiles", "program_files"),
                       ("ProgramFiles(x86)", "program_files_x86"), ("RUNNER_TEMP", "runner_temp")):
        if os.environ.get(key):
            roots.append((label, Path(os.environ[key])))
    if os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_TOOL_CACHE"):
        roots.append(("runner_tool_cache", Path(os.environ["RUNNER_TOOL_CACHE"])))
    report["worker"]["source_comparisons"] = map_worker_sources(
        report["worker"]["entries"], Path(toc).read_text(encoding="utf-8"), roots)
    report["dotnet_bundle"]["pack_comparisons"] = map_dotnet_sources(
        report["dotnet_bundle"]["entries"], Path(pack_dir))
    Path(output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 8:
        raise SystemExit("expected service, worker, input metadata, TOC, runtime pack, extraction directory, and output")
    main(*sys.argv[1:])
