"""Assemble unchanged first- and third-party notices for a test MSI."""
from pathlib import Path
import json
import re
import sys
import zipfile

LIMIT = 2 * 1024 * 1024


def assemble(repo: Path, python_home: Path, dotnet_root: Path, runtime_pack: Path, output: Path) -> None:
    if output.exists():
        raise ValueError("notice output already exists")
    source = repo / "third_party_notices"
    required = [source / "python-3.14.10" / "LICENSE.txt",
                source / "python-3.14.10" / "license.rst",
                source / "python-3.14.10" / "crtlicense.txt",
                source / "openssl-3.5.9" / "LICENSE.txt",
                source / "xz-5.2.5" / "COPYING",
                source / "wheels" / "wheels.json"]
    if source.is_symlink() or source.is_junction() or any(not p.is_file() or p.is_symlink() for p in required):
        raise ValueError("required source notice missing")
    wheel_rows = json.loads((source / "wheels" / "wheels.json").read_text(encoding="utf-8-sig"))
    if not isinstance(wheel_rows, list) or not wheel_rows:
        raise ValueError("empty wheel notice manifest")
    for row in wheel_rows:
        wheel = row["wheel"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", wheel) or not row["license_paths"]:
            raise ValueError("invalid wheel notice manifest")
        for original in row["license_paths"]:
            name = original.rsplit("/", 1)[-1]
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not (source / "wheels" / wheel[:-4] / name).is_file():
                raise ValueError("wheel notice missing")
    files = {"first-party/LICENSE.txt": repo / "LICENSE",
             "python-distribution/LICENSE.txt": python_home / "LICENSE.txt",
             "dotnet-distribution/LICENSE.txt": dotnet_root / "LICENSE.txt",
             "dotnet-distribution/ThirdPartyNotices.txt": dotnet_root / "ThirdPartyNotices.txt",
             "dotnet-runtimepack/LICENSE.TXT": runtime_pack / "LICENSE.TXT",
             "dotnet-runtimepack/THIRD-PARTY-NOTICES.TXT": runtime_pack / "THIRD-PARTY-NOTICES.TXT"}
    for path in source.rglob("*"):
        if path.is_symlink() or path.is_junction():
            raise ValueError("symlink in source notices")
        if path.is_file():
            path.resolve().relative_to(source.resolve())
            files["upstream/" + path.relative_to(source).as_posix()] = path
    if len(files) > 128:
        raise ValueError("too many notices")
    content = {}
    for name, path in files.items():
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= LIMIT:
            raise ValueError("missing or unsafe notice")
        content[name] = path.read_bytes()
    if b"Microsoft Distributable Code" not in content["python-distribution/LICENSE.txt"]:
        raise ValueError("Python Windows CRT notice missing")
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(content.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)


if __name__ == "__main__":
    if len(sys.argv) != 6:
        raise SystemExit("expected repository, Python root, .NET root, runtime pack and new output")
    assemble(*(Path(arg) for arg in sys.argv[1:]))
