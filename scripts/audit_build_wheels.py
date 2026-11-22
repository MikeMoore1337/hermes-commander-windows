"""Copy unmodified wheel license files and hash the exact build inputs."""
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

LICENSE = re.compile(
    r"^[^/]+\.dist-info/(?:licenses/)?(?:LICENSE|COPYING|NOTICE)(?:[._-][^/]*)?$",
    re.IGNORECASE,
)
LIMIT = 1024 * 1024


def audit(wheelhouse: Path, output: Path) -> None:
    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels or output.exists():
        raise ValueError("invalid wheelhouse or existing output")
    output.mkdir(parents=True)
    records = []
    for index, wheel in enumerate(wheels):
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        licenses = []
        with zipfile.ZipFile(wheel) as archive:
            for info in archive.infolist():
                if not LICENSE.fullmatch(info.filename):
                    continue
                if info.file_size > LIMIT or info.filename in licenses:
                    raise ValueError("unsafe or duplicate license")
                content = archive.read(info)
                name = f"{index:02d}-{len(licenses):02d}.txt"
                (output / name).write_bytes(content)
                licenses.append(info.filename)
        records.append({"wheel": wheel.name, "sha256": digest, "license_paths": licenses})
    (output / "wheels.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("expected wheelhouse and new output directory")
    audit(Path(sys.argv[1]), Path(sys.argv[2]))
