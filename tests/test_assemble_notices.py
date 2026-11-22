import json
import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.assemble_notices import assemble


class NoticeArchiveTests(unittest.TestCase):
    def test_upstream_notices_keep_their_original_git_blobs(self):
        root = Path(__file__).resolve().parents[1] / "third_party_notices"
        originals = {
            "python-3.14.10/LICENSE.txt": "20cf39097c68baa17cc566b64e76d34ebf034044",
            "python-3.14.10/license.rst": "56073c9118f672e29917f0eaea7073edf253d884",
            "python-3.14.10/crtlicense.txt": "f86841f263efe824f4336d162a6662881a7aad10",
            "xz-5.2.5/COPYING": "20e60d5b2427334e1fec6701e7c5ad0da0bc8a5d",
            "xz-5.2.5/COPYING.GPLv2": "d159169d1050894d3ea3b98e1c965c4058208fe1",
            "xz-5.2.5/COPYING.GPLv3": "94a9ed024d3859793618152ea559a168bbcbb5e2",
            "xz-5.2.5/COPYING.LGPLv2.1": "4362b49151d7b34ef83b3067a8f9c9f877d72a0e",
        }
        for name, expected in originals.items():
            with self.subTest(name=name):
                data = (root / name).read_bytes()
                actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                self.assertEqual(actual, expected)

    def test_preserves_notice_bytes_and_requires_windows_crt_terms(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, python, dotnet, pack = (root / name for name in ("repo", "python", "dotnet", "pack"))
            for directory in (repo, python, dotnet, pack):
                directory.mkdir()
            for relative in ("python-3.14.10/LICENSE.txt", "python-3.14.10/license.rst", "python-3.14.10/crtlicense.txt", "openssl-3.5.9/LICENSE.txt", "xz-5.2.5/COPYING", "wheels/example-1-py3-none-any/LICENSE"):
                p = repo / "third_party_notices" / relative
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"original\r\n")
            (repo / "third_party_notices/wheels/wheels.json").write_text(json.dumps([
                {"wheel": "example-1-py3-none-any.whl", "license_paths": ["example.dist-info/LICENSE"]}
            ]), encoding="utf-8")
            (repo / "LICENSE").write_bytes(b"MIT")
            (python / "LICENSE.txt").write_bytes(b"Microsoft Distributable Code\r\n")
            (dotnet / "LICENSE.txt").write_bytes(b"dotnet license")
            (dotnet / "ThirdPartyNotices.txt").write_bytes(b"dotnet notices")
            (pack / "LICENSE.TXT").write_bytes(b"runtime pack license")
            (pack / "THIRD-PARTY-NOTICES.TXT").write_bytes(b"runtime pack notices")
            output = root / "notices.zip"
            assemble(repo, python, dotnet, pack, output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read("upstream/openssl-3.5.9/LICENSE.txt"), b"original\r\n")
                self.assertEqual(archive.read("python-distribution/LICENSE.txt"), b"Microsoft Distributable Code\r\n")
                self.assertEqual(archive.read("dotnet-runtimepack/LICENSE.TXT"), b"runtime pack license")
            second = root / "notices-again.zip"
            assemble(repo, python, dotnet, pack, second)
            self.assertEqual(output.read_bytes(), second.read_bytes())
            with self.assertRaises(ValueError):
                assemble(repo, python, dotnet, pack, output)
            (repo / "third_party_notices/wheels/example-1-py3-none-any/LICENSE").unlink()
            with self.assertRaises(ValueError):
                assemble(repo, python, dotnet, pack, root / "missing-wheel.zip")
            self.assertFalse((root / "missing-wheel.zip").exists())
            (python / "LICENSE.txt").write_bytes(b"missing CRT")
            (repo / "third_party_notices/wheels/example-1-py3-none-any/LICENSE").write_bytes(b"original\r\n")
            with self.assertRaises(ValueError):
                assemble(repo, python, dotnet, pack, root / "denied.zip")
            (python / "LICENSE.txt").write_bytes(b"Microsoft Distributable Code")
            (pack / "THIRD-PARTY-NOTICES.TXT").unlink()
            with self.assertRaises(ValueError):
                assemble(repo, python, dotnet, pack, root / "missing-pack.zip")
            self.assertFalse((root / "missing-pack.zip").exists())


if __name__ == "__main__":
    unittest.main()
