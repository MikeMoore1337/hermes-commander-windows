import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.audit_build_wheels import audit


class WheelAuditTests(unittest.TestCase):
    def test_preserves_exact_notice_and_does_not_extract_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheelhouse = root / "wheels"
            wheelhouse.mkdir()
            with zipfile.ZipFile(wheelhouse / "example-1-py3-none-any.whl", "w") as z:
                z.writestr("example-1.dist-info/licenses/LICENSE", b"original notice\r\n")
                z.writestr("../../outside", b"not extracted")
            audit(wheelhouse, root / "evidence")
            self.assertEqual((root / "evidence" / "00-00.txt").read_bytes(), b"original notice\r\n")
            data = json.loads((root / "evidence" / "wheels.json").read_text(encoding="utf-8"))
            self.assertEqual(data[0]["license_paths"], ["example-1.dist-info/licenses/LICENSE"])
            self.assertFalse((root / "outside").exists())
            with self.assertRaises(ValueError):
                audit(wheelhouse, root / "evidence")


if __name__ == "__main__":
    unittest.main()
