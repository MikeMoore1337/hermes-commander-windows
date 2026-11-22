import struct
import sys
import types
import unittest
from unittest.mock import patch

from scripts.inspect_payload import inspect_dotnet, inspect_worker


def bundle(name=b"test.dll", content=b"abc", *, start=40, compressed=0):
    header_offset = 40 + len(content)
    header = struct.pack("<IIi", 6, 0, 1) + b"\x02id" + bytes(40)
    entry = struct.pack("<qqqB", start, len(content), compressed, 1) + bytes([len(name)]) + name
    marker = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
    return struct.pack("<q", header_offset) + marker + content + header + entry


class BundleInspectionTests(unittest.TestCase):
    def test_reads_real_bundle_layout_and_hashes_entry(self):
        result = inspect_dotnet(bundle())
        self.assertEqual(result["entries"][0]["name"], "test.dll")
        self.assertEqual(result["entries"][0]["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_rejects_traversal_offsets_and_truncation(self):
        for data in (bundle(b"../x.dll"), bundle(b"x\x00.dll"), bundle(start=99999), bundle()[:-1]):
            with self.subTest(size=len(data)), self.assertRaises((ValueError, UnicodeError)):
                inspect_dotnet(data)

    def test_compressed_entry_is_not_claimed_verified(self):
        self.assertIsNone(inspect_dotnet(bundle(compressed=2))["entries"][0]["sha256"])

    def test_reads_runtime_configuration(self):
        result = inspect_dotnet(bundle(b"app.runtimeconfig.json", b'{"runtimeOptions":{"tfm":"net10.0"}}'))
        self.assertEqual(result["runtime_config"]["runtimeOptions"]["tfm"], "net10.0")

    def test_worker_reports_both_matching_and_mismatching_inputs(self):
        reader = types.ModuleType("PyInstaller.archive.readers")

        class Archive:
            toc = {"python314.dll": (0, 3, 3, 0, "b")}

            def __init__(self, _):
                pass

            def extract(self, _):
                return b"abc"

        reader.CArchiveReader = Archive
        modules = {"PyInstaller": types.ModuleType("PyInstaller"),
                   "PyInstaller.archive": types.ModuleType("PyInstaller.archive"),
                   "PyInstaller.archive.readers": reader}
        with patch.dict(sys.modules, modules):
            result = inspect_worker("candidate.exe", [
                {"name": "python314.dll", "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
                {"name": "missing.dll", "sha256": "0" * 64},
            ])
        self.assertEqual([x["matches"] for x in result["input_comparisons"]], [True, False])


if __name__ == "__main__":
    unittest.main()
