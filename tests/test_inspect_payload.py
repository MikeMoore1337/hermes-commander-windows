import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.inspect_payload import inspect_dotnet, inspect_worker, map_dotnet_sources, map_worker_sources


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

    def test_reads_actual_dependency_identifiers(self):
        result = inspect_dotnet(bundle(b"app.deps.json", b'{"libraries":{"runtimepack/10.0.0":{}}}'))
        self.assertEqual(result["dependency_libraries"], ["runtimepack/10.0.0"])

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
        with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, modules):
            extracted = Path(tmp) / "files"
            result = inspect_worker("candidate.exe", [
                {"name": "python314.dll", "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
                {"name": "missing.dll", "sha256": "0" * 64},
            ], extracted)
            self.assertEqual((extracted / (result["entries"][0]["sha256"] + ".dll")).read_bytes(), b"abc")
            with self.assertRaises(FileExistsError):
                inspect_worker("candidate.exe", [], extracted)
        self.assertEqual([x["matches"] for x in result["input_comparisons"]], [True, False])

    def test_source_mapping_requires_matching_bytes_and_an_approved_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allowed = root / "allowed"
            allowed.mkdir()
            source = allowed / "input.dll"
            source.write_bytes(b"abc")
            digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            entries = [{"name": "input.dll", "sha256": digest}, {"name": "missing.dll", "sha256": digest}]
            toc = repr(([('input.dll', str(source), 'BINARY')],))
            mapped = map_worker_sources(entries, toc, [("python", allowed)])
            self.assertEqual(mapped[0]["matching_sources"], ["python"])
            self.assertEqual(map_worker_sources(entries, toc, [("runner_tool_cache", allowed)])[0]["matching_sources"], ["runner_tool_cache/other"])
            self.assertEqual(mapped[1]["matching_sources"], [])
            self.assertEqual(map_worker_sources(entries, toc, [("other", root / "elsewhere")])[0]["matching_sources"], [])
            self.assertEqual(map_worker_sources(entries, toc, [("other", root / "elsewhere")])[0]["diagnostics"][0]["status"], "not-read")
            self.assertTrue(map_dotnet_sources(entries, allowed)[0]["matches_pack"])
            source.write_bytes(b"changed")
            self.assertFalse(map_dotnet_sources(entries, allowed)[0]["matches_pack"])
            self.assertEqual(map_worker_sources(entries, toc, [("python", allowed)])[0]["diagnostics"][0]["status"], "different-bytes")


if __name__ == "__main__":
    unittest.main()
