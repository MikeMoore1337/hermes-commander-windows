import unittest

from scripts.h15_native_windows_read import NativeReadRefused, build_request
from scripts.h454_native_win32_worker import service_sid_verified


class BoundaryTests(unittest.TestCase):
    def test_read_scope_allows_readme_and_rejects_secrets_and_traversal(self):
        _, path = build_request("hermes", "README.md", "stat")
        self.assertTrue(path.endswith("README.md"))
        for path in (".env", "..\\outside.txt", ".git\\config"):
            with self.subTest(path=path), self.assertRaises(NativeReadRefused):
                build_request("hermes", path, "stat")

    def test_non_service_process_is_not_the_native_service(self):
        self.assertFalse(service_sid_verified())


if __name__ == "__main__":
    unittest.main()
