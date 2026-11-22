# Build and distribution dependencies

The source snapshot contains only the owner's MIT-licensed files. The hosted
build separately downloads Python, PyInstaller, websockets, WiX and .NET.
Their licenses are independent of the source license:

| Dependency | Reference | Role |
| --- | --- | --- |
| Python | https://docs.python.org/3/license.html | Interpreter bundled in the worker |
| OpenSSL | https://www.openssl.org/source/license.html | Native libraries bundled with Python |
| PyInstaller 6.22.3 | https://github.com/pyinstaller/pyinstaller/blob/v6.22.3/COPYING.txt | Build tool and bootloader; GPL with exception |
| websockets 17.2 | https://github.com/python-websockets/websockets/blob/17.2/LICENSE | Worker dependency, BSD-3-Clause |
| WiX 6.0.0 | https://github.com/wixtoolset/wix/blob/v6.0.0/LICENSE.TXT | Installer build tool |
| .NET 10 Windows | https://github.com/dotnet/core/blob/main/license-information.md | Self-contained service runtime |

This is a preliminary list, not an SBOM or permission to redistribute the
output. Exact transitive packages, embedded files and required notices must be
established from the actual build before publication or signing. In particular,
the SignPath system-library exception for the Windows .NET distribution has not
been determined. The workflow verifies the committed wheel hashes and records
exact notice files from the wheelhouse used in its isolated build. It also
records available Python and .NET runtime notices and reports missing ones;
this evidence does not establish completeness for the packaged runtimes or
native DLLs. It does not sign or publish its binary output.
