# Build and distribution dependencies

The source snapshot contains only the owner's MIT-licensed files. The hosted
build separately downloads Python, PyInstaller, websockets, WiX and .NET.
Their licenses are independent of the source license:

| Dependency | Reference | Role |
| --- | --- | --- |
| Python | https://docs.python.org/3/license.html | Interpreter bundled in the worker |
| OpenSSL | https://www.openssl.org/source/license.html | Native libraries bundled with Python |
| Microsoft Visual C++ runtime | https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files | Native DLLs bundled with Python |
| PyInstaller 6.22.3 | https://github.com/pyinstaller/pyinstaller/blob/v6.22.3/COPYING.txt | Build tool and bootloader; GPL with exception |
| websockets 17.2 | https://github.com/python-websockets/websockets/blob/17.2/LICENSE | Worker dependency, BSD-3-Clause |
| WiX 6.0.0 | https://github.com/wixtoolset/wix/blob/v6.0.0/LICENSE.TXT | Installer build tool |
| .NET 10 Windows | https://github.com/dotnet/core/blob/main/license-information.md | Self-contained service runtime |

This is a preliminary list, not an SBOM or permission to redistribute the
output. Exact transitive packages, embedded files and required notices must be
established from the actual build before publication or signing. In particular,
the SignPath system-library exception for the Windows .NET distribution has not
been determined. The workflow verifies the committed wheel hashes and records
exact notice files from the wheelhouse used in its isolated build. Copies of
the eight pinned wheels' notices are preserved in `third_party_notices/wheels`.
It also records available Python and .NET runtime notices and reports missing ones;
this evidence does not establish completeness for the packaged runtimes or
native DLLs. It does not sign or publish its binary output.

Microsoft documents Visual C++ runtime redistribution as subject to Visual
Studio licensing and its terms. Python's Windows license also contains
additional Microsoft distributable-code conditions. The applicable rights
for the exact runtime copies and SignPath's system-library exception remain
unverified; an MIT source license does not settle those questions.

The CI performs administrative MSI extraction on a hosted runner, verifies
that its worker and service match the just-built inputs, and inventories
embedded .NET and PyInstaller files without uploading binaries. Input hashes,
archive inventories and individual license texts are evidence for review;
they do not themselves establish redistribution rights or provider approval.

The test MSI now includes `ThirdPartyNotices.zip`, assembled from the pinned
source notices and the installed Python and .NET license files. CI checks that
the archive extracted from the MSI matches its build input. The .NET Library
terms also place conditions on distribution, including end-user terms and
indemnification. The notice archive alone does not satisfy or accept those
conditions, establish complete native-DLL coverage, or approve a release.
