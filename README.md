# Hermes Commander Windows native component

This source snapshot contains the owner's Windows read-only native worker,
disabled service and installer sources. It is derived from Hermes commit
`13584072697c901ae1da575dee2898cfee890779`; the copied file hashes were
checked against the owner's Windows source inventory. The source is provided
under the MIT license in `LICENSE`. `SOURCE-PROVENANCE.json` records the
original Git blob identifiers for the initial snapshot.

This is a development snapshot, not a signed release. The installer is designed
to install an unprovisioned, disabled service; the source alone does not pair a
device or grant access to files. Its project-root policy is owner-specific and
is not a general-purpose setup flow. Do not install a build from this snapshot
without independently verifying its signature, provenance and configuration.

The Windows build workflow creates temporary unsigned test outputs on a hosted
runner and publishes metadata, not binaries. Signing, distribution, dependency notices,
provider eligibility and the complete Windows onboarding process remain open.
No telemetry is intentionally added by this snapshot. Its worker is tied to
the owner's relay endpoints embedded in the source and contacts them when
provisioned; it is not a configurable multi-user release.

Python, PyInstaller, websockets, WiX and .NET have their own licenses. Their
terms are not replaced by this repository's MIT grant; a distributable package
must include all notices required by its actual resolved dependencies. On
Windows, .NET product distributions have their own license terms.
