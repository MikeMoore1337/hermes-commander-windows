$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/h454_verify_notices.ps1')
$root = Join-Path ([IO.Path]::GetFullPath($env:RUNNER_TEMP)) ('h454-notice-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
try {
    $digest = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    function Expect-Denied([string]$hash) {
        try { Assert-H454Notices $root $hash } catch { return }
        throw 'EXPECTED_NOTICE_REJECTION'
    }
    Expect-Denied $digest
    [IO.File]::WriteAllText((Join-Path $root 'ThirdPartyNotices.zip'), 'abc', [Text.Encoding]::ASCII)
    Assert-H454Notices $root $digest
    Expect-Denied ('0' * 64)
    Expect-Denied 'invalid'
    New-Item -ItemType Directory -Path (Join-Path $root 'duplicate') | Out-Null
    [IO.File]::WriteAllText((Join-Path $root 'duplicate/ThirdPartyNotices.zip'), 'abc', [Text.Encoding]::ASCII)
    Expect-Denied $digest
    Write-Output 'NOTICE_GATE_TESTS=PASS'
} finally {
    $parent = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    if (-not ([IO.Path]::GetFullPath($root)).StartsWith($parent, [StringComparison]::OrdinalIgnoreCase)) { throw 'UNSAFE_TEST_CLEANUP' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
