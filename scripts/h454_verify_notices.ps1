function Assert-H454Notices([string]$ExtractedRoot, [string]$ExpectedSha256) {
    if ($ExpectedSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'NOTICE_DIGEST_INVALID' }
    $notices = @(Get-ChildItem -LiteralPath $ExtractedRoot -Recurse -File |
        Where-Object { $_.Name -ceq 'ThirdPartyNotices.zip' })
    if ($notices.Count -ne 1 -or
        ($notices[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $notices[0].Length -le 0 -or $notices[0].Length -gt 16MB -or
        (Get-FileHash -LiteralPath $notices[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256) {
        throw 'NOTICE_MISMATCH'
    }
}
