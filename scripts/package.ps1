$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot = Join-Path $projectRoot 'artifacts'
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
$stagePath = [IO.Path]::GetFullPath((Join-Path $artifactRoot ('package-stage-' + [guid]::NewGuid().ToString('N'))))
if (-not $stagePath.StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Staging path escaped artifact directory.'
}
New-Item -ItemType Directory -Path $stagePath | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $projectRoot 'build\bin\AppCleanupDoctor.exe') -Destination $stagePath
    foreach ($name in @('LICENSE', 'README.md', 'SECURITY.md', 'RELEASE_NOTES.md')) {
        Copy-Item -LiteralPath (Join-Path $projectRoot $name) -Destination $stagePath
    }
    Copy-Item -LiteralPath (Join-Path $projectRoot 'docs') -Destination $stagePath -Recurse
    $zipPath = Join-Path $artifactRoot 'AppCleanupDoctor-v0.1.0-scan-only-win-x64.zip'
    Compress-Archive -Path (Join-Path $stagePath '*') -DestinationPath $zipPath -Force
    $digest = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $entry = $digest + '  ' + [IO.Path]::GetFileName($zipPath) + "`n"
    [IO.File]::WriteAllText($zipPath + '.sha256', $entry, [Text.UTF8Encoding]::new($false))
    Write-Output ('Local development package: ' + [IO.Path]::GetFileName($zipPath))
    Write-Output ('SHA-256: ' + $digest)
} finally {
    # Only the exact newly created staging directory inside artifacts is removed.
    Remove-Item -LiteralPath $stagePath -Recurse -Force
}
