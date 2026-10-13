$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'wails.json') -Raw | ConvertFrom-Json).info.productVersion
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid product version.' }
$exePath = Join-Path $projectRoot 'build\bin\AppCleanupDoctor.exe'
$metadata = [Diagnostics.FileVersionInfo]::GetVersionInfo($exePath)
if ($metadata.ProductVersion -ne $version -or $metadata.ProductName -ne 'App Cleanup Doctor' -or $metadata.CompanyName -ne 'ALMARFELD') { throw 'Executable metadata does not match package configuration.' }
$artifactRoot = Join-Path $projectRoot 'artifacts'
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
$stagePath = [IO.Path]::GetFullPath((Join-Path $artifactRoot ('package-stage-' + [guid]::NewGuid().ToString('N'))))
if (-not $stagePath.StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Staging path escaped artifact directory.'
}
New-Item -ItemType Directory -Path $stagePath | Out-Null
try {
    Copy-Item -LiteralPath $exePath -Destination $stagePath
    foreach ($name in @('LICENSE', 'README.md', 'SECURITY.md', 'RELEASE_NOTES.md', 'THIRD_PARTY_NOTICES.txt')) {
        Copy-Item -LiteralPath (Join-Path $projectRoot $name) -Destination $stagePath
    }
    New-Item -ItemType Directory -Path (Join-Path $stagePath 'docs') | Out-Null
    foreach ($name in @('architecture.md', 'safety-model.md', 'VALIDATION.md')) {
        Copy-Item -LiteralPath (Join-Path $projectRoot ('docs\' + $name)) -Destination (Join-Path $stagePath 'docs')
    }
    $zipPath = Join-Path $artifactRoot "AppCleanupDoctor-v$version-win-x64.zip"
    Compress-Archive -Path (Join-Path $stagePath '*') -DestinationPath $zipPath -Force
    $digest = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $entry = $digest + '  ' + [IO.Path]::GetFileName($zipPath) + "`n"
    [IO.File]::WriteAllText($zipPath + '.sha256', $entry, [Text.UTF8Encoding]::new($false))
    Write-Output ('Portable package: ' + [IO.Path]::GetFileName($zipPath))
    Write-Output ('SHA-256: ' + $digest)
} finally {
    # Only the exact newly created staging directory inside artifacts is removed.
    Remove-Item -LiteralPath $stagePath -Recurse -Force
}
