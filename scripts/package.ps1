<#
.SYNOPSIS
Builds the AWGSocks release zip from committed source.

.DESCRIPTION
Clones the repository into a temporary directory, checks out the requested
commit, builds it with scripts\build.bat, and zips the executable, the licence
and the service scripts into awgsocks-<version>-windows-amd64.zip beside a
SHA256SUMS.txt.

Building from a fresh clone rather than the working tree is the point: nothing
uncommitted, untracked or ignored can end up in a release, so the zip matches
what the commit says it is.

Run it through scripts\package.bat, which gets past the default execution
policy.

.PARAMETER Ref
The commit, tag or branch to package. Defaults to HEAD.

.PARAMETER OutDir
Where the zip and SHA256SUMS.txt are written. Defaults to release\ in the
repository, which git ignores. An existing zip of the same name is replaced.
#>
[CmdletBinding()]
param(
    [string]$Ref = 'HEAD',
    [string]$OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The operator scripts shipped beside the executable. They are listed rather
# than globbed, so a stray file in windows\ cannot slip into a release, and a
# test in cmd/awgsocks keeps this list equal to the scripts the executable
# names and to what windows\ holds.
$scripts = @(
    'service-install.bat',
    'service-start.bat',
    'service-stop.bat',
    'service-status.bat',
    'service-config.bat',
    'service-uninstall.bat'
)

function Invoke-Checked {
    param([string]$What, [scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE"
    }
}

$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) {
    $OutDir = Join-Path $repo 'release'
}

$sha = git -C $repo rev-parse --verify --quiet "$Ref^{commit}"
if ($LASTEXITCODE -ne 0 -or -not $sha) {
    throw "'$Ref' does not name a commit in $repo"
}
if ($Ref -eq 'HEAD' -and (git -C $repo status --porcelain)) {
    Write-Warning 'The working tree has changes that are not committed. They are not in this package.'
}

# Short on purpose, and git is told to allow long paths: pack files under .git
# add some sixty characters, and a temporary directory that is already deep
# pushes a clone past the 260 character limit Windows still applies by default.
$work = Join-Path ([IO.Path]::GetTempPath()) ('awgpkg-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    Write-Host "Cloning $sha into a clean directory"
    Invoke-Checked 'git clone' { git -c core.longpaths=true clone --quiet --no-local --no-checkout $repo $work }
    Invoke-Checked 'git checkout' { git -C $work -c core.longpaths=true checkout --quiet --detach $sha }

    $windowsDir = Join-Path $work 'windows'
    if (-not (Test-Path -LiteralPath $windowsDir)) {
        throw "$sha has no windows\ directory, so it predates the layout this script packages"
    }
    $present = @(Get-ChildItem -LiteralPath $windowsDir -Filter '*.bat' -File |
        ForEach-Object { $_.Name } | Sort-Object)
    $listed = @($scripts | Sort-Object)
    if (Compare-Object $present $listed) {
        throw "windows\ holds [$($present -join ', ')] but this script ships [$($listed -join ', ')]. Update the list."
    }

    Invoke-Checked 'scripts\build.bat' { cmd.exe /d /c "`"$work\scripts\build.bat`"" }

    $buildScript = Get-Content -LiteralPath (Join-Path $work 'scripts\build.bat')
    $versionLine = $buildScript | Where-Object { $_ -match '^set VERSION=(\S+)$' } | Select-Object -First 1
    if (-not $versionLine) {
        throw 'scripts\build.bat no longer sets VERSION'
    }
    $version = ($versionLine -replace '^set VERSION=', '').Trim()
    $short = git -C $work rev-parse --short HEAD

    $exe = Join-Path $work 'awgsocks.exe'
    $banner = & $exe version | Select-Object -First 1
    $expected = "AWGSocks $version (commit $short,"
    if (-not $banner.StartsWith($expected)) {
        throw "the built executable says '$banner', expected it to start with '$expected'"
    }

    $files = @($exe, (Join-Path $work 'LICENSE')) + @($scripts | ForEach-Object { Join-Path $work "windows\$_" })

    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $zipName = "awgsocks-$version-windows-amd64.zip"
    $zip = Join-Path (Resolve-Path -LiteralPath $OutDir) $zipName
    $sums = Join-Path (Resolve-Path -LiteralPath $OutDir) 'SHA256SUMS.txt'
    foreach ($old in @($zip, $sums)) {
        if (Test-Path -LiteralPath $old) {
            Remove-Item -LiteralPath $old -Force
        }
    }

    Compress-Archive -LiteralPath $files -DestinationPath $zip -CompressionLevel Optimal

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $entries = @($archive.Entries | ForEach-Object { $_.FullName })
    } finally {
        $archive.Dispose()
    }
    $wanted = @(@('awgsocks.exe', 'LICENSE') + $scripts)
    if (Compare-Object ($entries | Sort-Object) ($wanted | Sort-Object)) {
        throw "the zip holds [$($entries -join ', ')], expected [$($wanted -join ', ')]"
    }

    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    "$hash  $zipName" | Out-File -LiteralPath $sums -Encoding ascii

    $tags = @(git -C $repo tag --points-at $sha)
    $tagNote = if ($tags -contains "v$version") { "tagged v$version" } else { "NOT tagged v$version" }

    Write-Host ''
    Write-Host "Package : $zip"
    Write-Host ("Size    : {0:N2} MB" -f ((Get-Item -LiteralPath $zip).Length / 1MB))
    Write-Host "SHA256  : $hash"
    Write-Host "Commit  : $sha ($tagNote)"
    Write-Host "Banner  : $banner"
    Write-Host "Entries : $($entries -join ', ')"
} finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
