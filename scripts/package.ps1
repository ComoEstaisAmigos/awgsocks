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

The zip is reproducible. Every input is a function of the commit, including the
build date and the entry timestamps, which are the commit date, and the Go
toolchain, which is pinned below. Packaging the same commit again, anywhere,
gives the same SHA256.

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

# Releases are built with exactly this Go toolchain. The same source built by
# another Go version is a different binary, so without the pin two people
# packaging the same commit would publish two hashes. The go command downloads
# this version by itself when a different one is installed.
$goToolchain = 'go1.27.1'

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
    # Without tags. go build stamps the main module version from them, so a
    # clone that has v1.0.0 would embed v1.0.1-0.<date>-<commit> and one that
    # does not, such as a shallow CI checkout, v0.0.0-<date>-<commit>: the same
    # commit, two binaries. Which tags a packager happens to have fetched must
    # not decide the hash.
    Invoke-Checked 'git clone' { git -c core.longpaths=true clone --quiet --no-local --no-tags --no-checkout $repo $work }
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

    # Everything that goes into the zip is a function of the commit. Its date
    # stands in for the build time, both inside the executable and on every zip
    # entry, and the Go settings a user environment could change are reset so
    # that nobody's shell configuration leaks into a release.
    $epoch = [long](git -C $work log -1 --format=%ct)
    $stamp = [DateTimeOffset]::FromUnixTimeSeconds($epoch)
    $env:SOURCE_DATE_EPOCH = "$epoch"
    $env:GOTOOLCHAIN = $goToolchain
    $env:GOAMD64 = 'v1'
    $env:GOFLAGS = ''
    $env:GOEXPERIMENT = ''

    Invoke-Checked 'scripts\build.bat' { cmd.exe /d /c "`"$work\scripts\build.bat`"" }

    $buildScript = Get-Content -LiteralPath (Join-Path $work 'scripts\build.bat')
    $versionLine = $buildScript | Where-Object { $_ -match '^set VERSION=(\S+)$' } | Select-Object -First 1
    if (-not $versionLine) {
        throw 'scripts\build.bat no longer sets VERSION'
    }
    $version = ($versionLine -replace '^set VERSION=', '').Trim()
    $short = git -C $work rev-parse --short=7 HEAD

    $exe = Join-Path $work 'awgsocks.exe'
    $banner = & $exe version | Select-Object -First 1
    $expected = "AWGSocks $version (commit $short, built $($stamp.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')))"
    if ($banner -ne $expected) {
        throw "the built executable says '$banner', expected '$expected'"
    }
    $builtWith = (go version $exe) -replace '^.*:\s*', ''
    if ($builtWith -ne $goToolchain) {
        throw "the executable was built with $builtWith, expected $goToolchain"
    }
    $mainModule = go version -m $exe | Where-Object { $_ -match '^\s+mod\s+github\.com/ComoEstaisAmigos/awgsocks\s' } | Select-Object -First 1
    if (-not $mainModule -or $mainModule -notmatch '\sv0\.0\.0-\d{14}-[0-9a-f]{12}(\s|$)') {
        throw "the executable records its own module as '$mainModule'; a version derived from tags makes the hash depend on the packager's clone"
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

    # Written entry by entry rather than with Compress-Archive, which stamps each
    # entry with the file's modification time: in a fresh clone that is the
    # moment of the checkout, so every run would produce a different zip. The
    # timestamp has to be set before an entry is opened, because a ZipArchive in
    # Create mode refuses to change an entry once its data has been written.
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $stream = [IO.File]::Open($zip, [IO.FileMode]::CreateNew)
    try {
        $writer = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($file in $files) {
                $entry = $writer.CreateEntry((Split-Path -Leaf $file), [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $stamp
                $out = $entry.Open()
                $in = [IO.File]::OpenRead($file)
                try {
                    $in.CopyTo($out)
                } finally {
                    $in.Dispose()
                    $out.Dispose()
                }
            }
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }

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
    Write-Host "Go      : $builtWith"
    Write-Host "Entries : $($entries -join ', ')"
} finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
