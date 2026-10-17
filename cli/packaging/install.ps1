# Installs the standalone tdxguard executable (no Python needed) on Windows.
#
#   irm https://raw.githubusercontent.com/tda-corp/tdx-guard-ci/main/install.ps1 | iex
#
# Works in Windows PowerShell 5.1 and PowerShell 7. Environment:
#   TDXGUARD_VERSION      the version to install, e.g. 0.2.0 (default: the latest cli-v* release)
#   TDXGUARD_INSTALL_DIR  where tdxguard.exe goes (default: %LOCALAPPDATA%\Programs\tdxguard)
#   GITHUB_TOKEN          optional; raises the GitHub API rate limit when resolving the version
#
# The download is verified against the release's checksums.txt (sha256) and refused when it
# does not match. The install directory is added to the user's PATH; no administrator
# rights are needed.
#
# Windows on ARM64: Windows 11 runs the x86_64 executable (and the x86_64 scanners) under
# its x64 emulation, so the x86_64 build is installed there, with a warning. Windows 10 on
# ARM64 cannot run x64 programs and is refused.
#
# Testing only: TDXGUARD_DOWNLOAD_BASE and TDXGUARD_API_BASE replace the GitHub URLs, and
# TDXGUARD_INSTALL_NO_RUN=1 only defines the functions (for dot-sourcing in tests).

# Run through `irm | iex`, this script runs in the caller's session: preferences are set
# inside the functions, so the caller's own settings are left alone.
$TdxRepository = 'tda-corp/tdx-guard-ci'

function Get-TdxPlatform {
    <# The asset suffix (windows-x86_64) of this machine, or a terminating error. #>
    param(
        [string]$Architecture = $(if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }),
        [int]$Build = [Environment]::OSVersion.Version.Build
    )
    switch ($Architecture.ToUpperInvariant()) {
        'AMD64' { return 'windows-x86_64' }
        'ARM64' {
            if ($Build -ge 22000) {
                Write-Warning 'Windows on ARM64: installing the x86_64 build, which runs under the x64 emulation of Windows 11. This combination is not tested.'
                return 'windows-x86_64'
            }
            throw 'tdxguard needs Windows 11 on ARM64 (x64 emulation); Windows 10 on ARM64 cannot run it. Use WSL, or install it with Python 3.9+: pipx install "git+https://github.com/tda-corp/tdx-guard-ci#subdirectory=cli"'
        }
        default {
            throw "No tdxguard executable for Windows on $Architecture (only x86_64). Install it with Python 3.9+: pipx install `"git+https://github.com/tda-corp/tdx-guard-ci#subdirectory=cli`""
        }
    }
}

function Select-TdxRelease {
    <# The tag of the newest published cli-v* release in a GitHub releases list, or $null. #>
    param([object[]]$Releases)
    foreach ($release in $Releases) {
        if ($release.tag_name -like 'cli-v*' -and -not $release.prerelease -and -not $release.draft) {
            return [string]$release.tag_name
        }
    }
    return $null
}

function Get-TdxExpectedChecksum {
    <# The sha256 that checksums.txt lists for an asset (lower case), or $null. #>
    param([string]$Text, [string]$Name)
    foreach ($line in ($Text -split "`r?`n")) {
        $fields = $line.Trim() -split '\s+'
        if ($fields.Count -ge 2 -and ($fields[1] -eq $Name -or $fields[1] -eq "*$Name") -and $fields[0] -match '^[0-9a-fA-F]{64}$') {
            return $fields[0].ToLowerInvariant()
        }
    }
    return $null
}

function ConvertTo-TdxVersion {
    <# 0.2.0 from 0.2.0, v0.2.0 or cli-v0.2.0. #>
    param([string]$Value)
    $version = $Value -replace '^cli-v', '' -replace '^v', ''
    if ($version -notmatch '^[0-9][0-9A-Za-z.+-]*$') {
        throw "Not a version: $Value"
    }
    return $version
}

function Test-TdxPathEntry {
    param([string]$PathValue, [string]$Directory)
    $wanted = $Directory.TrimEnd('\')
    foreach ($entry in ($PathValue -split ';')) {
        if ($entry -and ($entry.TrimEnd('\') -ieq $wanted)) { return $true }
    }
    return $false
}

function Invoke-TdxDownload {
    param([string]$Url, [string]$OutFile, [hashtable]$Headers = @{})
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -Headers $Headers -UseBasicParsing
    } catch {
        throw "Download failed: $Url ($($_.Exception.Message))"
    }
}

function Install-Tdxguard {
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    # Windows PowerShell 5.1 may still default to TLS 1.0; GitHub needs 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    # The progress bar makes Invoke-WebRequest many times slower in Windows PowerShell 5.1.
    $ProgressPreference = 'SilentlyContinue'

    $apiBase = if ($env:TDXGUARD_API_BASE) { $env:TDXGUARD_API_BASE } else { 'https://api.github.com' }
    $downloadBase = if ($env:TDXGUARD_DOWNLOAD_BASE) { $env:TDXGUARD_DOWNLOAD_BASE } else { "https://github.com/$TdxRepository/releases/download" }
    $installDir = if ($env:TDXGUARD_INSTALL_DIR) { $env:TDXGUARD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\tdxguard' }

    $platform = Get-TdxPlatform
    if ($env:TDXGUARD_VERSION) {
        $version = ConvertTo-TdxVersion $env:TDXGUARD_VERSION
    } else {
        $headers = @{ Accept = 'application/vnd.github+json' }
        if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
        $url = "$apiBase/repos/$TdxRepository/releases?per_page=100"
        try {
            $releases = Invoke-RestMethod -Uri $url -Headers $headers -UseBasicParsing
        } catch {
            throw "Cannot list the releases of $TdxRepository ($url): $($_.Exception.Message). Check the network, or set TDXGUARD_VERSION."
        }
        $tag = Select-TdxRelease @($releases)
        if (-not $tag) { throw "$TdxRepository has no cli-v* release yet. Set TDXGUARD_VERSION, or install with pipx." }
        $version = ConvertTo-TdxVersion $tag
    }
    $tag = "cli-v$version"
    $asset = "tdxguard-$version-$platform.exe"
    $target = Join-Path $installDir 'tdxguard.exe'

    Write-Host "Installing tdxguard $version ($platform) into $installDir"
    $work = Join-Path ([IO.Path]::GetTempPath()) ("tdxguard-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    try {
        $checksums = Join-Path $work 'checksums.txt'
        try {
            Invoke-TdxDownload "$downloadBase/$tag/checksums.txt" $checksums
        } catch {
            throw "$($_.Exception.Message). Does release $tag exist? See https://github.com/$TdxRepository/releases"
        }
        $expected = Get-TdxExpectedChecksum -Text ([IO.File]::ReadAllText($checksums)) -Name $asset
        if (-not $expected) { throw "Release $tag has no $asset (not in its checksums.txt)." }
        $download = Join-Path $work $asset
        Invoke-TdxDownload "$downloadBase/$tag/$asset" $download
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $download).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "Checksum mismatch for ${asset}: expected sha256 $expected, got $actual. The download was corrupted or tampered with; nothing was installed."
        }
        Write-Host "  sha256 verified: $actual"
        # The mark of the web would make SmartScreen ask before every run.
        try { Unblock-File -LiteralPath $download } catch { Write-Verbose "Unblock-File: $($_.Exception.Message)" }

        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        try {
            Copy-Item -LiteralPath $download -Destination "$target.new" -Force
            Move-Item -LiteralPath "$target.new" -Destination $target -Force
        } catch {
            throw "Cannot write $target ($($_.Exception.Message)). Is tdxguard running? Close it, or set TDXGUARD_INSTALL_DIR."
        }
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  installed $target"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    if (-not (Test-TdxPathEntry $userPath $installDir)) {
        $newPath = if ($userPath) { $userPath.TrimEnd(';') + ";$installDir" } else { $installDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host "  added $installDir to your user PATH (new terminals pick it up)"
    }
    if (-not (Test-TdxPathEntry $env:Path $installDir)) {
        $env:Path = $env:Path.TrimEnd(';') + ";$installDir"
    }

    & $target --version
    if ($LASTEXITCODE -ne 0) { throw "The installed executable does not run: $target" }
    Write-Host ''
    Write-Host 'Next steps (in a new terminal if this one does not find tdxguard):'
    Write-Host '  tdxguard login     sign in with TDxSSO'
    Write-Host '  tdxguard init      write .tdxguard.yml in your repository'
    Write-Host '  tdxguard scan      scan it (the scanners are downloaded on first use)'
}

if ($env:TDXGUARD_INSTALL_NO_RUN -ne '1') {
    try {
        Install-Tdxguard
    } catch {
        Write-Host "tdxguard install: $($_.Exception.Message)" -ForegroundColor Red
        # Run as a file: a failing exit code. Run through `irm | iex`: exiting would close
        # the user's PowerShell window, so only the message is shown.
        if ($PSCommandPath) { exit 1 }
    }
}
