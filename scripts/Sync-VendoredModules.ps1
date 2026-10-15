<#
.SYNOPSIS
Vendors the PowerShell modules pinned in requirements.psd1 into the modules folder, or verifies that they match.

.DESCRIPTION
requirements.psd1 uses the PSResourceGet required resource file format:
https://learn.microsoft.com/powershell/module/microsoft.powershell.psresourceget/install-psresource#-requiredresourcefile

Every entry must pin an exact version using NuGet range syntax (for example '[1.2.3]').

Without -Check, the script downloads each pinned module as a .nupkg with Save-PSResource -AsNupkg and
computes its SHA512:
  - If requirements.lock.psd1 already records that module and version, the hash must match the lock.
  - Otherwise (new module or version bump) the hash must match the PackageHash the PowerShell Gallery
    publishes for that package, and it is then recorded in requirements.lock.psd1.
Only after every package is verified does the script replace the module folders under the modules path,
extracting the verified packages themselves (no second download). It then runs the same verification as -Check.

With -Check, the script makes no network calls. It fails if the modules path does not contain exactly the
pinned modules at the pinned versions, if a vendored manifest reports a different ModuleVersion, if a
vendored module requires another module that is not pinned in requirements.psd1, or if
requirements.lock.psd1 does not record a SHA512 for exactly the pinned modules and versions.

Files at the root of the modules path (for example third-party license notices) are left untouched and
ignored by the verification.

.PARAMETER RequirementsPath
Path to the required resource file.
Default is requirements.psd1 at the repository root.

.PARAMETER LockPath
Path to the lock file that records the SHA512 of each vendored package.
Default is requirements.lock.psd1 at the repository root.

.PARAMETER ModulesPath
Path to the vendored modules folder.
Default is modules at the repository root.

.PARAMETER Check
If provided, only verifies that the vendored modules and lock file match requirements.psd1 instead of downloading them.
Default is false.

.EXAMPLE
PS> ./scripts/Sync-VendoredModules.ps1

Downloads and hash-verifies every module pinned in requirements.psd1, then refreshes ./modules and requirements.lock.psd1.

.EXAMPLE
PS> ./scripts/Sync-VendoredModules.ps1 -Check

Fails if ./modules or requirements.lock.psd1 do not match requirements.psd1. Used by the release workflow.
#>
[CmdletBinding()]
param(
    [string]$RequirementsPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'requirements.psd1'),
    [string]$LockPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'requirements.lock.psd1'),
    [string]$ModulesPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules'),
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$PSGalleryApiUri = 'https://www.powershellgallery.com/api/v2'
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Get-PinnedRequirement {
    param([string]$Path)

    $requirements = Import-PowerShellDataFile -Path $Path
    foreach ($name in ($requirements.Keys | Sort-Object)) {
        $spec = $requirements[$name]
        if ($spec -isnot [hashtable]) {
            throw "Module '$name' in '$Path' must be a hashtable with a 'version' key."
        }
        if ([string]$spec['version'] -notmatch '^\[([^\[\],\s]+)\]$') {
            throw "Module '$name' in '$Path' must pin an exact version like '[1.2.3]'. Found: '$($spec['version'])'"
        }
        [pscustomobject]@{
            Name         = $name
            Version      = $Matches[1]
            VersionRange = $spec['version']
            Repository   = if ($spec['repository']) { $spec['repository'] } else { 'PSGallery' }
        }
    }
}

function Get-VendoredModuleProblem {
    param(
        [object[]]$Requirements,
        [string]$Path
    )

    if (-not (Test-Path -Path $Path -PathType Container)) {
        return "Vendored modules folder '$Path' does not exist."
    }

    $pinnedNames = @($Requirements | ForEach-Object Name)

    foreach ($requirement in $Requirements) {
        $moduleDir = Join-Path $Path $requirement.Name
        $versions = @(Get-ChildItem -Path $moduleDir -Directory -ErrorAction SilentlyContinue | ForEach-Object Name)

        if ($versions.Count -eq 0) {
            "$($requirement.Name) $($requirement.Version) is not vendored."
            continue
        }
        foreach ($version in ($versions | Where-Object { $_ -cne $requirement.Version })) {
            "$($requirement.Name) has unexpected vendored version '$version' (pinned: $($requirement.Version))."
        }
        if ($versions -cnotcontains $requirement.Version) {
            "$($requirement.Name) $($requirement.Version) is not vendored."
            continue
        }

        $manifestPath = Join-Path -Path $moduleDir -ChildPath $requirement.Version -AdditionalChildPath "$($requirement.Name).psd1"
        if (-not (Test-Path -Path $manifestPath -PathType Leaf)) {
            "$($requirement.Name) $($requirement.Version) is missing its module manifest '$manifestPath'."
            continue
        }

        $manifest = Import-PowerShellDataFile -Path $manifestPath
        if ([string]$manifest['ModuleVersion'] -cne $requirement.Version) {
            "$($requirement.Name) manifest reports ModuleVersion '$($manifest['ModuleVersion'])' (pinned: $($requirement.Version))."
        }

        foreach ($dependency in @($manifest['RequiredModules'] | Where-Object { $_ })) {
            $dependencyName = if ($dependency -is [hashtable]) { $dependency['ModuleName'] } else { [string]$dependency }
            if ($pinnedNames -cnotcontains $dependencyName) {
                "$($requirement.Name) requires module '$dependencyName', which is not pinned in requirements.psd1."
            }
        }
    }

    foreach ($dir in (Get-ChildItem -Path $Path -Directory)) {
        if ($pinnedNames -cnotcontains $dir.Name) {
            "Vendored module folder '$($dir.Name)' is not pinned in requirements.psd1."
        }
    }
}

function Read-Lock {
    param([string]$Path)

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        return @{}
    }
    Import-PowerShellDataFile -Path $Path
}

function Get-LockProblem {
    param(
        [object[]]$Requirements,
        [string]$Path
    )

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        return "Lock file '$Path' does not exist."
    }

    $lock = Read-Lock -Path $Path
    $pinnedNames = @($Requirements | ForEach-Object Name)

    foreach ($requirement in $Requirements) {
        $entryName = @($lock.Keys | Where-Object { $_ -ceq $requirement.Name })
        if ($entryName.Count -eq 0) {
            "$($requirement.Name) is not recorded in the lock file."
            continue
        }
        $entry = $lock[$entryName[0]]
        if ([string]$entry['version'] -cne $requirement.Version) {
            "$($requirement.Name) lock version '$($entry['version'])' does not match pinned version $($requirement.Version)."
        }
        if ([string]$entry['sha512'] -notmatch '^[A-Za-z0-9+/]{86}==$') {
            "$($requirement.Name) lock entry does not contain a valid base64 SHA512 hash."
        }
    }

    foreach ($name in $lock.Keys) {
        if ($pinnedNames -cnotcontains $name) {
            "Lock file entry '$name' is not pinned in requirements.psd1."
        }
    }
}

function Write-Lock {
    param(
        [object[]]$Entries,
        [string]$Path
    )

    $lines = @(
        '# Generated by scripts/Sync-VendoredModules.ps1. Do not edit by hand.'
        '# SHA512 (base64) of each .nupkg vendored into ./modules, verified on every sync.'
        '@{'
    )
    foreach ($entry in ($Entries | Sort-Object Name)) {
        $lines += "    '$($entry.Name)' = @{"
        $lines += "        version = '$($entry.Version)'"
        $lines += "        sha512  = '$($entry.Sha512)'"
        $lines += '    }'
    }
    $lines += '}'
    Set-Content -Path $Path -Value $lines -Encoding utf8NoBOM
}

function Get-FileSha512 {
    param([string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        [Convert]::ToBase64String([System.Security.Cryptography.SHA512]::HashData($stream))
    }
    finally {
        $stream.Dispose()
    }
}

function Get-GalleryPackageHash {
    param(
        [string]$Name,
        [string]$Version
    )

    $package = Invoke-RestMethod -Uri "$PSGalleryApiUri/Packages(Id='$Name',Version='$Version')"
    $properties = $package.entry.properties
    if ([string]$properties.PackageHashAlgorithm -ne 'SHA512') {
        throw "PowerShell Gallery reports hash algorithm '$($properties.PackageHashAlgorithm)' for $Name $Version; expected SHA512."
    }
    [string]$properties.PackageHash
}

function Expand-VerifiedPackage {
    param(
        [string]$PackagePath,
        [string]$Name,
        [string]$Destination
    )

    # ExtractToDirectory rejects entries that would escape the destination folder.
    [System.IO.Compression.ZipFile]::ExtractToDirectory($PackagePath, $Destination)

    # Drop the NuGet packaging metadata, matching the layout Save-PSResource produces.
    $metadata = @('_rels', 'package', '[Content_Types].xml', "$Name.nuspec") | ForEach-Object { Join-Path $Destination $_ }
    Remove-Item -LiteralPath $metadata -Recurse -Force -ErrorAction SilentlyContinue
}

$requirements = @(Get-PinnedRequirement -Path $RequirementsPath)

if (-not $Check) {
    $lock = Read-Lock -Path $LockPath
    $stagingPath = Join-Path ([System.IO.Path]::GetTempPath()) "vendored-modules-$([guid]::NewGuid())"
    New-Item -Path $stagingPath -ItemType Directory | Out-Null

    try {
        $verified = foreach ($requirement in $requirements) {
            $packageDir = Join-Path $stagingPath $requirement.Name
            New-Item -Path $packageDir -ItemType Directory | Out-Null

            Write-Information "Downloading $($requirement.Name) $($requirement.VersionRange) from $($requirement.Repository)..."
            # Dependencies are not saved implicitly; they must be pinned in requirements.psd1 (enforced below).
            Save-PSResource -Name $requirement.Name -Version $requirement.VersionRange -Repository $requirement.Repository `
                -Path $packageDir -AsNupkg -TrustRepository -SkipDependencyCheck

            $packages = @(Get-ChildItem -Path $packageDir -Filter '*.nupkg' -File)
            if ($packages.Count -ne 1) {
                throw "Expected exactly one package for $($requirement.Name) $($requirement.Version), found $($packages.Count)."
            }
            $actualHash = Get-FileSha512 -Path $packages[0].FullName

            $lockName = @($lock.Keys | Where-Object { $_ -ceq $requirement.Name })
            $locked = if ($lockName.Count -gt 0 -and [string]$lock[$lockName[0]]['version'] -ceq $requirement.Version) { $lock[$lockName[0]] }
            if ($locked) {
                if ($actualHash -cne [string]$locked['sha512']) {
                    throw "SHA512 mismatch for $($requirement.Name) $($requirement.Version): lock file has '$($locked['sha512'])', downloaded package is '$actualHash'."
                }
                Write-Information "  SHA512 matches requirements.lock.psd1."
            }
            elseif ($requirement.Repository -eq 'PSGallery') {
                $galleryHash = Get-GalleryPackageHash -Name $requirement.Name -Version $requirement.Version
                if ($actualHash -cne $galleryHash) {
                    throw "SHA512 mismatch for $($requirement.Name) $($requirement.Version): PowerShell Gallery publishes '$galleryHash', downloaded package is '$actualHash'."
                }
                Write-Information "  SHA512 matches the PowerShell Gallery package hash; recording it in requirements.lock.psd1."
            }
            else {
                throw "$($requirement.Name) $($requirement.Version) from '$($requirement.Repository)' is not in the lock file and its hash cannot be verified automatically. Downloaded SHA512: '$actualHash'."
            }

            [pscustomobject]@{
                Name        = $requirement.Name
                Version     = $requirement.Version
                Sha512      = $actualHash
                PackagePath = $packages[0].FullName
            }
        }

        # Every package is verified; only now replace the vendored folders.
        if (-not (Test-Path -Path $ModulesPath -PathType Container)) {
            New-Item -Path $ModulesPath -ItemType Directory | Out-Null
        }
        Get-ChildItem -Path $ModulesPath -Directory | Remove-Item -Recurse -Force
        foreach ($package in $verified) {
            $destination = Join-Path -Path $ModulesPath -ChildPath $package.Name -AdditionalChildPath $package.Version
            Expand-VerifiedPackage -PackagePath $package.PackagePath -Name $package.Name -Destination $destination
        }
        Write-Lock -Entries $verified -Path $LockPath
    }
    finally {
        Remove-Item -Path $stagingPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$problems = @(Get-VendoredModuleProblem -Requirements $requirements -Path $ModulesPath) + @(Get-LockProblem -Requirements $requirements -Path $LockPath)
if ($problems.Count -gt 0) {
    throw "Vendored modules in '$ModulesPath' do not match '$RequirementsPath':`n - $($problems -join "`n - ")`nRun ./scripts/Sync-VendoredModules.ps1 to refresh them."
}

Write-Output "Vendored modules match requirements.psd1: $(($requirements | ForEach-Object { "$($_.Name) $($_.Version)" }) -join ', ')"
