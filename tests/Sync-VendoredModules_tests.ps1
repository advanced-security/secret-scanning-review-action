# Tests for scripts/Sync-VendoredModules.ps1 (no network access; Save-PSResource and the gallery API are mocked)

Import-Module Pester

BeforeAll {
    Set-StrictMode -Version Latest
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $script:SyncScript = Join-Path $repoRoot 'scripts/Sync-VendoredModules.ps1'

    function script:Get-TestPath {
        param([string[]]$Parts)
        $path = $TestDrive
        foreach ($part in $Parts) { $path = Join-Path $path $part }
        $path
    }

    function script:New-RequirementFile {
        param(
            [System.Collections.Specialized.OrderedDictionary]$Modules,
            [string]$Repository = 'PSGallery'
        )

        $path = Get-TestPath 'requirements.psd1'
        $lines = foreach ($name in $Modules.Keys) {
            "    '$name' = @{ version = '$($Modules[$name])'; repository = '$Repository' }"
        }
        Set-Content -Path $path -Value (@('@{') + $lines + @('}'))
        $path
    }

    function script:New-LockFile {
        param([System.Collections.Specialized.OrderedDictionary]$Entries)

        $lines = foreach ($name in $Entries.Keys) {
            "    '$name' = @{ version = '$($Entries[$name].Version)'; sha512 = '$($Entries[$name].Sha512)' }"
        }
        Set-Content -Path (Get-TestPath 'requirements.lock.psd1') -Value (@('@{') + $lines + @('}'))
    }

    function script:New-FakeModule {
        param(
            [string]$Name,
            [string]$Version,
            [string]$ManifestVersion = $Version,
            [string[]]$RequiredModules = @()
        )

        $dir = Get-TestPath 'modules', $Name, $Version
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        $required = ($RequiredModules | ForEach-Object { "'$_'" }) -join ', '
        Set-Content -Path (Join-Path $dir "$Name.psd1") -Value "@{ ModuleVersion = '$ManifestVersion'; RequiredModules = @($required) }"
    }

    # A syntactically valid SHA512 for lock entries in -Check tests.
    $script:FakeSha = [Convert]::ToBase64String([byte[]]::new(64))

    function script:Invoke-Sync {
        param(
            [string]$RequirementsPath,
            [switch]$Check
        )
        & $script:SyncScript -RequirementsPath $RequirementsPath -LockPath (Get-TestPath 'requirements.lock.psd1') `
            -ModulesPath (Get-TestPath 'modules') -Check:$Check 6>$null
    }

    # Builds a fake .nupkg once per (name, version, variant) so its hash is stable across calls.
    $FakePackageCache = Join-Path ([System.IO.Path]::GetTempPath()) "sync-vendored-tests-$([guid]::NewGuid())"
    New-Item -Path $FakePackageCache -ItemType Directory | Out-Null

    function script:Get-FakePackage {
        param(
            [string]$Name,
            [string]$Version,
            [string]$Variant = 'original'
        )

        $package = Join-Path $FakePackageCache "$Name.$Version.$Variant.nupkg"
        if (-not (Test-Path -LiteralPath $package)) {
            $source = Join-Path $FakePackageCache "$Name.$Version.$Variant"
            New-Item -Path (Join-Path $source '_rels') -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $source "$Name.psd1") -Value "@{ ModuleVersion = '$Version' } # $Variant"
            Set-Content -LiteralPath (Join-Path $source "$Name.nuspec") -Value '<package />'
            Set-Content -LiteralPath (Join-Path $source '[Content_Types].xml') -Value '<Types />'
            Set-Content -LiteralPath (Join-Path -Path $source -ChildPath '_rels' -AdditionalChildPath '.rels') -Value '<Relationships />'
            [System.IO.Compression.ZipFile]::CreateFromDirectory($source, $package)
        }
        $package
    }

    function script:Get-Sha512 {
        param([string]$Path)
        [Convert]::ToBase64String([System.Security.Cryptography.SHA512]::HashData([System.IO.File]::ReadAllBytes($Path)))
    }

    # Package variant served by the Save-PSResource mock, and hashes served by the gallery API mock.
    # New-Variable keeps PSScriptAnalyzer from flagging these as unused; they are read inside the mocks.
    New-Variable -Name FakeVariant -Value @{}
    New-Variable -Name FakeGalleryHash -Value @{}
}

AfterAll {
    Remove-Item -Path $FakePackageCache -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Sync-VendoredModules -Check' {
    BeforeEach {
        Remove-Item -Path (Join-Path $TestDrive '*') -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path (Get-TestPath 'modules') -ItemType Directory -Force | Out-Null
    }

    It 'passes when vendored modules and lock match the pinned versions' {
        $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]'; ModB = '[2.1.0.3]' })
        New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeSha }; ModB = @{ Version = '2.1.0.3'; Sha512 = $FakeSha } })
        New-FakeModule -Name ModA -Version 1.0.0
        New-FakeModule -Name ModB -Version 2.1.0.3

        Invoke-Sync $req -Check | Should -Match 'match requirements.psd1: ModA 1.0.0, ModB 2.1.0.3'
    }

    Context 'vendored modules' {
        BeforeEach {
            New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeSha } })
        }

        It 'ignores files at the root of the modules folder' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-FakeModule -Name ModA -Version 1.0.0
            Set-Content -Path (Get-TestPath 'modules', 'ModA.LICENSE.txt') -Value 'license'

            { Invoke-Sync $req -Check } | Should -Not -Throw
        }

        It 'fails when a pinned module is not vendored' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })

            { Invoke-Sync $req -Check } | Should -Throw '*ModA 1.0.0 is not vendored*'
        }

        It 'fails when only a different version is vendored' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-FakeModule -Name ModA -Version 0.9.0

            { Invoke-Sync $req -Check } | Should -Throw '*unexpected vendored version ''0.9.0''*'
        }

        It 'fails when an extra version is vendored alongside the pinned one' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-FakeModule -Name ModA -Version 0.9.0
            New-FakeModule -Name ModA -Version 1.0.0

            { Invoke-Sync $req -Check } | Should -Throw '*unexpected vendored version ''0.9.0''*'
        }

        It 'fails when the manifest ModuleVersion differs from the folder version' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-FakeModule -Name ModA -Version 1.0.0 -ManifestVersion 0.9.0

            { Invoke-Sync $req -Check } | Should -Throw '*reports ModuleVersion ''0.9.0''*'
        }

        It 'fails when the module manifest is missing' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-Item -Path (Get-TestPath 'modules', 'ModA', '1.0.0') -ItemType Directory -Force | Out-Null

            { Invoke-Sync $req -Check } | Should -Throw '*missing its module manifest*'
        }

        It 'fails when a vendored module folder is not pinned' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-FakeModule -Name ModA -Version 1.0.0
            New-FakeModule -Name Stray -Version 1.0.0

            { Invoke-Sync $req -Check } | Should -Throw '*''Stray'' is not pinned*'
        }

        It 'fails when a vendored module requires a module that is not pinned' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-FakeModule -Name ModA -Version 1.0.0 -RequiredModules 'ModDep'

            { Invoke-Sync $req -Check } | Should -Throw '*requires module ''ModDep''*'
        }

        It 'passes when a required module is also pinned' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]'; ModDep = '[3.0.0]' })
            New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeSha }; ModDep = @{ Version = '3.0.0'; Sha512 = $FakeSha } })
            New-FakeModule -Name ModA -Version 1.0.0 -RequiredModules 'ModDep'
            New-FakeModule -Name ModDep -Version 3.0.0

            { Invoke-Sync $req -Check } | Should -Not -Throw
        }

        It 'fails when the module folder name differs only by case' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-FakeModule -Name moda -Version 1.0.0

            # On case-insensitive file systems the folder is found but its name does not match; on Linux it is missing.
            { Invoke-Sync $req -Check } | Should -Throw
        }

        It 'rejects version ranges that are not exact pins' -TestCases @(
            @{ Version = '1.0.0' }
            @{ Version = '[1.0.0,2.0.0)' }
            @{ Version = '[1.0.0,]' }
        ) {
            param($Version)
            $req = New-RequirementFile ([ordered]@{ ModA = $Version })
            New-FakeModule -Name ModA -Version 1.0.0

            { Invoke-Sync $req -Check } | Should -Throw '*must pin an exact version*'
        }

        It 'fails when the modules folder does not exist' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            Remove-Item -Path (Get-TestPath 'modules') -Recurse -Force

            { Invoke-Sync $req -Check } | Should -Throw '*does not exist*'
        }
    }

    Context 'lock file' {
        BeforeEach {
            New-FakeModule -Name ModA -Version 1.0.0
        }

        It 'fails when the lock file does not exist' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })

            { Invoke-Sync $req -Check } | Should -Throw '*Lock file*does not exist*'
        }

        It 'fails when a pinned module is not in the lock file' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-LockFile ([ordered]@{})

            { Invoke-Sync $req -Check } | Should -Throw '*ModA is not recorded in the lock file*'
        }

        It 'fails when the lock version differs from the pinned version' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-LockFile ([ordered]@{ ModA = @{ Version = '0.9.0'; Sha512 = $FakeSha } })

            { Invoke-Sync $req -Check } | Should -Throw '*lock version ''0.9.0'' does not match*'
        }

        It 'fails when the lock hash is not a valid SHA512' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = 'not-a-hash' } })

            { Invoke-Sync $req -Check } | Should -Throw '*valid base64 SHA512*'
        }

        It 'fails when the lock file has an entry that is not pinned' {
            $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
            New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeSha }; Old = @{ Version = '1.0.0'; Sha512 = $FakeSha } })

            { Invoke-Sync $req -Check } | Should -Throw '*Lock file entry ''Old'' is not pinned*'
        }
    }
}

Describe 'Sync-VendoredModules (sync)' {
    BeforeAll {
        Mock Save-PSResource {
            # Save-PSResource -Name is [string[]], so take the single requested name as a string.
            $moduleName = [string]$Name[0]
            $exact = $Version.Trim('[', ']')
            $packageVariant = if ($FakeVariant.ContainsKey($moduleName)) { $FakeVariant[$moduleName] } else { 'original' }
            $package = Get-FakePackage -Name $moduleName -Version $exact -Variant $packageVariant
            Copy-Item -LiteralPath $package -Destination (Join-Path $Path "$moduleName.$exact.nupkg")
        }

        Mock Invoke-RestMethod {
            if ($Uri -notmatch "Packages\(Id='([^']+)',Version='([^']+)'\)") { throw "Unexpected URI $Uri" }
            [pscustomobject]@{
                entry = [pscustomobject]@{
                    properties = [pscustomobject]@{
                        PackageHashAlgorithm = 'SHA512'
                        PackageHash          = $FakeGalleryHash["$($Matches[1])|$($Matches[2])"]
                    }
                }
            }
        }
    }

    BeforeEach {
        Remove-Item -Path (Join-Path $TestDrive '*') -Recurse -Force -ErrorAction SilentlyContinue
        $FakeVariant.Clear()
        $FakeGalleryHash.Clear()
        $FakeGalleryHash['ModA|1.0.0'] = Get-Sha512 (Get-FakePackage ModA 1.0.0)
        $FakeGalleryHash['ModA|2.0.0'] = Get-Sha512 (Get-FakePackage ModA 2.0.0)
    }

    It 'records the gallery-verified hash for a new module and extracts the package' {
        $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })

        Invoke-Sync $req | Should -Match 'match requirements.psd1: ModA 1.0.0'

        $lock = Import-PowerShellDataFile (Get-TestPath 'requirements.lock.psd1')
        $lock.ModA.version | Should -Be '1.0.0'
        $lock.ModA.sha512 | Should -Be $FakeGalleryHash['ModA|1.0.0']
        Get-TestPath 'modules', 'ModA', '1.0.0', 'ModA.psd1' | Should -Exist
        @(Get-ChildItem (Get-TestPath 'modules', 'ModA', '1.0.0') -Force).Name | Should -Be @('ModA.psd1')
    }

    It 'passes when the downloaded package matches the lock file' {
        $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
        New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeGalleryHash['ModA|1.0.0'] } })
        $FakeGalleryHash['ModA|1.0.0'] = 'gallery is not consulted when the lock has the version'

        { Invoke-Sync $req } | Should -Not -Throw
    }

    It 'fails without touching ./modules or the lock when the package does not match the lock file' {
        $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' })
        New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeGalleryHash['ModA|1.0.0'] } })
        New-FakeModule -Name ModA -Version 1.0.0
        $lockBefore = Get-Content (Get-TestPath 'requirements.lock.psd1') -Raw
        $FakeVariant['ModA'] = 'tampered'

        { Invoke-Sync $req } | Should -Throw '*SHA512 mismatch for ModA 1.0.0: lock file has*'

        Get-Content (Get-TestPath 'modules', 'ModA', '1.0.0', 'ModA.psd1') -Raw | Should -Not -Match 'tampered'
        Get-Content (Get-TestPath 'requirements.lock.psd1') -Raw | Should -Be $lockBefore
    }

    It 'fails without touching ./modules when a new package does not match the gallery hash' {
        $req = New-RequirementFile ([ordered]@{ ModA = '[2.0.0]' })
        New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeGalleryHash['ModA|1.0.0'] } })
        New-FakeModule -Name ModA -Version 1.0.0
        $FakeVariant['ModA'] = 'tampered'

        { Invoke-Sync $req } | Should -Throw '*SHA512 mismatch for ModA 2.0.0: PowerShell Gallery publishes*'

        Get-TestPath 'modules', 'ModA', '1.0.0' | Should -Exist
        Get-TestPath 'modules', 'ModA', '2.0.0' | Should -Not -Exist
    }

    It 'replaces the old version and updates the lock on a version bump' {
        $req = New-RequirementFile ([ordered]@{ ModA = '[2.0.0]' })
        New-LockFile ([ordered]@{ ModA = @{ Version = '1.0.0'; Sha512 = $FakeGalleryHash['ModA|1.0.0'] }; Old = @{ Version = '1.0.0'; Sha512 = $FakeSha } })
        New-FakeModule -Name ModA -Version 1.0.0

        { Invoke-Sync $req } | Should -Not -Throw

        Get-TestPath 'modules', 'ModA', '1.0.0' | Should -Not -Exist
        Get-TestPath 'modules', 'ModA', '2.0.0', 'ModA.psd1' | Should -Exist
        $lock = Import-PowerShellDataFile (Get-TestPath 'requirements.lock.psd1')
        @($lock.Keys) | Should -Be @('ModA')
        $lock.ModA.version | Should -Be '2.0.0'
        $lock.ModA.sha512 | Should -Be $FakeGalleryHash['ModA|2.0.0']
    }

    It 'refuses to record a hash for a non-PSGallery package that is not in the lock file' {
        $req = New-RequirementFile ([ordered]@{ ModA = '[1.0.0]' }) -Repository 'Internal'

        { Invoke-Sync $req } | Should -Throw '*cannot be verified automatically*'
        Get-TestPath 'requirements.lock.psd1' | Should -Not -Exist
    }
}

Describe 'Repository vendored modules' {
    # Skipped in CI: requirements.psd1 can merge before the vendor PR; the Release workflow enforces the match.
    It 'match requirements.psd1 and requirements.lock.psd1' -Tag 'SkipCI' {
        { & $script:SyncScript -Check } | Should -Not -Throw
    }
}
