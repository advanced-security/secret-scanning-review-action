# PowerShell module dependencies for action.ps1.
#
# Format: PSResourceGet required resource file
# https://learn.microsoft.com/powershell/module/microsoft.powershell.psresourceget/install-psresource#-requiredresourcefile
#
# Every entry must pin an exact version using NuGet range syntax, e.g. '[1.2.3]'.
# The modules are vendored into ./modules by scripts/Sync-VendoredModules.ps1, which also records the
# SHA512 of each downloaded package in requirements.lock.psd1 and verifies it on every later sync.
# Merging a change to this file into main triggers the "Vendor PowerShell Modules"
# workflow, which opens a PR with the refreshed ./modules folder and lock file.
@{
    GitHubActions       = @{
        version    = '[1.1.0.2]'
        repository = 'PSGallery'
    }
    PowerShellForGitHub = @{
        version    = '[0.17.0]'
        repository = 'PSGallery'
    }
}
