# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GUID = '9e8dfd44-f782-445a-883c-70614f71519c'
    Author = 'Microsoft Corporation'
    CompanyName = 'Microsoft Corporation'
    Copyright = 'Copyright (C) Microsoft Corporation.  All rights reserved.'

    ModuleVersion = '0.17.0'
    Description = 'PowerShell wrapper for GitHub API'

    # Script module or binary module file associated with this manifest.
    RootModule = 'PowerShellForGitHub.psm1'

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @(
        'Formatters/GitHubBranches.Format.ps1xml',
        'Formatters/GitHubCodespaces.Format.ps1xml',
        'Formatters/GitHubDeployments.Format.ps1xml',
        'Formatters/GitHubGistComments.Format.ps1xml',
        'Formatters/GitHubGists.Format.ps1xml',
        'Formatters/GitHubReleases.Format.ps1xml'
        'Formatters/GitHubRepositories.Format.ps1xml'
        'Formatters/GitHubTeams.Format.ps1xml'
    )

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        # Ideally this list would be kept completely alphabetical, but other scripts (like
        # GitHubConfiguration.ps1) depend on some of the code in Helpers being around at load time.
        'Helpers.ps1',
        'GitHubConfiguration.ps1',

        'GitHubAnalytics.ps1',
        'GitHubAssignees.ps1',
        'GitHubBranches.ps1',
        'GitHubCodespaces.ps1',
        'GitHubCore.ps1',
        'GitHubContents.ps1',
        'GitHubEvents.ps1',
        'GitHubGistComments.ps1',
        'GitHubGists.ps1',
        'GitHubGraphQl.ps1',
        'GitHubIssueComments.ps1',
        'GitHubIssues.ps1',
        'GitHubLabels.ps1',
        'GitHubMilestones.ps1',
        'GitHubMiscellaneous.ps1',
        'GitHubOrganizations.ps1',
        'GitHubProjects.ps1',
        'GitHubProjectCards.ps1',
        'GitHubProjectColumns.ps1',
        'GitHubPullRequests.ps1',
        'GitHubReactions.ps1',
        'GitHubReleases.ps1',
        'GitHubRepositories.ps1',
        'GitHubRepositoryForks.ps1',
        'GitHubRepositoryTraffic.ps1',
        'GitHubTeams.ps1',
        'GitHubUsers.ps1',
        'GitHubDeployments.ps1',
        'Telemetry.ps1',
        'UpdateCheck.ps1')

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '4.0'

    # Functions to export from this module
    FunctionsToExport = @(
        'Add-GitHubAssignee',
        'Add-GitHubIssueLabel',
        'Add-GitHubGistStar',
        'Backup-GitHubConfiguration',
        'Clear-GitHubAuthentication',
        'ConvertFrom-GitHubMarkdown',
        'Copy-GitHubGist',
        'Disable-GitHubRepositorySecurityFix',
        'Disable-GitHubRepositoryVulnerabilityAlert',
        'Enable-GitHubRepositorySecurityFix',
        'Enable-GitHubRepositoryVulnerabilityAlert',
        'Get-GitHubAssignee',
        'Get-GitHubCloneTraffic',
        'Get-GitHubCodeOfConduct',
        'Get-GitHubCodespace',
        'Get-GitHubConfiguration',
        'Get-GitHubContent',
        'Get-GitHubDeploymentEnvironment',
        'Get-GitHubEmoji',
        'Get-GitHubEvent',
        'Get-GitHubGist',
        'Get-GitHubGistComment',
        'Get-GitHubGitIgnore',
        'Get-GitHubIssue',
        'Get-GitHubIssueComment',
        'Get-GitHubIssueTimeline',
        'Get-GitHubLabel',
        'Get-GitHubLicense',
        'Get-GitHubMilestone',
        'Get-GitHubOrganizationMember',
        'Get-GitHubPathTraffic',
        'Get-GitHubProject',
        'Get-GitHubProjectCard',
        'Get-GitHubProjectColumn',
        'Get-GitHubPullRequest',
        'Get-GitHubRateLimit',
        'Get-GitHubReaction',
        'Get-GitHubReferrerTraffic',
        'Get-GitHubRelease',
        'Get-GitHubReleaseAsset',
        'Get-GitHubRepository',
        'Get-GitHubRepositoryActionsPermission',
        'Get-GitHubRepositoryBranch',
        'Get-GitHubRepositoryBranchPatternProtectionRule',
        'Get-GitHubRepositoryBranchProtectionRule',
        'Get-GitHubRepositoryCollaborator',
        'Get-GitHubRepositoryContributor',
        'Get-GitHubRepositoryFork',
        'Get-GitHubRepositoryLanguage',
        'Get-GitHubRepositoryTag',
        'Get-GitHubRepositoryTeamPermission',
        'Get-GitHubRepositoryTopic',
        'Get-GitHubRepositoryUniqueContributor',
        'Get-GitHubTeam',
        'Get-GitHubTeamMember',
        'Get-GitHubUser',
        'Get-GitHubUserContextualInformation',
        'Get-GitHubViewTraffic',
        'Group-GitHubIssue',
        'Group-GitHubPullRequest',
        'Initialize-GitHubLabel',
        'Invoke-GHGraphQl',
        'Invoke-GHRestMethod',
        'Invoke-GHRestMethodMultipleResult',
        'Join-GitHubUri',
        'Lock-GitHubIssue',
        'Move-GitHubProjectCard',
        'Move-GitHubProjectColumn',
        'Move-GitHubRepositoryOwnership',
        'New-GitHubCodespace',
        'New-GitHubDeploymentEnvironment',
        'New-GitHubGist',
        'New-GitHubGistComment',
        'New-GitHubIssue',
        'New-GitHubIssueComment',
        'New-GitHubLabel',
        'New-GitHubMilestone',
        'New-GitHubProject',
        'New-GitHubProjectCard',
        'New-GitHubProjectColumn',
        'New-GitHubPullRequest',
        'New-GitHubRelease',
        'New-GitHubReleaseAsset',
        'New-GitHubRepository',
        'New-GitHubRepositoryFromTemplate',
        'New-GitHubRepositoryBranch',
        'New-GitHubRepositoryBranchPatternProtectionRule',
        'New-GitHubRepositoryBranchProtectionRule',
        'New-GitHubRepositoryFork',
        'New-GitHubTeam',
        'Remove-GitHubAssignee',
        'Remove-GitHubCodespace',
        'Remove-GitHubComment',
        'Remove-GitHubDeploymentEnvironment'
        'Remove-GitHubGist',
        'Remove-GitHubGistComment',
        'Remove-GitHubGistFile',
        'Remove-GitHubGistStar',
        'Remove-GitHubIssueComment',
        'Remove-GitHubIssueLabel',
        'Remove-GitHubLabel',
        'Remove-GitHubMilestone',
        'Remove-GitHubProject',
        'Remove-GitHubProjectCard',
        'Remove-GitHubProjectColumn',
        'Remove-GitHubReaction',
        'Remove-GitHubRelease',
        'Remove-GitHubReleaseAsset',
        'Remove-GitHubRepository',
        'Remove-GitHubRepositoryBranch'
        'Remove-GitHubRepositoryBranchPatternProtectionRule',
        'Remove-GitHubRepositoryBranchProtectionRule',
        'Remove-GitHubRepositoryTeamPermission',
        'Remove-GitHubTeam',
        'Rename-GitHubGistFile',
        'Rename-GitHubRepository',
        'Rename-GitHubTeam',
        'Reset-GitHubConfiguration',
        'Restore-GitHubConfiguration',
        'Set-GitHubAuthentication',
        'Set-GitHubConfiguration',
        'Set-GitHubContent',
        'Set-GitHubGist',
        'Set-GitHubGistComment',
        'Set-GitHubGistFile',
        'Set-GitHubGistStar',
        'Set-GitHubIssue',
        'Set-GitHubIssueComment',
        'Set-GitHubIssueLabel',
        'Set-GitHubLabel',
        'Set-GitHubMilestone',
        'Set-GitHubProfile',
        'Set-GitHubProject',
        'Set-GitHubProjectCard',
        'Set-GitHubProjectColumn',
        'Set-GitHubReaction',
        'Set-GitHubRelease',
        'Set-GitHubReleaseAsset',
        'Set-GitHubRepository',
        'Set-GitHubRepositoryActionsPermission',
        'Set-GitHubRepositoryTeamPermission',
        'Set-GitHubRepositoryTopic',
        'Set-GitHubTeam',
        'Split-GitHubUri',
        'Start-GitHubCodespace',
        'Stop-GitHubCodespace',
        'Test-GitHubAssignee',
        'Test-GitHubAuthenticationConfigured',
        'Test-GitHubGistStar',
        'Test-GitHubOrganizationMember',
        'Test-GitHubRepositoryVulnerabilityAlert',
        'Unlock-GitHubIssue'
    )

    AliasesToExport = @(
        'Add-GitHubGistFile',
        'Delete-GitHubAsset',
        'Delete-GitHubBranch',
        'Delete-GitHubComment',
        'Delete-GitHubDeploymentEnvironment',
        'Delete-GitHubGist',
        'Delete-GitHubGistComment',
        'Delete-GitHubGistFile',
        'Delete-GitHubIssueComment',
        'Delete-GitHubLabel',
        'Delete-GitHubMilestone',
        'Delete-GitHubProject',
        'Delete-GitHubProjectCard',
        'Delete-GitHubProjectColumn'
        'Delete-GitHubReaction',
        'Delete-GitHubRelease',
        'Delete-GitHubReleaseAsset',
        'Delete-GitHubRepository',
        'Delete-GitHubRepositoryBranch',
        'Delete-GitHubRepositoryBranchPatternProtectionRule',
        'Delete-GitHubRepositoryBranchProtectionRule',
        'Delete-GitHubRepositoryTeamPermission',
        'Delete-GitHubTeam',
        'Fork-GitHubGist',
        'Get-GitHubAsset',
        'Get-GitHubBranch',
        'Get-GitHubComment',
        'New-GitHubAsset',
        'New-GitHubAssignee',
        'New-GitHubBranch',
        'New-GitHubComment',
        'Remove-GitHubAsset',
        'Remove-GitHubBranch'
        'Remove-GitHubComment',
        'Set-GitHubAsset',
        'Set-GitHubComment',
        'Set-GitHubDeploymentEnvironment',
        'Star-GitHubGist',
        'Transfer-GitHubRepositoryOwnership'
        'Unstar-GitHubGist'
        'Update-GitHubIssue',
        'Update-GitHubLabel',
        'Update-GitHubCurrentUser',
        'Update-GitHubRepository'
    )

    # Cmdlets to export from this module
    # CmdletsToExport = '*'

    # Variables to export from this module
    # VariablesToExport = '*'

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('GitHub', 'API', 'PowerShell')

            # A URL to the license for this module.
            LicenseUri = 'https://aka.ms/PowerShellForGitHub_License'

            # A URL to the main website for this project.
            ProjectUri = 'https://aka.ms/PowerShellForGitHub'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'https://github.com/microsoft/PowerShellForGitHub/blob/master/CHANGELOG.md'
        }
    }

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = 'GH'

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # HelpInfo URI of this module
    # HelpInfoURI = ''
}

# SIG # Begin signature block
# MIIoLgYJKoZIhvcNAQcCoIIoHzCCKBsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDujuMZd5FtR55A
# NqQ2fFy/s3Bzt2aKF7MteKKNAzWxA6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGg4wghoKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOiXFFcZJQRHLo6E3eCJyvyY
# ExWdM6K731NJEAIyGbkUMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBkwIaQS3VY6qkVAhnvSajJKmwJ2GISyGXdLtUyjj2ZR3QdgWM+JffN
# 47LSx1bK/UkJncvTl6O297peqKgklvhh/pE6QGEfC52KfcvGlIiC6e62Poavtajq
# hI3Ils/3AypuG1MdUYjNwc0WFaM+HFgoobk4tPaUHFV56GhhOT3qpRsblJF5ZrSi
# b+maATyEbKh/YNQuTqM/2gv6cwnj/kVG2MzGpi3uUByTkQV6PPIY6I5mmtYNZhnk
# sFMPk3vinxfxxbpGjCyzXyrr5XL7oPmlsE/s7ytmieAeSOe2VzEd4gRY6ThNQx3W
# Z3NJF2zSjnB08sE90Sfw5feZrfG2gsPYoYIXljCCF5IGCisGAQQBgjcDAwExgheC
# MIIXfgYJKoZIhvcNAQcCoIIXbzCCF2sCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIIqdbOEfTXOxC1Zyr+ObS/2UW97tj5SZcJvt7UOcce5KAgZlVsam
# IpAYEjIwMjMxMTIxMTczNjE2LjU4WjAEgAIB9KCB0aSBzjCByzELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkE5MzUt
# MDNFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIR7TCCByAwggUIoAMCAQICEzMAAAHRsltAKGwu0kUAAQAAAdEwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMwNTI1MTkx
# MjE4WhcNMjQwMjAxMTkxMjE4WjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOkE5MzUtMDNFMC1EOTQ3MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAmUzaNDnhs9lxXdoC4OZ05QZvFzqbsCSIl7DFOta8
# KtWSg6WuON0a0hv6R/Bs+lzZxUChpwqjQrZr6ClCwKcK0/7O/3tV9JTRSpo+1O1+
# KdNEtLkG1ui8Ep/81h2htnOeGV7BmPgWH4Vg4GxaQk8Uc050Qhutm5Fj6emR22T4
# OB7dQkQgDIYThk0fMCOBu8MFmcHTHOlL1FJatKpfQMQH85GEaYtrUbwxzHZmd78l
# 6aoRcL0RvHIAh/00wo1uaumjW3aii9wRQz81LbgjbD1y9/xNHUdmwzKmtGjR/oiH
# 4RguP73MLrXjjAj1CA1UqgwjXyGjwxMGHItX3fYLtc1cPhxIQ2TOxGt58SFK87fk
# X6eU6DDI+EAJielGnZvkz2w26PJBSCu9EoZlvMJ/HyZPUXkEBKU7SDeN3kb/UJl8
# t1HnfNKLDgRPlpHTL0ghYfqoArCnc0MUCRutnE3qFNnqjYR96KaV5sn1VMG7Hn0M
# zD7W4pwmXdBVJZpTP3R/uDp4qkMmh767WMt8KiGn2N83hSE5VQKD/avbxeFuyh0f
# 7hdJr06QC+TWkwzdaZUEtDHYzJIM2SuYLcKjnv9605agc8cGu2GKd7qz+clpE8yE
# hp4TViGTsTskCDsWX24iGwB25tzPIY+9ykFnAkeSWr4JMFJp3BRxEmkH+A66rPv9
# S9UCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBQLjvFMxew3B9JprBeF0McR0L0tozAf
# BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
# hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBe
# MFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Nl
# cnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE
# AwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAm7va0wB1duJmNKqBuXhJyJs+WpBl074g
# cCqdmOdbNusPKA61qK/ptNEeP9wXA5mJVCvDa8f2rmBWInWXXXFI8ONkMUkrZr/6
# lpwkIv9jpx99ilR0PpDDmTwAUExtV5HJ2D1DjhBKK+n/9ybNbo+MIx8xOFeGrpmF
# wQLK+C+SkfLynrObRcYTJFjQ/zu1v0Wh2MCTIzJMVaLAaJO1dtbCQJcUnBF8XyWv
# v6pKlK+wmYMN0eIwh0ZD6kITFom1zzGGq/4hdGbiwfTvPQzCTYYyvQUn+oqoGaDL
# syFbfhAaE86b//aeMEOsaAQrNvZpI/xCFhXXPuWt9JLgkDkhDo9O/liNvQOJOkCE
# QecPnjJmdCXnNLEsnkAeSo8ROdYmDIbZTK1CnK9OpwagrEij2LEgCEwM4LLCQ/mf
# 3E0uwrt+Xya1oTPTWF9uLgMWCwFtIqTbVqbSHlempLmRHhFegTbTN1U5PpgJVef3
# gv9GNe2lUoyuf4Mg6CzZq4FcL+UwGgZqv8IEURR5lvVCd87/C5pOpiKAMk6agW7l
# IzC8q7Wo7krAP5tg5yjDtEIs9b/hUlW6jN/Cfz05YQk1GxTsdJC0+2P+/mcq4pVQ
# s8gGHxSIpwyI1pTPObQ3lPGXyQoxSsKtw7EcVeCWNfMcMPE05qHd5ZK/TahkOeC5
# sj1XPuYmza4wggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqG
# SIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
# MjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4X
# YDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTz
# xXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7
# uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlw
# aQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedG
# bsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXN
# xF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03
# dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9
# ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5
# UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReT
# wDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZ
# MBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8
# RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAE
# VTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAww
# CgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQD
# AgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb
# 186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29t
# L3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoG
# CCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZI
# hvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9
# MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2Lpyp
# glYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OO
# PcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8
# DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA
# 0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1Rt
# nWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjc
# ZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq7
# 7EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJ
# C4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328
# y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYID
# UDCCAjgCAQEwgfmhgdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBOTM1LTAzRTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# RyWNhb/hoS0LUQ0dryMwWkr/+yyggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsFAAIFAOkHM4QwIhgPMjAyMzExMjExMzQ3
# NDhaGA8yMDIzMTEyMjEzNDc0OFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA6Qcz
# hAIBADAKAgEAAgIPqgIB/zAHAgEAAgISzzAKAgUA6QiFBAIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBCwUAA4IBAQAWMcrd9lW60xhQGJDw4Y4rpuHYqReZnacfAYa+c0nb
# mcnbOwXKI9/a8qzRDpZ4MwzJ4XYZfAcUqX7xDvI6MM08Rw7J7ECFDkVJwSd8tL8+
# buj71LjwvIOgQWsRwbV78oSocIU+/GiG26b+93XGeKT7TH0oMEXxjNSzo5pTDlGD
# QPAy6iNLsdtoY3gkdzyz+FzuvyFLKSuoZYgxE85u2YSsjFxDB+MIZKZ6Q7ZuvjT/
# XlaMywf+EywYOpv8GwWMfX+YE/HwfW+/LTqht3IASs7d3H+E2SOs0OLnr37jiYfj
# LO1TFhePqI5ZiHwJ7HtydbYmSHzewmJrGWTMW5b4kMfnMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHRsltAKGwu0kUAAQAA
# AdEwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgra5XfW1giy/svfnAOJ0NkLTAO6FaTGQQ7b4Nsmai
# zu0wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDMvGF5AgC7+e3ObEYaz07m
# 9auE8CeqFQN+pPCIiPwHDDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAAB0bJbQChsLtJFAAEAAAHRMCIEIPHGoqv5rt6VzRpNff2stPZo
# ZbCq5F02Zr/PIVSE/ER8MA0GCSqGSIb3DQEBCwUABIICAHGcXFIA/5W8vMLHoxsE
# m1bZ7jCBqwFvIidHLUi+Wf32VX26eHKdAh/20QJvf6rU3NQNAPHL5wxuuMbibUAj
# TVh4GfY5mhUB3tdiq/KKqGvVWsNMYCIoVV8xmbdijo2GFBL+gdVAxf6A17ckPqB1
# uUwriLjLRh1cCQo/AXLXyCQOFAQkDGtGzP8Blasu1NukzmUVfxVNBci+PMQCOgHG
# oVrM5yDEyxVBvOW/BE9yZGFYCxt/XJfvZTI5YKcxzVit/FOLXUX8NI0EGQYsAwNs
# EMJqr/sW9TVkuaWXvZtQmx/Yj3KtbmhhQ54DXrr403QQIXRxK7sWlgcRMN9oL60O
# RMAiTSHhHjWM7EPUG4hTNjJDMyKmC6SU18vbowVnl8zuJHdx7xNjCQ2k3QseIUWR
# 8p5GbkzQD2Y3pMxa8KSqA07efnFmdKiLjUNop2HnqLW7oEbd/VGLkwx9eYBF8D+O
# LX+lYaJICMyIzeILGaJ95sWetmY+dXJtVBFtqYShgkaCj1IWnmtMUXE0NFj92cao
# vlni+ETxhRcAc50SFl4k+xxE24RIIneIKA9jGP0GZa4MFGq5ZiDYm0MV4+XMHMOZ
# hC87tqDJjr77JO19Upv1Mggr4/9mgnkMnpgr8cY1CXAZeptqfhTrm6lgpakKqB0W
# LYKsR3BnXAKBvVjsP31VKtzX
# SIG # End signature block
