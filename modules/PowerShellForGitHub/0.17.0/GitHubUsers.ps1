# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubUserTypeName = 'GitHub.User'
    GitHubUserContextualInformationTypeName = 'GitHub.UserContextualInformation'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubUser
{
<#
    .SYNOPSIS
        Retrieves information about the specified user on GitHub.

    .DESCRIPTION
        Retrieves information about the specified user on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER UserName
        The GitHub user to retrieve information for.
        If not specified, will retrieve information on all GitHub users
        (and may take a while to complete).

    .PARAMETER Current
        If specified, gets information on the current user.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .NOTES
        The email key in the following response is the publicly visible email address from the
        user's GitHub profile page.  You only see publicly visible email addresses when
        authenticated with GitHub.

        When setting up your profile, a user can select a primary email address to be public
        which provides an email entry for this endpoint.  If the user does not set a public
        email address for email, then it will have a value of null.

    .INPUTS
        GitHub.User

    .OUTPUTS
        GitHub.User

    .EXAMPLE
        Get-GitHubUser -UserName octocat

        Gets information on just the user named 'octocat'

    .EXAMPLE
        'octocat', 'PowerShellForGitHubTeam' | Get-GitHubUser

        Gets information on the users named 'octocat' and 'PowerShellForGitHubTeam'

    .EXAMPLE
        Get-GitHubUser

        Gets information on every GitHub user.

    .EXAMPLE
        Get-GitHubUser -Current

        Gets information on the current authenticated user.
#>
    [CmdletBinding(DefaultParameterSetName = 'ListAndSearch')]
    [OutputType({$script:GitHubUserTypeName})]
    param(
        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName='ListAndSearch')]
        [Alias('Name')]
        [Alias('User')]
        [string] $UserName,

        [Parameter(ParameterSetName='Current')]
        [switch] $Current,

        [string] $AccessToken
    )

    Write-InvocationLog

    $params = @{
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
    }

    if ($Current)
    {
        return (Invoke-GHRestMethod -UriFragment "user" -Description "Getting current authenticated user" -Method 'Get' @params |
            Add-GitHubUserAdditionalProperties)
    }
    elseif ([String]::IsNullOrEmpty($UserName))
    {
        return (Invoke-GHRestMethodMultipleResult -UriFragment 'users' -Description 'Getting all users' @params |
            Add-GitHubUserAdditionalProperties)
    }
    else
    {
        return (Invoke-GHRestMethod -UriFragment "users/$UserName" -Description "Getting user $UserName" -Method 'Get' @params |
            Add-GitHubUserAdditionalProperties)
    }
}

filter Get-GitHubUserContextualInformation
{
<#
    .SYNOPSIS
        Retrieves contextual information about the specified user on GitHub.

    .DESCRIPTION
        Retrieves contextual information about the specified user on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER User
        The GitHub user to retrieve information for.

    .PARAMETER OrganizationId
        The ID of an Organization.  When provided, this returns back the context for the user
        in relation to this Organization.

    .PARAMETER RepositoryId
        The ID for a Repository.  When provided, this returns back the context for the user
        in relation to this Repository.

    .PARAMETER IssueId
        The ID for a Issue.  When provided, this returns back the context for the user
        in relation to this Issue.
        NOTE: This is the *id* of the issue and not the issue *number*.

    .PARAMETER PullRequestId
        The ID for a PullRequest.  When provided, this returns back the context for the user
        in relation to this Pull Request.
        NOTE: This is the *id* of the pull request and not the pull request *number*.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Issue
        GitHub.Organization
        GitHub.PullRequest
        GitHub.Repository
        GitHub.User

    .OUTPUTS
        GitHub.UserContextualInformation

    .EXAMPLE
        Get-GitHubUserContextualInformation -User octocat

    .EXAMPLE
        Get-GitHubUserContextualInformation -User octocat -RepositoryId 1300192

    .EXAMPLE
        $repo = Get-GitHubRepository -OwnerName microsoft -RepositoryName 'PowerShellForGitHub'
        $repo | Get-GitHubUserContextualInformation -User octocat

    .EXAMPLE
        Get-GitHubIssue -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 70 |
            Get-GitHubUserContextualInformation -User octocat
#>
    [CmdletBinding(DefaultParameterSetName = 'NoContext')]
    [OutputType({$script:GitHubUserContextualInformationTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Name')]
        [Alias('User')]
        [string] $UserName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Organization')]
        [int64] $OrganizationId,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Repository')]
        [int64] $RepositoryId,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Issue')]
        [int64] $IssueId,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='PullRequest')]
        [int64] $PullRequestId,

        [string] $AccessToken
    )

    Write-InvocationLog

    $getParams = @()

    $contextType = [String]::Empty
    $contextId = 0
    if ($PSCmdlet.ParameterSetName -ne 'NoContext')
    {
        if ($PSCmdlet.ParameterSetName -eq 'Organization')
        {
            $getParams += 'subject_type=organization'
            $getParams += "subject_id=$OrganizationId"

            $contextType = 'OrganizationId'
            $contextId = $OrganizationId
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Repository')
        {
            $getParams += 'subject_type=repository'
            $getParams += "subject_id=$RepositoryId"

            $contextType = 'RepositoryId'
            $contextId = $RepositoryId
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Issue')
        {
            $getParams += 'subject_type=issue'
            $getParams += "subject_id=$IssueId"

            $contextType = 'IssueId'
            $contextId = $IssueId
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'PullRequest')
        {
            $getParams += 'subject_type=pull_request'
            $getParams += "subject_id=$PullRequestId"

            $contextType = 'PullRequestId'
            $contextId = $PullRequestId
        }
    }

    $params = @{
        'UriFragment' = "users/$UserName/hovercard`?" + ($getParams -join '&')
        'Method' = 'Get'
        'Description' = "Getting hovercard information for $UserName"
        'AcceptHeader' = $script:hagarAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
    }

    $result = Invoke-GHRestMethod @params
    foreach ($item in $result.contexts)
    {
        $item.PSObject.TypeNames.Insert(0, $script:GitHubUserContextualInformationTypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            Add-Member -InputObject $item -Name 'UserName' -Value $UserName -MemberType NoteProperty -Force
            if ($PSCmdlet.ParameterSetName -ne 'NoContext')
            {
                Add-Member -InputObject $item -Name $contextType -Value $contextId -MemberType NoteProperty -Force
            }
        }
    }

    return $result
}

function Set-GitHubProfile
{
<#
    .SYNOPSIS
        Updates profile information for the current authenticated user on GitHub.

    .DESCRIPTION
        Updates profile information for the current authenticated user on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Name
        The new name of the user.

    .PARAMETER Email
        The publicly visible email address of the user.

    .PARAMETER Blog
        The new blog URL of the user.

    .PARAMETER Company
        The new company of the user.

    .PARAMETER Location
        The new location of the user.

    .PARAMETER Bio
        The new short biography of the user.

    .PARAMETER Hireable
        Specify to indicate a change in hireable availability for the current authenticated user's
        GitHub profile.  To change to "not hireable", specify -Hireable:$false

    .PARAMETER PassThru
        Returns the updated User Profile.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .OUTPUTS
        GitHub.User

    .EXAMPLE
        Set-GitHubProfile -Location 'Seattle, WA' -Hireable:$false

        Updates the current user to indicate that their location is "Seattle, WA" and that they
        are not currently hireable.
#>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType({$script:GitHubUserTypeName})]
    [Alias('Update-GitHubCurrentUser')] # Non-standard usage of the Update verb, but done to avoid a breaking change post 0.14.0
    param(
        [string] $Name,

        [string] $Email,

        [string] $Blog,

        [string] $Company,

        [string] $Location,

        [string] $Bio,

        [switch] $Hireable,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $hashBody = @{}
    if ($PSBoundParameters.ContainsKey('Name')) { $hashBody['name'] = $Name }
    if ($PSBoundParameters.ContainsKey('Email')) { $hashBody['email'] = $Email }
    if ($PSBoundParameters.ContainsKey('Blog')) { $hashBody['blog'] = $Blog }
    if ($PSBoundParameters.ContainsKey('Company')) { $hashBody['company'] = $Company }
    if ($PSBoundParameters.ContainsKey('Location')) { $hashBody['location'] = $Location }
    if ($PSBoundParameters.ContainsKey('Bio')) { $hashBody['bio'] = $Bio }
    if ($PSBoundParameters.ContainsKey('Hireable')) { $hashBody['hireable'] = $Hireable.ToBool() }

    if (-not $PSCmdlet.ShouldProcess('Update Current GitHub User'))
    {
        return
    }

    $params = @{
        'UriFragment' = 'user'
        'Method' = 'Patch'
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Description' = "Updating current authenticated user"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubUserAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Add-GitHubUserAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub User objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .PARAMETER Name
        The name of the user.  This information might be obtainable from InputObject, so this
        is optional based on what InputObject contains.

    .PARAMETER Id
        The ID of the user.  This information might be obtainable from InputObject, so this
        is optional based on what InputObject contains.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.User
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Internal helper that is definitely adding more than one property.")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubUserTypeName,

        [string] $Name,

        [int64] $Id
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $userName = $item.login
            if ([String]::IsNullOrEmpty($userName) -and $PSBoundParameters.ContainsKey('Name'))
            {
                $userName = $Name
            }

            if (-not [String]::IsNullOrEmpty($userName))
            {
                Add-Member -InputObject $item -Name 'UserName' -Value $userName -MemberType NoteProperty -Force
            }

            $userId = $item.id
            if (($userId -eq 0) -and $PSBoundParameters.ContainsKey('Id'))
            {
                $userId = $Id
            }

            if ($userId -ne 0)
            {
                Add-Member -InputObject $item -Name 'UserId' -Value $userId -MemberType NoteProperty -Force
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAIWCae/xRqMZJo
# sHzkkJ+kEVjUD7WbX+Ykk+yk9G6idaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGg8wghoLAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAj1+yomwBgq7Pz/K95bMtsQ
# ivrDm4VRh8Ja5RJuvS2CMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCw1pX7fb8MPlvdoB2HnC1rBRrjSAYy47CvzsY5J3hdea3hKHLH+ebj
# xZe/qeTtUH8jLACq30NYPICJSZ2qkepyzsq9V81TvK4TyXg5wKryCNz/VTo6PYq2
# o+JEAowDraoXpOx/K4Pv83EEZeLycTh5g95ZzD8dSzPkdBnjEO5pqe23aRA3XFO4
# Ir+wSq8PxvcZWLcR3y6SRH0BtsRXE2ORSsMf1tfbODvv6XyQpLSHuvoCLjxyW1Um
# +wf76syb04hklLYyYI2+wnwKNwr0XnHy2ySfZaU69icl+O1wTeAdD6ImHoA0kuxG
# B1l9Zx3lUsAPya2ZgNXfwPRe094eziCLoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEINfVLfBHVF++vUMCgJdA/OcUF6zIdguALlkugTXC0Rz0AgZlVsde
# 4DQYEzIwMjMxMTIxMTczNjA4LjgxNFowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo4NjAz
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAAB15sNHlcujFGOAAEAAAHXMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIzN1oXDTI0MDIwMTE5MTIzN1owgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo4NjAzLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAMSsYKQ3Zf9S+40Jx+XTJUE2j4sgjLMbsDXRfmRW
# Aaen2zyZ/hpmy6Rm7mu8uzs2po0TFzCc+4chZ2nqSzCNrVjD1LFNf4TSV6r5YG5w
# hEpZ1wy6YgMGAsTQRv/f8Fj3lm1PVeyedq0EVmGvS4uQOJP0eCtFvXbaybv9iTIy
# KAWRPQm6iJI9egsvvBpQT214j1A6SiOqNGVwgLhhU1j7ZQgEzlCiso1o53P+yj5M
# gXqbPFfmfLZT+j+IwVVN+/CbhPyD9irHDJ76U6Zr0or3y/q/B7+KLvZMxNVbApcV
# 1c7Kw/0aKhxe3fxy4/1zxoTV4fergV0ZOAo53Ssb7GEKCxEXwaotPuTnxWlCcny7
# 7KNFbouia3lFyuimB/0Qfx7h+gNShTJTlDuI+DA4nFiGgrFGMZmW2EOanl7H7pTr
# O/3mt33vfrrykakKS7QgHjcv8FPMxwMBXj/G7pF9xUXBqs3/Imrmp9nIyykfmBxp
# MJUCi5eRBNzwvC1/G2AjPneoxJVH1z2CRKfEzlzW0eCIxfcPYYGdBqf3m3L4J1Ng
# ACGOAFNzKP0/s4YQyGveXJpnGOveCmzpmajjtU5Mjy2xJgeEe0PwGkGiDf0vl7j+
# UMmD86risawUpLExe4hFnUTTx2Zfrtczuqa+bbs7zTgKESZv4I5HxZvjowUQTPra
# O77FAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUrqfAu/1ZAvc0jEQnI+4kxnowjY0w
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAFIF3dQn4iy90wJf4rvGodrlQG1ULUJp
# dm8dF36y1bSVcD91M2d4JbRMWsGgljn1v1+dtOi49F5qS7aXdfluaGxqjoMJFW6p
# yaFU8BnJJcZ6hV+PnZwsaLJksTDpNDO7oP76+M04aZKJs7QoT0Z2/yFARHHlEbQq
# CtOaTxyR4LVVSq55RAcpUIRKpMNQMPx1dMtYKaboeqZBfr/6AoNJeCDClzvmGLYB
# spKji26UzBN9cl0Z3CuyIeOTPyfMhb9nc+cyAYVTvoq7NgVXRfIf0NNL8M87zpEu
# 1CMDlmVUbKZM99OfDuTGiIsk3/KW4wciQdLOlom8KKpf4OfVAZEQSc0hl5F6S8ui
# 6uo9EQg5ObVslEnTrlz1hftsnSdo+LHObnLxjYH5gggQCLiNSto6HegTtrgm8hbc
# SDeg2o/uqGl3vEwvGrZacz5T1upZN5PhUKikCFe7a4ZB7F0urttZ1xjDIQUOFLhn
# 03S7DeHpuMHtLgxf3ql9hIRXQwoUY4puZ8JRLtZ6aS4WpnLSg0c8/H5x901h5IXp
# uE48d2yujURV3fNYiR0PUbmQQM+cRC0Vqu0zwf5u/nNSEBQmzyovO4UB0FlAu54P
# 1dl7KeNArAR4DPrfEBMgKHy05QzbMyBISFUvwebjlIHp+h6zgFMLRjxJlai/chqG
# 2/DIcVtSqzViMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+
# F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU
# 88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqY
# O7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzp
# cGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0Xn
# Rm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1
# zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZN
# N3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLR
# vWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTY
# uVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUX
# k8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB
# 2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKR
# PEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0g
# BFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQM
# MAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQ
# W9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
# bS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBa
# BggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOX
# PTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6c
# qYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/z
# jj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz
# /AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyR
# gNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdU
# bZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo
# 3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4K
# u+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10Cga
# iQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9
# vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGC
# A1AwggI4AgEBMIH5oYHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046ODYwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# ADFb26LMbeERjz24va675f6Yb+t1oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpBzSFMCIYDzIwMjMxMTIxMTM1
# MjA1WhgPMjAyMzExMjIxMzUyMDVaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOkH
# NIUCAQAwCgIBAAICA1oCAf8wBwIBAAICE6swCgIFAOkIhgUCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEAP+ZhbpsuLd6+3AKom7AF7UnI987ZvK1q3B4FvEwJ
# IawNBI1K01v4tZxjct2GUQupXwqLUCXSr10DVUg4aBz+z/+hqlI0hBVXStz7Ptvu
# 1KXni8rIX9jUnWgBGHmF2Xz4GH5X0GUBA9K8uZbYfe2HnXVQ9WWferTw0cZn14Fd
# s1DS1ylQmssI3ZXj42GsshIF+UObEzup/ChMp+fcQwWCMu+XTAQja9SezfsAleqd
# VC8+ZLenbDjvlYCl1P2SRW3qqVxgh04BhHnSgqYKuH/xLwAzdmnarSctSkiz1sw1
# f+xeiCC5aDSDEjhjl+3Ugv2itt1YLcFhbQJLxvieJtqysjGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB15sNHlcujFGOAAEA
# AAHXMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIF6u1Wx4yZpgf5Bgo7vt57aaCbLGLAVjXS1WTTJw
# WliuMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgnN4+XktefU+Ko2PHxg3t
# M3VkjR3Vlf/bNF2cj3usmjswgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAdebDR5XLoxRjgABAAAB1zAiBCCRk2UKPzkqALam3mrjq8U/
# 8TKrNFwzX7y0Dh+4V5Z8dTANBgkqhkiG9w0BAQsFAASCAgC22w03Kn+76NYTMPnz
# AyXOYe9cF0QpL+Uc37HPZDRj0dSJpgTemgoRV3/Qc52cemtm2AzobnvU9zf2/syp
# cKNKVRtdFk/RD1yeWmFnjs2BrwtPpIqpPoakRO0rXPzGHZmEdVhYT5xV2Zudq1FD
# 3+0bkGEdjVpgxXUfm5MhJhUftRf8sDpwlgVeGUbut4A5BBBTt8fm+9NnwYA2qeeM
# nL1pNJwRbTI2qG6jGjEdqsL+UMERdaBV3OpTTN+XZCrNiMNufvAEzGRBRJEbEHPr
# QJ6X77Myrs0e4OhwDsaVv5G7S4umidDvsTiLPaBrl4aLwcvAo/kXUZQ2hS04ktlq
# nc1sYPkGJW6P+jxu4Ys4zZd2Yizt4JAkSpc5x/5/+68ARbuKN8sj/9eUulIdJVP2
# 7NGHIVX8ALBJWXEyFIrQ5NYDw6/iMDBIHXqBZsRUvwxs7bWwCdLyPpbkRr1jorw7
# inENIOt+B9qNPVXmoPF3Rhx4o9IKb/CbFevjytqS/ZOwQUToO0WfytyLw0WhG3PA
# pi/8R1N7cAolEMVyXMCTWd2ojkTuCK4v+CJTzHrB917dOlWZnJ2ug2yZ//jq74yH
# JqfoEtYPDEL+kqit+sdkoAwEuwhItuwGE2mYJvQgBJvZVwJmW2Ttf0O1Ia7x2CKc
# a/q5Ta5XLXDPssMPBqmTeODJeg==
# SIG # End signature block
