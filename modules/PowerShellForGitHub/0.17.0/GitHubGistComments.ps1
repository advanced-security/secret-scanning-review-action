# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubGistCommentTypeName = 'GitHub.GistComment'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubGistComment
{
<#
    .SYNOPSIS
        Retrieves comments for a specific gist from GitHub.

    .DESCRIPTION
        Retrieves comments for a specific gist from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to retrieve the comments for.

    .PARAMETER Comment
        The ID of the specific comment on the gist that you wish to retrieve.

    .PARAMETER MediaType
        The format in which the API will return the body of the comment.

        Raw - Return the raw markdown body. Response will include body. This is the default if you do not pass any specific media type.
        Text - Return a text only representation of the markdown body. Response will include body_text.
        Html - Return HTML rendered from the body's markdown. Response will include body_html.
        Full - Return raw, text and HTML representations. Response will include body, body_text, and body_html.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.GistComment

    .EXAMPLE
        Get-GitHubGistComment -Gist 6cad326836d38bd3a7ae

        Gets all comments on octocat's "hello_world.rb" gist.

    .EXAMPLE
        Get-GitHubGistComment -Gist 6cad326836d38bd3a7ae -Comment 1507813

        Gets comment 1507813 from octocat's "hello_world.rb" gist.
#>
    [CmdletBinding(PositionalBinding = $false)]
    [OutputType({$script:GitHubGistCommentTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [string] $Gist,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('GistCommentId')]
        [ValidateNotNullOrEmpty()]
        [int64] $Comment,

        [ValidateSet('Raw', 'Text', 'Html', 'Full')]
        [string] $MediaType = 'Full',

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = [String]::Empty
    $description = [String]::Empty

    if ($PSBoundParameters.ContainsKey('Comment'))
    {
        $telemetryProperties['SpecifiedComment'] = $true

        $uriFragment = "gists/$Gist/comments/$Comment"
        $description = "Getting comment $Comment for gist $Gist"
    }
    else
    {
        $uriFragment = "gists/$Gist/comments"
        $description = "Getting comments for gist $Gist"
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' =  $description
        'AccessToken' = $AccessToken
        'AcceptHeader' = (Get-MediaAcceptHeader -MediaType $MediaType -AsJson)
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubGistCommentAdditionalProperties)
}

filter Remove-GitHubGistComment
{
<#
    .SYNOPSIS
        Removes/deletes a comment from a gist on GitHub.

    .DESCRIPTION
        Removes/deletes a comment from a gist on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to remove the comment from.

    .PARAMETER Comment
        The ID of the comment to remove from the gist.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .EXAMPLE
        Remove-GitHubGist -Gist 6cad326836d38bd3a7ae -Comment 12324567

        Removes the specified comment from octocat's "hello_world.rb" gist
        (assuming you have permission).

    .EXAMPLE
        Remove-GitHubGist -Gist 6cad326836d38bd3a7ae -Comment 12324567 -Confirm:$false

        Removes the specified comment from octocat's "hello_world.rb" gist
        (assuming you have permission).
        Will not prompt for confirmation, as -Confirm:$false was specified.

    .EXAMPLE
        Remove-GitHubGist -Gist 6cad326836d38bd3a7ae -Comment 12324567 -Force

        Removes the specified comment from octocat's "hello_world.rb" gist
        (assuming you have permission).
        Will not prompt for confirmation, as -Force was specified.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false,
        ConfirmImpact="High")]
    [Alias('Delete-GitHubGist')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [Alias('GistCommentId')]
        [ValidateNotNullOrEmpty()]
        [int64] $Comment,

        [switch] $Force,

        [string] $AccessToken
    )

    Write-InvocationLog

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Comment, "Delete comment from gist $Gist"))
    {
        return
    }

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist/comments/$Comment"
        'Method' = 'Delete'
        'Description' =  "Removing comment $Comment from gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter New-GitHubGistComment
{
<#
    .SYNOPSIS
        Creates a new comment on the specified gist from GitHub.

    .DESCRIPTION
        Creates a new comment on the specified gist from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the specific gist that you wish to add the comment to.

    .PARAMETER Body
        The body of the comment that you wish to leave on the gist.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.GistComment

    .EXAMPLE
        New-GitHubGistComment -Gist 6cad326836d38bd3a7ae -Body 'Hello World'

        Adds a new comment of "Hello World" to octocat's "hello_world.rb" gist.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistCommentTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [Parameter(
            Mandatory,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Body,

        [string] $AccessToken
    )

    Write-InvocationLog

    $hashBody = @{
        'body' = $Body
    }

    if (-not $PSCmdlet.ShouldProcess($Gist, "Create new comment for gist"))
    {
        return
    }

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist/comments"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Post'
        'Description' =  "Creating new comment on gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethod @params | Add-GitHubGistCommentAdditionalProperties)
}

filter Set-GitHubGistComment
{
    <#
    .SYNOPSIS
        Edits a comment on the specified gist from GitHub.

    .DESCRIPTION
        Edits a comment on the specified gist from GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Gist
        The ID of the gist that the comment is on.

    .PARAMETER Comment
        The ID of the comment that you wish to edit.

    .PARAMETER Body
        The new text of the comment that you wish to leave on the gist.

    .PARAMETER PassThru
        Returns the updated Comment.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Gist
        GitHub.GistComment
        GitHub.GistCommit
        GitHub.GistFork
        GitHub.GistSummary

    .OUTPUTS
        GitHub.GistComment

    .EXAMPLE
        Set-GitHubGistComment -Gist 6cad326836d38bd3a7ae -Comment 1232456 -Body 'Hello World'

        Updates the body of the comment with ID 1232456 octocat's "hello_world.rb" gist to be
        "Hello World".
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false)]
    [OutputType({$script:GitHubGistCommentTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [Alias('GistId')]
        [ValidateNotNullOrEmpty()]
        [string] $Gist,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [Alias('GistCommentId')]
        [ValidateNotNullOrEmpty()]
        [int64] $Comment,

        [Parameter(
            Mandatory,
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $Body,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $hashBody = @{
        'body' = $Body
    }

    if (-not $PSCmdlet.ShouldProcess($Comment, "Update gist comment on gist $Gist"))
    {
        return
    }

    $telemetryProperties = @{}
    $params = @{
        'UriFragment' = "gists/$Gist/comments/$Comment"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Patch'
        'Description' = "Creating new comment on gist $Gist"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubGistCommentAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Add-GitHubGistCommentAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Gist Comment objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .PARAMETER GistId
        The ID of the gist that the comment is for.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.GistComment
#>
    [CmdletBinding()]
    [OutputType({$script:GitHubGisCommentTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Internal helper that is definitely adding more than one property.")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubGistCommentTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $hostName = $(Get-GitHubConfiguration -Name 'ApiHostName')
            if ($item.url -match "^https?://(?:www\.|api\.|)$hostName/gists/([^/]+)/comments/(.+)$")
            {
                $gistId = $Matches[1]
                $commentId = $Matches[2]

                if ($commentId -ne $item.id)
                {
                    $message = "The gist comment url no longer follows the expected pattern.  Please contact the PowerShellForGitHubTeam: $item.url"
                    Write-Log -Message $message -Level Warning
                }
            }

            Add-Member -InputObject $item -Name 'GistCommentId' -Value $item.id -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'GistId' -Value $gistId -MemberType NoteProperty -Force

            if ($null -ne $item.user)
            {
                $null = Add-GitHubUserAdditionalProperties -InputObject $item.user
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLgYJKoZIhvcNAQcCoIIoHzCCKBsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpZ8N03tJRHri/
# 6gp4tCeA+qUD2iXxTuxeGDBrHtehWKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIASJmaF1VxlQdeF0HxCjNPaz
# yKKcKVjx+W5x8X3YSl28MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB6V9l4Fz8h2Un+JGKz5m2YO8DVFljtd2m9oEiOBu7rwQ/T46X0qRvE
# fiGwxI9zW9Ue25l6aE6ZWUV0ZAsPdWhKPkvGTRUiAmpKlizlol2E7fjM3g422JuW
# 69UstoWb8IK3CyVujphF+BJz2CyrzY4RMjfE2iBYEo33Egnm2ClO2Lvwe23KJ3us
# pWyIy6NKVqWPKuSiCFoP11DF8dX1XCjpP+AD6mSr+Tp+px8NL3GOoBdMp36E08ug
# B4dqn3u3eK5uPTZvdhWNBMTZS1mGFm2P2MrRWHhzweWkOTCgVCbgYppVCrds0wRh
# /siwplX4M9El0aCI1EQGT7VB9bT9eVrZoYIXljCCF5IGCisGAQQBgjcDAwExgheC
# MIIXfgYJKoZIhvcNAQcCoIIXbzCCF2sCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIB6RPGdo82dbxVUplNGlzN0ftAAZcXe+w3umxSqFUkhIAgZlVsmd
# 4+gYEjIwMjMxMTIxMTczNTI2LjU1WjAEgAIB9KCB0aSBzjCByzELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjg5MDAt
# MDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIR7TCCByAwggUIoAMCAQICEzMAAAHTHTKaFztAMHMAAQAAAdMwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMwNTI1MTkx
# MjI0WhcNMjQwMjAxMTkxMjI0WjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjg5MDAtMDVFMC1EOTQ3MSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAtI6rkzeINcW4VwnPDFfnTrvFKnNym22lrYub3bAF
# jNQ+H1UovuDVoBrT/wVUWK1Y9qFZ5zMtHms4nUDieLlLHATGzx2jMWjaYG0RvRRE
# ERZ3AFKbVpyPlT5edzw+jDy9Ms/HBwtmQ98HheMPrjAwBpy9+gZJtLKzjV75zPXj
# b5xuXY6KRKoh6HVkmrkcnuLn7QUdrE8Bh1ZsSrtBkuHzvOzYGyeFRsyAkcmV8Pfk
# b71zBv44TNdR/AFisyqZ9KDBptTEjHjby1Fm99R0mXpMfzQRLV75naO+TldN9DR4
# CF4ocWBHkoFCMX2yOTpoDKv1QwkKdq/38v+TVWtyowkKDapphDOqKwCdlyo2IRCc
# 6KeJ1gnCfe9FOq16QTyuFxjSgRYYS2u+EzP8rExSKxFziRtX1Ll33HVm9BMdBQHk
# 06+oJpgqq3iTXozR33xv1RHheyzb1KrmBUZ3YglIYMutuK1uqbXJ0E4kXxNEC/4C
# xeNZANr2TGM3HNehImF0EAWhd1wLTHbodXaV6kzz0BDtzLOf+QfyrY4UrKTHD1L0
# b29+SFjfqvi/sxMIqYZpwhhU7sjjKnOUBNK7hjdzMdFb+sf4XDpml8ax0BqTSiOT
# 5+/WJPPQHJalNplx89WR1qfigXNw+lT+y99iZcMYScd2rGtPOcb9Fzw+fDEVtVmh
# r2kCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTSxyCGuBQA+PeM9+Yb8wpptONeYjAf
# BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
# hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQl
# MjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBe
# MFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Nl
# cnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQE
# AwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAQGJYWKFEPuGmkOeDBTXxOhMvL+K1r/i7
# Q0UozDNl/YOLmpwPXFO1YrXaSD1f8xOr+ABIXv1Z4NlAEeao9kld7M/nw6jelS1l
# GbCkdEEdiWFypxT0VY9ens2cj+83eR/CLL7HBHKJ3l/mkRxdMRhjOLQy60vOL4+k
# ZtG4KFi11pzE2eZD+KMJxpptC7JiJ7rtBiqw2Z5Hk1Zn5PIE08vHdctz9iGHNlCO
# IiWFwrkmigrhXjtMKsrHKb4RkEp6NVwBSt6Gsm7g9ZkqEMU/au+/iwBhkG4kqBpY
# E40EGsmLEGj3BtUOEDcDjRqpAEgmU28yZZ5pB4JFpSki07pTmopViGOIUtRGfsPr
# F9ASfS3DNeNoedTpVyzKDy6cxwG+sdtoqWgCeSn97shWjilsOIZ7tM1rPjyj3dfd
# p3XitqIFn2hXX5xL5Fgwx9naC/mQOUAXfF54LP5ndwa55ZdgZGf4ImRP3ysqJa4k
# d2kwFgsRQlyiJfwpbtm254/an1WC6QFUBHD2gn0wH+zmQZV5pbhE76tWP0jYcQuj
# CdUCwp5F0iP/4l2KZkSk+/N0CkYJqP+M7Y97i/We8W2xsSEoPj9B00V9ecuE0XgW
# ztkRTcgo/PIDjkZPrME9ZGil1HxgeM44OV7pcUm8t7izcUHmxOkxN3ACtPn52OVK
# R2hHZcOHu4owggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqG
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
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo4OTAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# Usdt3DHDQdSEMLPy2JEV2uyOSbCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsFAAIFAOkHNsIwIhgPMjAyMzExMjExNDAx
# MzhaGA8yMDIzMTEyMjE0MDEzOFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA6Qc2
# wgIBADAKAgEAAgIzbgIB/zAHAgEAAgITXzAKAgUA6QiIQgIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBCwUAA4IBAQCGHyoc9fJ8ED98NCpjB9cyzm7y8rsD5qH06vGmKXfF
# 4XvC0QB5cfvgDo//bdOV7k+rV4shL0tL/ChaPEpVUNtxYdRXgZ/JjYKy7FF0mJBR
# LH0VU8X8fhblvwNWn7wktjZEraB/qQ/RqwGN3yZhuCS9fekYnyND+sS/TbeFUHkr
# PLrHSLMidaAIEddRA1AroG84sYP1b1/U8HJyMkyBICH5Pw5LNTMgAo7xu9sBc4Vc
# O0QQdn1o7OBB5D8lbS/zE/Lrir6z1F0Wvf4vVAVQeXwsRXtgOqhSxSK4mrQM3bZC
# 8gr5kVGi6UvaEJ9PlueegWJQuVVB6HrMJUWg6OC55lzUMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHTHTKaFztAMHMAAQAA
# AdMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgamqal4GM2vAZF92mB8LnbvTr1Rd3FUiRn5yC8VMD
# UXQwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCSZvTqxODuT1gNSmhWs7a/
# bj/eq0IBJ/rYBrWN8Tqq9TCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAAB0x0ymhc7QDBzAAEAAAHTMCIEIH6JVQj8F/GFeGsg57etzcvv
# Rnq7WuOymKb78cVSKsh9MA0GCSqGSIb3DQEBCwUABIICAK7ikNjsNd1ydR4i11AM
# NgC6uEJwPSZVOUWl4E92Y+g4Z4MKRgi1z54ehXjaUwKnr6/yO0Q6l/VijaSCgj4f
# jma1isAG5lJR322UNWbQfdxxgDDTdYYggExmADRXE3ZFaJS6tXIRq6l0MTEqCdU1
# mCuLXkvcRihHss9yZvQ1MQCttfLbATQUyMIzqd2r8H+9jQdvpHI0NpSrVn88FV2R
# c9dTiEaUpillsz+klCUu3Tz949enOR57uMiAxmSVkldawJd3fX7CRndU0VfDgXo4
# hRf92n8fb9JMdBqhhROCAz0Yn2fUjp43gJr9qr+upoIJnva4DorVwAJsBMpm7kMf
# hlxNEj2JasH6LnjBYOqO5ycJrNcjUqB2kLcNCDiWOCSKRcrMwIDaNZdl0W5drz5g
# TkgWsLXV+tz3PKoTvzwDCTPhrN8NLhrYV1lVt8zQ55HpxFiHf4DsOZIT+oC+12w4
# KjTlDd38ZtuWpQmgy9pIiSoZJErU1YgxKIi9DaEvnMMTXjvTbYW7YgXVsK2R8T0m
# ShNLKacJT5B3oENFztlBK7cbSSBgoZfODNNJRWLHrGoGigjgAAmauwlzNCVMejK3
# 38JUNHUHtK64FWjAd/HRj4hXX8YY5sdZCtTmJC0cNsi3JdixLrPixkV98RZr75Ct
# Vu8h5DxB6HTKP4lCct5WGWQV
# SIG # End signature block
