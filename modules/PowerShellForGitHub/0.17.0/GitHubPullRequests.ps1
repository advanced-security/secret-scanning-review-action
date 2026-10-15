# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubPullRequestTypeName = 'GitHub.PullRequest'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubPullRequest
{
<#
    .SYNOPSIS
        Retrieve the pull requests in the specified repository.

    .DESCRIPTION
        Retrieve the pull requests in the specified repository.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OwnerName
        Owner of the repository.
        If not supplied here, the DefaultOwnerName configuration property value will be used.

    .PARAMETER RepositoryName
        Name of the repository.
        If not supplied here, the DefaultRepositoryName configuration property value will be used.

    .PARAMETER Uri
        Uri for the repository.
        The OwnerName and RepositoryName will be extracted from here instead of needing to provide
        them individually.

    .PARAMETER PullRequest
        The specific pull request id to return back.  If not supplied, will return back all
        pull requests for the specified Repository.

    .PARAMETER State
        The state of the pull requests that should be returned back.

    .PARAMETER Head
        Filter pulls by head user and branch name in the format of 'user:ref-name'

    .PARAMETER Base
        Base branch name to filter the pulls by.

    .PARAMETER Sort
        What to sort the results by.
        * created
        * updated
        * popularity (comment count)
        * long-running (age, filtering by pulls updated in the last month)

    .PARAMETER Direction
        The direction to be used for Sort.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Branch
        GitHub.Content
        GitHub.Event
        GitHub.Issue
        GitHub.IssueComment
        GitHub.Label
        GitHub.Milestone
        GitHub.PullRequest
        GitHub.Project
        GitHub.ProjectCard
        GitHub.ProjectColumn
        GitHub.Reaction
        GitHub.Release
        GitHub.ReleaseAsset
        GitHub.Repository

    .OUTPUTS
        GitHub.PulLRequest

    .EXAMPLE
        $pullRequests = Get-GitHubPullRequest -Uri 'https://github.com/PowerShell/PowerShellForGitHub'

    .EXAMPLE
        $pullRequests = Get-GitHubPullRequest -OwnerName microsoft -RepositoryName PowerShellForGitHub -State Closed
#>
    [CmdletBinding(DefaultParameterSetName = 'Elements')]
    param(
        [Parameter(ParameterSetName='Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName='Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('PullRequestNumber')]
        [int64] $PullRequest,

        [ValidateSet('Open', 'Closed', 'All')]
        [string] $State = 'Open',

        [string] $Head,

        [string] $Base,

        [ValidateSet('Created', 'Updated', 'Popularity', 'LongRunning')]
        [string] $Sort = 'Created',

        [ValidateSet('Ascending', 'Descending')]
        [string] $Direction = 'Descending',

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
        'ProvidedPullRequest' = $PSBoundParameters.ContainsKey('PullRequest')
    }

    $uriFragment = "/repos/$OwnerName/$RepositoryName/pulls"
    $description = "Getting pull requests for $RepositoryName"
    if ($PSBoundParameters.ContainsKey('PullRequest'))
    {
        $uriFragment = $uriFragment + "/$PullRequest"
        $description = "Getting pull request $PullRequest for $RepositoryName"
    }

    $sortConverter = @{
        'Created' = 'created'
        'Updated' = 'updated'
        'Popularity' = 'popularity'
        'LongRunning' = 'long-running'
    }

    $directionConverter = @{
        'Ascending' = 'asc'
        'Descending' = 'desc'
    }

    $getParams = @(
        "state=$($State.ToLower())",
        "sort=$($sortConverter[$Sort])",
        "direction=$($directionConverter[$Direction])"
    )

    if ($PSBoundParameters.ContainsKey('Head'))
    {
        $getParams += "head=$Head"
    }

    if ($PSBoundParameters.ContainsKey('Base'))
    {
        $getParams += "base=$Base"
    }

    $params = @{
        'UriFragment' = $uriFragment + '?' +  ($getParams -join '&')
        'Description' = $description
        'AcceptHeader' = $script:symmetraAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubPullRequestAdditionalProperties)
}

filter New-GitHubPullRequest
{
    <#
    .SYNOPSIS
        Create a new pull request in the specified repository.

    .DESCRIPTION
        Opens a new pull request from the given branch into the given branch
        in the specified repository.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OwnerName
        Owner of the repository.
        If not supplied here, the DefaultOwnerName configuration property value will be used.

    .PARAMETER RepositoryName
        Name of the repository.
        If not supplied here, the DefaultRepositoryName configuration property value will be used.

    .PARAMETER Uri
        Uri for the repository.
        The OwnerName and RepositoryName will be extracted from here instead of needing to provide
        them individually.

    .PARAMETER Title
        The title of the pull request to be created.

    .PARAMETER Body
        The text description of the pull request.

    .PARAMETER Issue
        The GitHub issue number to open the pull request to address.

    .PARAMETER Head
        The name of the head branch (the branch containing the changes to be merged).

        May also include the name of the owner fork, in the form "${fork}:${branch}".

    .PARAMETER Base
        The name of the target branch of the pull request
        (where the changes in the head will be merged to).

    .PARAMETER HeadOwner
        The name of fork that the change is coming from.

        Used as the prefix of $Head parameter in the form "${HeadOwner}:${Head}".

        If unspecified, the unprefixed branch name is used,
        creating a pull request from the $OwnerName fork of the repository.

    .PARAMETER MaintainerCanModify
        If set, allows repository maintainers to commit changes to the
        head branch of this pull request.

    .PARAMETER Draft
        If set, opens the pull request as a draft.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Branch
        GitHub.Content
        GitHub.Event
        GitHub.Issue
        GitHub.IssueComment
        GitHub.Label
        GitHub.Milestone
        GitHub.PullRequest
        GitHub.Project
        GitHub.ProjectCard
        GitHub.ProjectColumn
        GitHub.Reaction
        GitHub.Release
        GitHub.ReleaseAsset
        GitHub.Repository

    .OUTPUTS
        GitHub.PullRequest

    .EXAMPLE
        $prParams = @{
            OwnerName = 'Microsoft'
            Repository = 'PowerShellForGitHub'
            Title = 'Add simple file to root'
            Head = 'octocat:simple-file'
            Base = 'master'
            Body = "Adds a simple text file to the repository root.`n`nThis is an automated PR!"
            MaintainerCanModify = $true
        }
        $pr = New-GitHubPullRequest @prParams

    .EXAMPLE
        New-GitHubPullRequest -Uri 'https://github.com/PowerShell/PSScriptAnalyzer' -Title 'Add test' -Head simple-test -HeadOwner octocat -Base development -Draft -MaintainerCanModify

    .EXAMPLE
        New-GitHubPullRequest -Uri 'https://github.com/PowerShell/PSScriptAnalyzer' -Issue 642 -Head simple-test -HeadOwner octocat -Base development -Draft
    #>

    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements_Title')]
    param(
        [Parameter(ParameterSetName='Elements_Title')]
        [Parameter(ParameterSetName='Elements_Issue')]
        [string] $OwnerName,

        [Parameter(ParameterSetName='Elements_Title')]
        [Parameter(ParameterSetName='Elements_Issue')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri_Title')]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri_Issue')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ParameterSetName='Elements_Title')]
        [Parameter(
            Mandatory,
            ParameterSetName='Uri_Title')]
        [ValidateNotNullOrEmpty()]
        [string] $Title,

        [Parameter(ParameterSetName='Elements_Title')]
        [Parameter(ParameterSetName='Uri_Title')]
        [string] $Body,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Elements_Issue')]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri_Issue')]
        [Alias('IssueNumber')]
        [int64] $Issue,

        [Parameter(Mandatory)]
        [string] $Head,

        [Parameter(Mandatory)]
        [string] $Base,

        [string] $HeadOwner,

        [switch] $MaintainerCanModify,

        [switch] $Draft,

        [string] $AccessToken
    )

    Write-InvocationLog

    if (-not [string]::IsNullOrWhiteSpace($HeadOwner))
    {
        if ($Head.Contains(':'))
        {
            $message = "`$Head ('$Head') was specified with an owner prefix, but `$HeadOwner ('$HeadOwner') was also specified." +
                " Either specify `$Head in '<owner>:<branch>' format, or set `$Head = '<branch>' and `$HeadOwner = '<owner>'."

            Write-Log -Message $message -Level Error
            throw $message
        }

        # $Head does not contain ':' - add the owner fork prefix
        $Head = "${HeadOwner}:${Head}"
    }

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
    }

    $uriFragment = "/repos/$OwnerName/$RepositoryName/pulls"

    $postBody = @{
        'head' = $Head
        'base' = $Base
    }

    if ($PSBoundParameters.ContainsKey('Title'))
    {
        $description = "Creating pull request $Title in $RepositoryName"
        $shouldProcessAction = "Create GitHub Pull Request: $Title"
        $postBody['title'] = $Title

        # Body may be whitespace, although this might not be useful
        if ($Body)
        {
            $postBody['body'] = $Body
        }
    }
    else
    {
        $description = "Creating pull request for issue $Issue in $RepositoryName"
        $shouldProcessAction = "Create GitHub Pull Request for Issue $Issue"
        $postBody['issue'] = $Issue
    }

    if ($MaintainerCanModify)
    {
        $postBody['maintainer_can_modify'] = $true
    }

    if ($Draft)
    {
        $postBody['draft'] = $true
        $acceptHeader = 'application/vnd.github.shadow-cat-preview+json'
    }

    if (-not $PSCmdlet.ShouldProcess($RepositoryName, $shouldProcessAction))
    {
        return
    }

    $restParams = @{
        'UriFragment' = $uriFragment
        'Method' = 'Post'
        'Description' = $description
        'Body' = ConvertTo-Json -InputObject $postBody -Compress
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    if ($acceptHeader)
    {
        $restParams['AcceptHeader'] = $acceptHeader
    }

    return (Invoke-GHRestMethod @restParams | Add-GitHubPullRequestAdditionalProperties)
}

filter Add-GitHubPullRequestAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Repository objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.
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
        [string] $TypeName = $script:GitHubPullRequestTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $elements = Split-GitHubUri -Uri $item.html_url
            $repositoryUrl = Join-GitHubUri @elements
            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'PullRequestId' -Value $item.id -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'PullRequestNumber' -Value $item.number -MemberType NoteProperty -Force

            @('assignee', 'assignees', 'requested_reviewers', 'merged_by', 'user') |
                ForEach-Object {
                    if ($null -ne $item.$_)
                    {
                        $null = Add-GitHubUserAdditionalProperties -InputObject $item.$_
                    }
                }

            if ($null -ne $item.labels)
            {
                $null = Add-GitHubLabelAdditionalProperties -InputObject $item.labels
            }

            if ($null -ne $item.milestone)
            {
                $null = Add-GitHubMilestoneAdditionalProperties -InputObject $item.milestone
            }

            if ($null -ne $item.requested_teams)
            {
                $null = Add-GitHubTeamAdditionalProperties -InputObject $item.requested_teams
            }

            # TODO: What type are item.head and item.base?
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD4CPafwA8DRxVx
# T73QDBJGM321c5RgiQp8rs03EacFdKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIM5T/nyWqqDj8mgyrEj24pDW
# v2K7I8GA+vkqumCamlDUMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBlLI9WAZPnk9FWTRE/i48m8g8cO4dE1RWQPPaSxRLHRs8lS2makmdp
# sCx4JLE/EGYuH2dU0WSJgV3tMVp8zzwmHbJjpuPaeGJg5cLfKk/7cttPUbNuWJOB
# 2vH8VoUOGQbrnRXo7ve//t9oGfC2/0W9VI4oKv/hB4vRtKk8Xl9nYqWmNAYEODoL
# pEbv6++5uDdZHzW6hT2zOUIurRmjt2PKZzzUJLrPh5BFcD3y3eMEfVR6ZNAeXAWE
# P9WRtSVNc5bzPnl4AwAI5WP7HRWa+++bSK8yj6SSyCbsOzIAlS5xSEHZjVKrIDyH
# TNG30+KwEpaAXzv7KkK+oxxyZFrhJA9zoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHNFmpFoSNVFfyigESEe5b7Ylyt4tPNdKwX+ACer7kumAgZlVsZl
# xowYEzIwMjMxMTIxMTczNTUyLjI0N1owBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo5MjAw
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAABz1I2vnFLzUjKAAEAAAHPMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIxMVoXDTI0MDIwMTE5MTIxMVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo5MjAwLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALg9y37XlNjKtSN7nneXMFCh2CZ3kHPta4fxJ0ek
# ChbP7TVOscTEFK5owqfG9UyzJi1qzmHpqilQYBLlYpUtkC9S0frZMqYATQkr6LWF
# p+IJJctk9xF7HF5GQ6p5l58sHNenSe50w5dRRpvffdKzwuSgriXctjGbURuyvdvY
# 5OjZ5uwCg0niRLGZW48zsL5EOEa1UpH8SYexD0ZzAaaW67nhuqJUV3SgAUFvDi3F
# NTWau4gZY/+L6yCI2q91X/BqH9BysqIaWlaI6v1rloaslo9JAPbGAQN09utJ+VjG
# xEx1kIkjy/O86/oGW49w88YZUsRpTs6zN1iMrl/hnlK7+U8rV5JPk8LhEWxVw6JL
# gvSwjggVnLAh0MkegqB2pZGnpDm8QOTyS9nPodYWdgs6Ue6owRi9Auvo6CihhT3P
# QDlwwscQgdhXXGJoHPHYRGJFj0xQ9aiGH5OllYRRmVSb+r1qddVE3S6N6Obo6xRU
# UOywgyzNE0KoSi0kbC0cebnGsIq4mQWvwZ/A16UWX5cOgdetBgv3Njs2n5+uxNdC
# kpE2eYjVqyFyfkQL7DFS38RkiyRbN7AR+3T/7/SDf7xi0yRR1pATn7x7sLxQyJc4
# eQwrbmM01CosJ52UnAUh/2Kv1KkxzvY1H7WPpR5uLP9k9Xvh2jeN1W+rsOI8WVNv
# 3ZQrAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUNp4o+2nR5NJV0b6BlzkEORptODgw
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAFCCbimcDTGR3/24pckzN0xjLFR9Sb9m
# 6xQFrfYwRldC4wanbSlK5fZVb3+2lMyjluRol0FWhTJ3YNsOw1vWSOv/fqe1PSO8
# vcChZK0AWFkHKmak9vH4E8rj1mV6OUzh3l6lfrry1FEZ8WKn1OKX3IpF9cGtecz+
# rrgiKc3vNcRDcUVCF0kzO3yJtcKU7t4UD7UeLBk9bKxhY9v9k4Whs8Qy9eJ74aYR
# tMpuETm3N7pGsD1p6OM/6/Wi4WgPlsyPlCD7B9lep76F9gqkx3xA6dDJ7P42WPWK
# 3Kc5lZ/AdVHt1XBXTItKU9P7Icg7yD7d9aIDCmg7XtsNye1Jntg4GWNesiBp3hbi
# Bf7i2nV4GxzpdYghM8E3PFANllHEPitfM4HpdGURUl1hlDyBtc6KuD9029LYbFxH
# nRB05cMC6Z0QdoY0dvrLYiclp0I+naJPlAsLgyfNH5hmejVvyZakJ051Gz2DbVBt
# usjTqIuT0oPrWfHsrlF5K5y5Lln2duQgFotTEN6wWGvXCZ3XKd/QdDnVLCvKHtgj
# tNdPSOvzWZu+8j3G2iqMW8iE0GwgJ0J9NH3XKUlMfxa1SWkOESBKpa3eDM0s9NK9
# cDFdOkgznzexl137/ZgYAMx5aa3w+4xx7oawhwsI4XY2JhnXRJcdlLkdGsusKG7N
# 50NGKxaki7m5MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046OTIwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# AOrzHNVfAuC5q4BCPWusnj9PIQyboIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpBzOJMCIYDzIwMjMxMTIxMTM0
# NzUzWhgPMjAyMzExMjIxMzQ3NTNaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOkH
# M4kCAQAwCgIBAAICHeACAf8wBwIBAAICE6YwCgIFAOkIhQkCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEAKknlyh3fsQyaENZvfNZCOqduISaCJA5xmvmQ3dlP
# IKuqGmFBeTUlLkoHEWtVbHgnWTmALtc5tjW7Kf7TojDgvLpYxAV35Oz81D2C1+Y0
# gDNgTOkXwwbyIxVGCa/E83BVpnRW0Y28XK4hzjhFOsvHrVvyjldu2JHr1Iwk2Qe0
# fpU+CPu38amNgqq/CbGDNuXuhKUdLoGF9har9JMFrjUr2Red8Yq0By0z/SoyK4th
# X8pEDJXeehkjAEe7mFUHu6VNhPGfiBt7p01kpgV/GZOpAt2Ytx7P9vnm49PF50z4
# r7h50VvbJdoS/cvinnXVpz0gxAhvK3AFcsCT4QlXCKdNETGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABz1I2vnFLzUjKAAEA
# AAHPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIGsZTf47kaGocP5w+KCQD3V0XQQFe3+aavuaqahD
# 4XOEMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgs+mwup41Lg25hcTZUmUy
# 69B5ZUDzRkMWGk4+NLOE9r8wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAc9SNr5xS81IygABAAABzzAiBCDZKOKzpZH6rxkzwCpc1gEl
# H21sse0maAS/+ZdIm3FVyzANBgkqhkiG9w0BAQsFAASCAgB/NHltRM+ESQkwe4nQ
# SQruqnkQVwr+nOWRmPg8if30Ti5bddiYBkfobmOEFZEziex9PZERS3c1f88+J5Q/
# 3K5dZVOb2snc+Af5AuUJkoi+3gCoJSs7KPm2Eee+bc5JrNnVSwCkre0zbNxFIojk
# VntYmNhOb7e/Bxz3R0eZhc8jD1TeuvfbI/yMqU2JptuIe2WPgw24h6JJBzCjZIs1
# nu8rBfC5nusMN2/G45ufJUIbfnhaa4bJLz4JP4Syrl/gBuCZ1K1N9zVy1xqU43NP
# VrEMX50H2L4oJQ7IcU80zTugfN28XZS2U8/jL3evfMwxxQd7ljkQ6B3HRKZIa5u3
# rlsJCcDzlOTE+JOH/yZQ5eR/JyURVYHhx6oeLY4ihdT8rn08GM9zXyAS7uRM0MaC
# E4mTolM7SFq80koR8V2OHrKzmmOGsbFrsB3/S5gZ9eFygfcHZKe64w7P8UKjBvxP
# gdoKCN4sECr8CHIFOuHlU1RfbN1rXGeaq5sfTCL1BWQZfQYXzo+txjL2X0qxhhlG
# g1iuvMuN/RR5ajnFzFBmyfNOoo6OLmjoZPyKQnDuYmUos7RO3lOqwsnwzJdTkUNq
# vuNqSRUWOlQeFz/ePq4EXIiOf8LVqnTo3mjG5jmirS5I9P+dUUETzBYPgaZgP4OJ
# 4i2W3r94taugpmGqJwccOxtJ9A==
# SIG # End signature block
