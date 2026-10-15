# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubProjectCardTypeName = 'GitHub.ProjectCard'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubProjectCard
{
<#
    .SYNOPSIS
        Get the cards for a given GitHub Project Column.

    .DESCRIPTION
        Get the cards for a given GitHub Project Column.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Column
        ID of the column to retrieve cards for.

    .PARAMETER State
        Only cards with this State are returned.
        Options are all, archived, or NotArchived (default).

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.ProjectCard
        GitHub.ProjectColumn

    .OUTPUTS
        GitHub.ProjectCard

    .EXAMPLE
        Get-GitHubProjectCard -Column 999999

        Get the the not_archived cards for column 999999.

    .EXAMPLE
        Get-GitHubProjectCard -Column 999999 -State All

        Gets all the cards for column 999999, no matter the State.

    .EXAMPLE
        Get-GitHubProjectCard -Column 999999 -State Archived

        Gets the archived cards for column 999999.

    .EXAMPLE
        Get-GitHubProjectCard -Card 999999

        Gets the card with ID 999999.
#>
    [CmdletBinding(DefaultParameterSetName = 'Card')]
    [OutputType({$script:GitHubProjectCardTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Column')]
        [Alias('ColumnId')]
        [int64] $Column,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Card')]
        [Alias('CardId')]
        [int64] $Card,

        [ValidateSet('All', 'Archived', 'NotArchived')]
        [Alias('ArchivedState')]
        [string] $State = 'NotArchived',

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = [String]::Empty
    $description = [String]::Empty

    if ($PSCmdlet.ParameterSetName -eq 'Column')
    {
        $telemetryProperties['Column'] = $true

        $uriFragment = "/projects/columns/$Column/cards"
        $description = "Getting cards for column $Column"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Card')
    {
        $telemetryProperties['Card'] = $true

        $uriFragment = "/projects/columns/cards/$Card"
        $description = "Getting project card $Card"
    }

    if ($PSBoundParameters.ContainsKey('State'))
    {
        $getParams = @()
        $Archived = $State.ToLower().Replace('notarchived','not_archived')
        $getParams += "archived_state=$Archived"

        $uriFragment = "$uriFragment`?" + ($getParams -join '&')
        $description += " with State '$Archived'"
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $description
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubProjectCardAdditionalProperties)
}

filter New-GitHubProjectCard
{
<#
    .SYNOPSIS
        Creates a new card for a GitHub project.

    .DESCRIPTION
        Creates a new card for a GitHub project.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Column
        ID of the column to create a card for.

    .PARAMETER Note
        The name of the column to create.

    .PARAMETER IssueId
        The ID of the issue you want to associate with this card (not to be confused with
        the Issue _number_ which you see in the URL and can refer to with a hashtag).

    .PARAMETER PullRequestId
        The ID of the pull request you want to associate with this card (not to be confused with
        the Pull Request _number_ which you see in the URL and can refer to with a hashtag).

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.IssueComment
        GitHub.Issue
        GitHub.PullRequest
        GitHub.ProjectCard
        GitHub.ProjectColumn

    .OUTPUTS
        GitHub.ProjectCard

    .EXAMPLE
        New-GitHubProjectCard -Column 999999 -Note 'Note on card'

        Creates a card on column 999999 with the note 'Note on card'.

    .EXAMPLE
        New-GitHubProjectCard -Column 999999 -IssueId 888888

        Creates a card on column 999999 for the issue with ID 888888.

    .EXAMPLE
        New-GitHubProjectCard -Column 999999 -PullRequestId 888888

        Creates a card on column 999999 for the pull request with ID 888888.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'Note')]
    [OutputType({$script:GitHubProjectCardTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('ColumnId')]
        [int64] $Column,

        [Parameter(
            Mandatory,
            ParameterSetName = 'Note')]
        [Alias('Content')]
        [string] $Note,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Issue')]
        [int64] $IssueId,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'PullRequest')]
        [int64] $PullRequestId,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = "/projects/columns/$Column/cards"
    $apiDescription = "Creating project card"

    if ($PSCmdlet.ParameterSetName -eq 'Note')
    {
        $telemetryProperties['Note'] = $true

        $hashBody = @{
            'note' = $Note
        }
    }
    elseif ($PSCmdlet.ParameterSetName -in ('Issue', 'PullRequest'))
    {
        $contentType = $PSCmdlet.ParameterSetName
        $telemetryProperties['ContentType'] = $contentType

        $hashBody = @{
            'content_type' = $contentType
        }

        if ($PSCmdlet.ParameterSetName -eq 'Issue')
        {
            $hashBody['content_id'] = $IssueId
        }
        else
        {
            $hashBody['content_id'] = $PullRequestId
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Column, 'Create GitHub Project Card'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Post'
        'Description' = $apiDescription
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    return (Invoke-GHRestMethod @params | Add-GitHubProjectCardAdditionalProperties)
}

filter Set-GitHubProjectCard
{
<#
    .SYNOPSIS
        Modify a GitHub Project Card.

    .DESCRIPTION
        Modify a GitHub Project Card.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Card
        ID of the card to modify.

    .PARAMETER Note
        The note content for the card.  Only valid for cards without another type of content,
        so this cannot be specified if the card already has a content_id and content_type.

    .PARAMETER Archive
        Archive a project card.

    .PARAMETER Restore
        Restore a project card.

    .PARAMETER PassThru
        Returns the updated Project Card.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.ProjectCard

    .OUTPUTS
        GitHub.ProjectCard

    .EXAMPLE
        Set-GitHubProjectCard -Card 999999 -Note UpdatedNote

        Sets the card note to 'UpdatedNote' for the card with ID 999999.

    .EXAMPLE
        Set-GitHubProjectCard -Card 999999 -Archive

        Archives the card with ID 999999.

    .EXAMPLE
        Set-GitHubProjectCard -Card 999999 -Restore

        Restores the card with ID 999999.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'Note')]
    [OutputType({$script:GitHubProjectCardTypeName})]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('CardId')]
        [int64] $Card,

        [Alias('Content')]
        [string] $Note,

        [Parameter(ParameterSetName = 'Archive')]
        [switch] $Archive,

        [Parameter(ParameterSetName = 'Restore')]
        [switch] $Restore,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = "/projects/columns/cards/$Card"
    $apiDescription = "Updating card $Card"

    $hashBody = @{}

    if ($PSBoundParameters.ContainsKey('Note'))
    {
        $telemetryProperties['Note'] = $true
        $hashBody.add('note', $Note)
    }

    if ($Archive)
    {
        $telemetryProperties['Archive'] = $true
        $hashBody.add('archived', $true)
    }

    if ($Restore)
    {
        $telemetryProperties['Restore'] = $true
        $hashBody.add('archived', $false)
    }

    if (-not $PSCmdlet.ShouldProcess($Card, 'Set GitHub Project Card'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $apiDescription
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'AccessToken' = $AccessToken
        'Method' = 'Patch'
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubProjectCardAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Remove-GitHubProjectCard
{
<#
    .SYNOPSIS
        Removes a project card.

    .DESCRIPTION
        Removes a project card.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Card
        ID of the card to remove.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.ProjectCard

    .EXAMPLE
        Remove-GitHubProjectCard -Card 999999

        Remove project card with ID 999999.

    .EXAMPLE
        Remove-GitHubProjectCard -Card 999999 -Confirm:$False

        Remove project card with ID 999999 without prompting for confirmation.

    .EXAMPLE
        Remove-GitHubProjectCard -Card 999999 -Force

        Remove project card with ID 999999 without prompting for confirmation.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'High')]
    [Alias('Delete-GitHubProjectCard')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('CardId')]
        [int64] $Card,

        [switch] $Force,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = "/projects/columns/cards/$Card"
    $description = "Deleting card $Card"

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Card, 'Remove GitHub Project Card'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $description
        'AccessToken' = $AccessToken
        'Method' = 'Delete'
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    return Invoke-GHRestMethod @params
}

filter Move-GitHubProjectCard
{
<#
    .SYNOPSIS
        Move a GitHub Project Card.

    .DESCRIPTION
        Move a GitHub Project Card.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER Card
        ID of the card to move.

    .PARAMETER Top
        Moves the card to the top of the column.

    .PARAMETER Bottom
        Moves the card to the bottom of the column.

    .PARAMETER After
        Moves the card to the position after the card ID specified.

    .PARAMETER Column
        The ID of a column in the same project to move the card to.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.ProjectCard
        GitHub.ProjectColumn

    .EXAMPLE
        Move-GitHubProjectCard -Card 999999 -Top

        Moves the project card with ID 999999 to the top of the column.

    .EXAMPLE
        Move-GitHubProjectCard -Card 999999 -Bottom

        Moves the project card with ID 999999 to the bottom of the column.

    .EXAMPLE
        Move-GitHubProjectCard -Card 999999 -After 888888

        Moves the project card with ID 999999 to the position after the card ID 888888.
        Within the same column.

    .EXAMPLE
        Move-GitHubProjectCard -Card 999999 -After 888888 -Column 123456

        Moves the project card with ID 999999 to the position after the card ID 888888, in
        the column with ID 123456.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('CardId')]
        [int64] $Card,

        [switch] $Top,

        [switch] $Bottom,

        [int64] $After,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('ColumnId')]
        [int64] $Column,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = "/projects/columns/cards/$Card/moves"
    $apiDescription = "Updating card $Card"

    if (-not ($Top -xor $Bottom -xor ($After -gt 0)))
    {
        $message = 'You must use one (and only one) of the parameters Top, Bottom or After.'
        Write-Log -Message $message -level Error
        throw $message
    }
    elseif ($Top)
    {
        $position = 'top'
    }
    elseif ($Bottom)
    {
        $position = 'bottom'
    }
    else
    {
        $position = "after:$After"
    }

    $hashBody = @{
        'position' = $Position
    }

    if ($PSBoundParameters.ContainsKey('Column'))
    {
        $telemetryProperties['Column'] = $true
        $hashBody.add('column_id', $Column)
    }

    if (-not $PSCmdlet.ShouldProcess($Card, 'Move GitHub Project Card'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $apiDescription
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'AccessToken' = $AccessToken
        'Method' = 'Post'
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
        'AcceptHeader' = $script:inertiaAcceptHeader
    }

    return Invoke-GHRestMethod @params
}


filter Add-GitHubProjectCardAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Project Card objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.ProjectCard
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
        [string] $TypeName = $script:GitHubProjectCardTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            Add-Member -InputObject $item -Name 'CardId' -Value $item.id -MemberType NoteProperty -Force

            if ($item.project_url -match '^.*/projects/(\d+)$')
            {
                $projectId = $Matches[1]
                Add-Member -InputObject $item -Name 'ProjectId' -Value $projectId -MemberType NoteProperty -Force
            }

            if ($item.column_url -match '^.*/columns/(\d+)$')
            {
                $columnId = $Matches[1]
                Add-Member -InputObject $item -Name 'ColumnId' -Value $columnId -MemberType NoteProperty -Force
            }

            if ($null -ne $item.content_url)
            {
                $elements = Split-GitHubUri -Uri $item.content_url
                $repositoryUrl = Join-GitHubUri @elements
                Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force

                if ($item.content_url -match '^.*/issues/(\d+)$')
                {
                    $issueNumber = $Matches[1]
                    Add-Member -InputObject $item -Name 'IssueNumber' -Value $issueNumber -MemberType NoteProperty -Force
                }
                elseif ($item.content_url -match '^.*/pull/(\d+)$')
                {
                    $pullRequestNumber = $Matches[1]
                    Add-Member -InputObject $item -Name 'PullRequestNumber' -Value $pullRequestNumber -MemberType NoteProperty -Force
                }
            }

            if ($null -ne $item.creator)
            {
                $null = Add-GitHubUserAdditionalProperties -InputObject $item.creator
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCK+cg24/Q2MaD7
# eJeXWJhFQCmQpOphE2kG20e/dz0ftKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAMa5ciZtb5URpPpO8A9DG9H
# e82LnIic2GOzXviyhwzNMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB+wf9/tNcVpC3FNND6ZqrIqHVu3Qlfzj7BQas2gtcHualANNTKI+vR
# erHmb5MksPvKHL4K+Rx3XK2jtXc4NErxuTk5JH1KjqxGi8iFZzIWB64fDfZEh80Y
# NJY9sGSFDa8AzAWK6OdSis3BPJAv9xk1vf7oj0nAFwrFMiFEcb461ZpSBOHRTdwz
# GWlIjQY1D7cBtx8kgjIRu9qKGFph2QfO0PpTO21t0/q/+u7iT1DYkAfTt8nWrkfq
# uHJO7P1qNiTcns3xcmKwwghGBuDu3bv0Sl0wPGzIC24admoBmzEhHwc+Rztqn1H/
# w6DGCJX2DFAvq1Kz7hSI90FmjOWYtCWyoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJik80o2ADKO9bSE7Kx1ZhADmB0n89CZqSKJaomyTFodAgZlVsam
# G98YEzIwMjMxMTIxMTczNTQ1LjAwNVowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBOTM1
# LTAzRTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAAB0bJbQChsLtJFAAEAAAHRMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIxOFoXDTI0MDIwMTE5MTIxOFowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBOTM1LTAzRTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAJlM2jQ54bPZcV3aAuDmdOUGbxc6m7AkiJewxTrW
# vCrVkoOlrjjdGtIb+kfwbPpc2cVAoacKo0K2a+gpQsCnCtP+zv97VfSU0UqaPtTt
# finTRLS5BtbovBKf/NYdobZznhlewZj4Fh+FYOBsWkJPFHNOdEIbrZuRY+npkdtk
# +Dge3UJEIAyGE4ZNHzAjgbvDBZnB0xzpS9RSWrSqX0DEB/ORhGmLa1G8Mcx2Zne/
# JemqEXC9EbxyAIf9NMKNbmrpo1t2oovcEUM/NS24I2w9cvf8TR1HZsMyprRo0f6I
# h+EYLj+9zC6144wI9QgNVKoMI18ho8MTBhyLV932C7XNXD4cSENkzsRrefEhSvO3
# 5F+nlOgwyPhACYnpRp2b5M9sNujyQUgrvRKGZbzCfx8mT1F5BASlO0g3jd5G/1CZ
# fLdR53zSiw4ET5aR0y9IIWH6qAKwp3NDFAkbrZxN6hTZ6o2EfeimlebJ9VTBux59
# DMw+1uKcJl3QVSWaUz90f7g6eKpDJoe+u1jLfCohp9jfN4UhOVUCg/2r28Xhbsod
# H+4XSa9OkAvk1pMM3WmVBLQx2MySDNkrmC3Co57/etOWoHPHBrthine6s/nJaRPM
# hIaeE1Yhk7E7JAg7Fl9uIhsAdubczyGPvcpBZwJHklq+CTBSadwUcRJpB/gOuqz7
# /UvVAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUC47xTMXsNwfSaawXhdDHEdC9LaMw
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAJu72tMAdXbiZjSqgbl4ScibPlqQZdO+
# IHAqnZjnWzbrDygOtaiv6bTRHj/cFwOZiVQrw2vH9q5gViJ1l11xSPDjZDFJK2a/
# +pacJCL/Y6cffYpUdD6Qw5k8AFBMbVeRydg9Q44QSivp//cmzW6PjCMfMThXhq6Z
# hcECyvgvkpHy8p6zm0XGEyRY0P87tb9FodjAkyMyTFWiwGiTtXbWwkCXFJwRfF8l
# r7+qSpSvsJmDDdHiMIdGQ+pCExaJtc8xhqv+IXRm4sH07z0Mwk2GMr0FJ/qKqBmg
# y7MhW34QGhPOm//2njBDrGgEKzb2aSP8QhYV1z7lrfSS4JA5IQ6PTv5Yjb0DiTpA
# hEHnD54yZnQl5zSxLJ5AHkqPETnWJgyG2UytQpyvTqcGoKxIo9ixIAhMDOCywkP5
# n9xNLsK7fl8mtaEz01hfbi4DFgsBbSKk21am0h5XpqS5kR4RXoE20zdVOT6YCVXn
# 94L/RjXtpVKMrn+DIOgs2auBXC/lMBoGar/CBFEUeZb1QnfO/wuaTqYigDJOmoFu
# 5SMwvKu1qO5KwD+bYOcow7RCLPW/4VJVuozfwn89OWEJNRsU7HSQtPtj/v5nKuKV
# ULPIBh8UiKcMiNaUzzm0N5Txl8kKMUrCrcOxHFXgljXzHDDxNOah3eWSv02oZDng
# ubI9Vz7mJs2uMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTkzNS0wM0UwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# AEcljYW/4aEtC1ENHa8jMFpK//ssoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpBzOEMCIYDzIwMjMxMTIxMTM0
# NzQ4WhgPMjAyMzExMjIxMzQ3NDhaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOkH
# M4QCAQAwCgIBAAICD6oCAf8wBwIBAAICEs8wCgIFAOkIhQQCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEAFjHK3fZVutMYUBiQ8OGOK6bh2KkXmZ2nHwGGvnNJ
# 25nJ2zsFyiPf2vKs0Q6WeDMMyeF2GXwHFKl+8Q7yOjDNPEcOyexAhQ5FScEnfLS/
# Pm7o+9S48LyDoEFrEcG1e/KEqHCFPvxohtum/vd1xnik+0x9KDBF8YzUs6OaUw5R
# g0DwMuojS7HbaGN4JHc8s/hc7r8hSykrqGWIMRPObtmErIxcQwfjCGSmekO2br40
# /15WjMsH/hMsGDqb/BsFjH1/mBPx8H1vvy06obdyAErO3dx/hNkjrNDi569+44mH
# 4yztUxYXj6iOWYh8Cex7cnW2Jkh83sJiaxlkzFuW+JDH5zGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB0bJbQChsLtJFAAEA
# AAHRMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEICSFqT4h0Wlx2Hnrvr9To5SXonopCbzwhd8eFtbd
# 0e34MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgzLxheQIAu/ntzmxGGs9O
# 5vWrhPAnqhUDfqTwiIj8BwwwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAdGyW0AobC7SRQABAAAB0TAiBCDxxqKr+a7elc0aTX39rLT2
# aGWwquRdNma/zyFUhPxEfDANBgkqhkiG9w0BAQsFAASCAgCOvWk2CLamq8J9ZQIG
# 1aO71qQbCX2Oi6qe7FeQdzfV7mfeccgoIAUwdh0pBbjiuA3LWk0tLGKyw4LK9NeU
# Bup1I5Dt3fwydC8yKa+Vwld3XV8bLPE0hyKV8wlNytuRBDIvijx+BvOt4t6qMEKN
# O9op7Mc0V8Gku9VQrC+N5Kl3x/5tlix1dNzPlFWex3U6iTgkgFYb75stzooPGimF
# Gjoil7tfLsNPeDyYG+nqufDS4xAZKEvBVVXZefOSFcalRwNvUH3TT6r85WW7lywJ
# eij9Ed+HXKe7yNb6Vs2ne2FoOrCqjdbHfqXAgfPv3MKa/WR3caeIvWmqXw3KUJ+n
# ykUhQ756BN5iioh02dvxH6Ub0YEm8GU/k+73dLH7Zd7Obv50eCvjRMbjwyJ3Gw2E
# tennUSG5xn/yakPZotmoUVLPbMpiJ6+aAeVJZGiaSvHFlsikKIl8GQixdtVAjZsr
# syRja9IJyVz5qqEv/29X/KRrJBkJ0L1dY7wyq2OjkoD9sPwS7tmJJwX8ozQWC5aV
# 6Q34kgoBA47BVOMlpnLc6Azgph5C3uGURKNUVGW6W08Nfu12B2OUntHbR5S8B6TL
# QNmUTZVktNRYCUobY7yB3Bxxju83WclfuCjyqSm1BNUNO3WPB2nfqV08vLUMJ/a8
# V+ZDxRpGvBRUBVGB7JuKfpBVrA==
# SIG # End signature block
