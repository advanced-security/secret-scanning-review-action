# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubMilestoneTypeName = 'GitHub.Milestone'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

# For more information refer to:
#  https://github.community/t5/How-to-use-Git-and-GitHub/Milestone-quot-Due-On-quot-field-defaults-to-7-00-when-set-by-v3/m-p/6901
$script:minimumHoursToEnsureDesiredDateInPacificTime = 9

filter Get-GitHubMilestone
{
<#
    .SYNOPSIS
        Get the milestones for a given GitHub repository.

    .DESCRIPTION
        Get the milestones for a given GitHub repository.

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

    .PARAMETER Milestone
        The number of a specific milestone to get. If not supplied, will return back all milestones
        for this repository.

    .PARAMETER Sort
        How to sort the results.

    .PARAMETER Direction
        How to list the results. Ignored without the sort parameter.

    .PARAMETER State
        Only milestones with this state are returned.

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
        GitHub.Milestone

    .EXAMPLE
        Get-GitHubMilestone -OwnerName microsoft -RepositoryName PowerShellForGitHub
        Get the milestones for the microsoft\PowerShellForGitHub project.

    .EXAMPLE
        Get-GitHubMilestone -Uri 'https://github.com/PowerShell/PowerShellForGitHub' -Milestone 1
        Get milestone number 1 for the microsoft\PowerShellForGitHub project.
#>
    [CmdletBinding(DefaultParameterSetName = 'RepositoryElements')]
    param(
        [Parameter(
            Mandatory,
            ParameterSetName='MilestoneElements')]
        [Parameter(
            Mandatory,
            ParameterSetName='RepositoryElements')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ParameterSetName='MilestoneElements')]
        [Parameter(
            Mandatory,
            ParameterSetName='RepositoryElements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='MilestoneUri')]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='RepositoryUri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName='MilestoneUri')]
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            ParameterSetName='MilestoneElements')]
        [Alias('MilestoneNumber')]
        [int64] $Milestone,

        [Parameter(ParameterSetName='RepositoryUri')]
        [Parameter(ParameterSetName='RepositoryElements')]
        [ValidateSet('Open', 'Closed', 'All')]
        [string] $State,

        [Parameter(ParameterSetName='RepositoryUri')]
        [Parameter(ParameterSetName='RepositoryElements')]
        [ValidateSet('DueOn', 'Completeness')]
        [string] $Sort,

        [Parameter(ParameterSetName='RepositoryUri')]
        [Parameter(ParameterSetName='RepositoryElements')]
        [ValidateSet('Ascending', 'Descending')]
        [string] $Direction,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName
    $uriFragment = [String]::Empty
    $description = [String]::Empty

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
        'ProvidedMilestone' = $PSBoundParameters.ContainsKey('Milestone')
    }

    if ($PSBoundParameters.ContainsKey('Milestone'))
    {
        $uriFragment = "repos/$OwnerName/$RepositoryName/milestones/$Milestone"
        $description = "Getting milestone $Milestone for $RepositoryName"
    }
    else
    {
        $getParams = @()

        if ($PSBoundParameters.ContainsKey('Sort'))
        {
            $sortConverter = @{
                'Completeness' = 'completeness'
                'DueOn' = 'due_on'
            }

            $getParams += "sort=$($sortConverter[$Sort])"

            # We only look at this parameter if the user provided Sort as well.
            if ($PSBoundParameters.ContainsKey('Direction'))
            {
                $directionConverter = @{
                    'Ascending' = 'asc'
                    'Descending' = 'desc'
                }

                $getParams += "direction=$($directionConverter[$Direction])"
            }
        }

        if ($PSBoundParameters.ContainsKey('State'))
        {
            $State = $State.ToLower()
            $getParams += "state=$State"
        }

        $uriFragment = "repos/$OwnerName/$RepositoryName/milestones`?" +  ($getParams -join '&')
        $description = "Getting milestones for $RepositoryName"
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $description
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubMilestoneAdditionalProperties)
}

filter New-GitHubMilestone
{
<#
    .SYNOPSIS
        Creates a new GitHub milestone for the given repository.

    .DESCRIPTION
        Creates a new GitHub milestone for the given repository.

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
        The title of the milestone.

    .PARAMETER State
        The state of the milestone.

    .PARAMETER Description
        A description of the milestone.

    .PARAMETER DueOn
        The milestone due date.
        GitHub will drop any time provided with this value, therefore please ensure that the
        UTC version of this value has your desired date.

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
        GitHub.Milestone

    .EXAMPLE
        New-GitHubMilestone -OwnerName microsoft -RepositoryName PowerShellForGitHub -Title "Testing this API"

        Creates a new GitHub milestone for the microsoft\PowerShellForGitHub project.

    .NOTES
        For more information on how GitHub handles the dates specified in DueOn, please refer to
        this support forum post:
        https://github.community/t5/How-to-use-Git-and-GitHub/Milestone-quot-Due-On-quot-field-defaults-to-7-00-when-set-by-v3/m-p/6901

        Please note that due to artifacts of how GitHub was originally designed, all timestamps
        in the GitHub database are normalized to Pacific Time.  This means that any dates specified
        that occur before 7am UTC will be considered timestamps for the _previous_ day.

        Given that GitHub drops the _time_ aspect of this DateTime, this function will ensure that
        the requested DueOn date specified is honored by manipulating the time as needed.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    param(
        [Parameter(
            Mandatory,
            ParameterSetName='Elements')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ParameterSetName='Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ParameterSetName='Uri')]
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ParameterSetName='Elements')]
        [string] $Title,

        [ValidateSet('Open', 'Closed')]
        [string] $State,

        [string] $Description,

        [DateTime] $DueOn,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
        'Title' =  (Get-PiiSafeString -PlainText $Title)
    }

    $hashBody = @{
        'title' = $Title
    }

    if ($PSBoundParameters.ContainsKey('State'))
    {
        $State = $State.ToLower()
        $hashBody.add('state', $State)
    }

    if ($PSBoundParameters.ContainsKey('Description'))
    {
        $hashBody.add('description', $Description)
    }

    if ($PSBoundParameters.ContainsKey('DueOn'))
    {
        # If you set 'due_on' to be '2020-09-24T06:59:00Z', GitHub considers that to be '2020-09-23T07:00:00Z'
        # And if you set 'due_on' to be '2020-09-24T07:01:00Z', GitHub considers that to be '2020-09-24T07:00:00Z'
        # SO....we can't depend on the typical definition of midnight when trying to specify a specific day.
        # Instead, we'll use 9am on the designated date to ensure we're always dealing with the
        # same date that GitHub uses, regardless of the current state of Daylight Savings Time.
        # (See .NOTES for more info)
        $modifiedDueOn = $DueOn.ToUniversalTime().date.AddHours($script:minimumHoursToEnsureDesiredDateInPacificTime)
        $dueOnFormattedTime = $modifiedDueOn.ToString('o')
        $hashBody.add('due_on', $dueOnFormattedTime)
    }

    if (-not $PSCmdlet.ShouldProcess($Title, 'Create GitHub Milestone'))
    {
        return
    }

    $params = @{
        'UriFragment' = "repos/$OwnerName/$RepositoryName/milestones"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Post'
        'Description' = "Creating milestone for $RepositoryName"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethod @params | Add-GitHubMilestoneAdditionalProperties)
}

filter Set-GitHubMilestone
{
<#
    .SYNOPSIS
        Update an existing milestone for the given repository.

    .DESCRIPTION
        Update an existing milestone for the given repository.

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

    .PARAMETER Milestone
        The number of a specific milestone to get.

    .PARAMETER Title
        The title of the milestone.

    .PARAMETER State
        The state of the milestone.

    .PARAMETER Description
        A description of the milestone.

    .PARAMETER DueOn
        The milestone due date.
        GitHub will drop any time provided with this value, therefore please ensure that the
        UTC version of this value has your desired date.

    .PARAMETER PassThru
        Returns the updated Milestone.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

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
        GitHub.Milestone

    .EXAMPLE
        Set-GitHubMilestone -OwnerName microsoft -RepositoryName PowerShellForGitHub -Milestone 1 -Title "Testing this API"

        Update an existing milestone for the microsoft\PowerShellForGitHub project.

    .NOTES
        For more information on how GitHub handles the dates specified in DueOn, please refer to
        this support forum post:
        https://github.community/t5/How-to-use-Git-and-GitHub/Milestone-quot-Due-On-quot-field-defaults-to-7-00-when-set-by-v3/m-p/6901

        Please note that due to artifacts of how GitHub was originally designed, all timestamps
        in the GitHub database are normalized to Pacific Time.  This means that any dates specified
        that occur before 7am UTC will be considered timestamps for the _previous_ day.

        Given that GitHub drops the _time_ aspect of this DateTime, this function will ensure that
        the requested DueOn date specified is honored by manipulating the time as needed.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    param(
        [Parameter(
            Mandatory,
            ParameterSetName='Elements')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ParameterSetName='Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Elements')]
        [Alias('MilestoneNumber')]
        [int64] $Milestone,

        [Parameter(
            Mandatory,
            ParameterSetName='Uri')]
        [Parameter(
            Mandatory,
            ParameterSetName='Elements')]
        [string] $Title,

        [ValidateSet('Open', 'Closed')]
        [string] $State,

        [string] $Description,

        [DateTime] $DueOn,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
        'Title' =  (Get-PiiSafeString -PlainText $Title)
        'Milestone' =  (Get-PiiSafeString -PlainText $Milestone)
    }

    $hashBody = @{
        'title' = $Title
    }

    if ($PSBoundParameters.ContainsKey('State'))
    {
        $State = $State.ToLower()
        $hashBody.add('state', $State)
    }

    if ($PSBoundParameters.ContainsKey('Description'))
    {
        $hashBody.add('description', $Description)
    }

    if ($PSBoundParameters.ContainsKey('DueOn'))
    {
        # If you set 'due_on' to be '2020-09-24T06:59:00Z', GitHub considers that to be '2020-09-23T07:00:00Z'
        # And if you set 'due_on' to be '2020-09-24T07:01:00Z', GitHub considers that to be '2020-09-24T07:00:00Z'
        # SO....we can't depend on the typical definition of midnight when trying to specify a specific day.
        # Instead, we'll use 9am on the designated date to ensure we're always dealing with the
        # same date that GitHub uses, regardless of the current state of Daylight Savings Time.
        # (See .NOTES for more info)
        $modifiedDueOn = $DueOn.ToUniversalTime().date.AddHours($script:minimumHoursToEnsureDesiredDateInPacificTime)
        $dueOnFormattedTime = $modifiedDueOn.ToString('o')
        $hashBody.add('due_on', $dueOnFormattedTime)
    }

    if (-not $PSCmdlet.ShouldProcess($Milestone, 'Set GitHub Milestone'))
    {
        return
    }

    $params = @{
        'UriFragment' = "repos/$OwnerName/$RepositoryName/milestones/$Milestone"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Patch'
        'Description' = "Setting milestone $Milestone for $RepositoryName"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubMilestoneAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Remove-GitHubMilestone
{
<#
    .SYNOPSIS
        Deletes a GitHub milestone for the given repository.

    .DESCRIPTION
        Deletes a GitHub milestone for the given repository.

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

    .PARAMETER Milestone
        The number of a specific milestone to delete.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

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

    .EXAMPLE
        Remove-GitHubMilestone -OwnerName microsoft -RepositoryName PowerShellForGitHub -Milestone 1

        Deletes a GitHub milestone from the microsoft\PowerShellForGitHub project.

    .EXAMPLE
        Remove-GitHubMilestone -OwnerName microsoft -RepositoryName PowerShellForGitHub -Milestone 1 -Confirm:$false

        Deletes a Github milestone from the microsoft\PowerShellForGitHub project. Will not prompt
        for confirmation, as -Confirm:$false was specified.

    .EXAMPLE
        Remove-GitHubMilestone -OwnerName microsoft -RepositoryName PowerShellForGitHub -Milestone 1 -Force

        Deletes a Github milestone from the microsoft\PowerShellForGitHub project. Will not prompt
        for confirmation, as -Force was specified.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements',
        ConfirmImpact="High")]
    [Alias('Delete-GitHubMilestone')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
    param(
        [Parameter(
            Mandatory,
            ParameterSetName='Elements')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ParameterSetName='Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Elements')]
        [Alias('MilestoneNumber')]
        [int64] $Milestone,

        [switch] $Force,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
        'Milestone' =  (Get-PiiSafeString -PlainText $Milestone)
    }

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Milestone, 'Remove GitHub Milestone'))
    {
        return
    }

    $params = @{
        'UriFragment' = "repos/$OwnerName/$RepositoryName/milestones/$Milestone"
        'Method' = 'Delete'
        'Description' = "Removing milestone $Milestone for $RepositoryName"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Add-GitHubMilestoneAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Milestone objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Milestone
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
        [string] $TypeName = $script:GitHubMilestoneTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $elements = Split-GitHubUri -Uri $item.html_url
            $repositoryUrl = Join-GitHubUri @elements
            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'MilestoneId' -Value $item.id -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'MilestoneNumber' -Value $item.number -MemberType NoteProperty -Force

            if ($null -ne $item.creator)
            {
                $null = Add-GitHubUserAdditionalProperties -InputObject $item.creator
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLgYJKoZIhvcNAQcCoIIoHzCCKBsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBUBMZi62EgrVXF
# HPVTIL74zODUkVV+FU6DSzez7dJIhKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIF/ZmSKj4Z4pCGWTeNwEnJgc
# zJH1RJZrHuVJOy29SKuqMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQDa49xd00cNX/Bv10Fd0EA4cXh7mCU34f3ORXtLTGzJyWo+OSZarmwS
# ZrdQehOHX5ISTxy1KzOF493c9AyHHlZQYLFDBLlgwV2y4OloWsYwRp2Bu9fzdDyA
# Kq39G/nMlcjVplZ7UQeL4W+cD08VyihdR8DmZ49k23sYBh7qvxvpc78lHHh+rbNJ
# pl742zd1EDforSzDBm3I8zAVSYcqlDsIupnoEMIog/gYXTVKW/e8eqXRDy967WJN
# XbuyXx71Bg8hXmgajYak9ucVStP4ztJ+CIZP6j4lxyWf7UHAOX3LzUAkMppeEqd4
# K+dSjd3xf6wj99D3eDbp63EfmckZY09foYIXljCCF5IGCisGAQQBgjcDAwExgheC
# MIIXfgYJKoZIhvcNAQcCoIIXbzCCF2sCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIM0/rS/4QAV9wjfTlp9RB+C2LCJgGAoWjw7TOSrRxZRPAgZlVsdo
# IOMYEzIwMjMxMTIxMTczNTM4LjkyMlowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpEQzAw
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEewwggcgMIIFCKADAgECAhMzAAAB0iEkMUpYvy0RAAEAAAHSMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIyMVoXDTI0MDIwMTE5MTIyMVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpEQzAwLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBANxgiELRAj9I9pPn6dhIGxJ2EE87ZJczjRXLKDwW
# rVM+sw0PPEKHFZQPt9srBgZKw42C2ONV53kdKHmKXvmM1pxvpOtnC5f5Db75/b/w
# ILK7xNjSvEQicPdOPnZtbPlBFZVB6N90ID+fpnOKeFxlnv5V6VaBN9gLusOuFfdM
# Ffz16WpeYhI5UhZ5eJEryH2EfpJeCOFAYZBt/ZtIzu4aQrMn+lnYu+VPOr6Y5b2I
# /aNxgQDhuk966umCUtVRKcYZAuaNCntJ3LXATnZaM8p0ucEXoluZJEQz8OP1nuiT
# FE1SNhJ2DK9nUtZKKWFX/B6BhdVDo/0wqNGcTwIjkowearsSweEgErQH310VDJ0v
# W924Lt5YSPPPnln8PIfoeXZI85/kpniUd/oxTC2Bp/4x5nGRbSLGH+8vWZfxWwlM
# drwAf7SX/12dbMUwUUkUbuD3mccnoyZg+t+ah4o5GjIRBGxK6zaoKukyOD8/dn1Y
# kC0UahdgwPX02vMbhQU+lVuXc3Ve8bj+6V2jX5qcGkNiHFBTuTWB8efpDF1RTROy
# sn8kK8t99Lz1vhVeUhrGdUXpBmH4nvEtQ0a0SaPp3A/OgJ8vvOoNkm+ay9g2TWVx
# vJXEwiAMU+gDZ9k9ccXt3FqEzZkbsAC3e9kSIy0LoT9yItFwjDOUmsGIcR6cg+/F
# bXmrAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUILaftydHdOg/+RsRnZckUWZnWSQw
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBALDmKrQTLQuUB3PY9ypyFHBbl35+K00h
# IK+oPQTpb8DKJOT5MzdaFhNrFDak/o6vio5X4O7v8v6TXyBivWmGyHFUxWdc1x2N
# 5wy1NZQ5UDBsmh5YdoCCSc0gzNcrf7OC4blNVwsSH8JUzLUnso8TxDQLPno2BbN3
# 26sb6yFIMqQp2E5g9cX3vQyvUYIUWl7WheMTLppL4d5q+nbCbLrmZu7QBxQ48Sf6
# FiqKOAtdI+q+4WY46jlSdJXroO/kV2SorurkNF6jH1E8RlwdRr7YFQo+On51DcPh
# z0gfzvbsqMwPw5dmiYP0Dwyv99wOfkUjuV9lzyCFhzuylgpM7/Rn1hFFqaFVbHGs
# iwE3kutaH7Xyyhcn74R5KPNJh2AZZg+DXqEv/sDJ3HgrP9YFNSZsaKJVRwT8jRpB
# TZT/Q3NSIgUhbzRK/F4Nafoj6HJWD+x0VIAs/klPvAB7zNO+ysjaEykRUt1K0UAy
# pqcViq3BlTkWgCyg9nuHUSVaYotmReTx4+4AvO01jXKx47RPB254gZwjAi2uUFiD
# Vek/PX6kyEYxVuV7ooe6doqjkr+V04zSZBBPhWODplvNEhVGgNwCtDn//TzvmM5S
# 8m1jJzseXTiNya+MQhcLceORRi+AcRYvRAX/h/u8sByFoRnzf3/cZg52oflVWdmt
# QgFAHoNNpQgsMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# A08wggI3AgEBMIH5oYHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046REMwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# AImm0sJmwTTo22YdDMHkXVOugVIGoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpBzSNMCIYDzIwMjMxMTIxMTM1
# MjEzWhgPMjAyMzExMjIxMzUyMTNaMHYwPAYKKwYBBAGEWQoEATEuMCwwCgIFAOkH
# NI0CAQAwCQIBAAIBFwIB/zAHAgEAAgITGjAKAgUA6QiGDQIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBCwUAA4IBAQAhsSEigtTmjFCr0ODFk1qtpckDUv/8qDvZhQqTqo+L
# wdbORSgpwKtIEkEpanSLaeDJKUf268/T60d0JPI1DK7jHjWvbbtA3hnSVhVMnk3r
# g8c4M5k4jF0Vfkll/IFJ8MKkacA8fvdowFE/u/CQtnIMuNnQ/mqAjWWqw0teOWIR
# jjQQx/dCOeI6qr0XzIvPTRye4QtH5YClm4vfTcAaOFoS/XtaraEDSesf9FlcaUVC
# QTlW4oU5Gvv2V6YZ0enSRIbT/DB+MhH3dWYUywK2OwIFpAU8VXmIX7UkDjFoWUju
# URDPx4jCWqaFkEktgFiQaluBZL+x2HJiLy9s+KJYlKTlMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHSISQxSli/LREAAQAA
# AdIwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQggfx+0BMadYRt6IZjFL+9PM+xY4Q7CPD2FZ+10xZg
# 1ZQwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDHgCCT399IvWWzhMVOeexs
# FjWix9GebOuSRYGtg3mkTjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAAB0iEkMUpYvy0RAAEAAAHSMCIEIN08OhlwXB7q3CnXy53bav5W
# sXN0Eag7tEG2XNn73qTOMA0GCSqGSIb3DQEBCwUABIICAG7AftxOeRqKXflA6DXB
# 6Gd3qjbFIppQ9jGFxyZUwd7/kP22Yfzhae5pLoK1e8DM1Wf1bnWbHIhu8sQ38vTL
# /A4rAkZ88ar8tkp59XX77+WzgY4QC8EVE/o/4vIx4GVKSAB5rmzPum38E5gSt/xR
# 3ro/JAPih5KUvbH2KTT2DSM027NFr/WKuU+Zg1k2GuidXgMq2B+j+cKAtIjR2kfL
# r7Po0cGdlbNtMHcyWQHP4odgUbBD1b85o6kcVlT0hr57+6WrX9BC2xEoia/o2wRN
# famnc0Cj+tyREKDEyXwid8USrQAu2FYHKpf12Or3vtPuIKiFTjWKR7cx+7FrkEk3
# z0YgJWmB9yeTP/7A0FrANEhcez+1Ye0pn4L8rRX5wldCeNVmOHLLzq3NtGpPJTG3
# f4po8kKEQ+m1Z8R7sjNGk6gr7FfOXVOHX19QiLwAJSQfNPi/mG2KBoFIGcZhJsjk
# duQzHUfKRj8yeZtV2XqqtdqBvzM3Sktu208ByK2/EHzF0zZSa/7UOxEK+hhAVhMT
# AkNwO3DXoS3+2bdq5kUmgncH8Sdp0FK4F7Jpz4/XSd6H8xSvfgU7P+Kz885RwRKM
# 700J2di1wgy7upK0L16pzDIJwIJWYPH9iEkJOVX5AY17GTLNsKxLPhVpq70JnolT
# eCiEevdQbIQ9+ix6Txas587H
# SIG # End signature block
