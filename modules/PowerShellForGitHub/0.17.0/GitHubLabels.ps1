# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubLabelTypeName = 'GitHub.Label'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubLabel
{
<#
    .SYNOPSIS
        Retrieve label(s) of a given GitHub repository.

    .DESCRIPTION
        Retrieve label(s) of a given GitHub repository.

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

    .PARAMETER Label
        Name of the specific label to be retrieved.  If not supplied, all labels will be retrieved.
        Emoji and codes are supported.  For more information, see here: https://www.webpagefx.com/tools/emoji-cheat-sheet/

    .PARAMETER Issue
        If provided, will return all of the labels for this particular issue.

    .PARAMETER MilestoneNumber
        If provided, will return all of the labels assigned to issues for this particular milestone.

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
        GitHub.Label

    .EXAMPLE
        Get-GitHubLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub

        Gets the information for every label from the microsoft\PowerShellForGitHub project.

    .EXAMPLE
        Get-GitHubLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel

        Gets the information for the label named "TestLabel" from the microsoft\PowerShellForGitHub
        project.

    .NOTES
        There were a lot of complications with the ParameterSets with this function due to pipeline
        input.  For the time being, the ParameterSets have been simplified and the validation of
        parameter combinations is happening within the function itself.
#>
    [CmdletBinding(DefaultParameterSetName = 'NameUri')]
    [OutputType({$script:GitHubLabelTypeName})]
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

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('LabelName')]
        [string] $Label,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('IssueNumber')]
        [int64] $Issue,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int64] $MilestoneNumber,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
    }

    # There were a lot of complications trying to get pipelining working right when using all of
    # the necessary ParameterSets, so we'll do internal parameter validation instead until someone
    # can figure out the right way to do the parameter sets here _with_ pipeline support.
    if ($PSBoundParameters.ContainsKey('Label') -or
        $PSBoundParameters.ContainsKey('Issue') -or
        $PSBoundParameters.ContainsKey('MilestoneNumber'))
    {
        if (-not ($PSBoundParameters.ContainsKey('Label') -xor
            $PSBoundParameters.ContainsKey('Issue') -xor
            $PSBoundParameters.ContainsKey('MilestoneNumber')))
        {
            $message = 'Label, Issue and Milestone are mutually exclusive.  Only one can be specified in a single command.'
            Write-Log -Message $message -Level Error
            throw $message
        }
    }

    $uriFragment = [String]::Empty
    $description = [String]::Empty

    if ($PSBoundParameters.ContainsKey('Issue'))
    {
        $uriFragment = "/repos/$OwnerName/$RepositoryName/issues/$Issue/labels"
        $description = "Getting labels for Issue $Issue in $RepositoryName"
    }
    elseif ($PSBoundParameters.ContainsKey('MilestoneNumber'))
    {
        $uriFragment = "/repos/$OwnerName/$RepositoryName/milestones/$MilestoneNumber/labels"
        $description = "Getting labels for issues in Milestone $MilestoneNumber in $RepositoryName"
    }
    else
    {
        $uriFragment = "repos/$OwnerName/$RepositoryName/labels/$Label"

        if ($PSBoundParameters.ContainsKey('Name'))
        {
            $description = "Getting label $Label for $RepositoryName"
        }
        else
        {
            $description = "Getting labels for $RepositoryName"
        }
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Description' = $description
        'AcceptHeader' = $script:symmetraAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubLabelAdditionalProperties)
}

filter New-GitHubLabel
{
<#
    .SYNOPSIS
        Create a new label on a given GitHub repository.

    .DESCRIPTION
        Create a new label on a given GitHub repository.

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

    .PARAMETER Label
        Name of the label to be created.
        Emoji and codes are supported.
        For more information, see here: https://www.webpagefx.com/tools/emoji-cheat-sheet/

    .PARAMETER Color
        Color (in HEX) for the new label.

    .PARAMETER Description
        A short description of the label.

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
        GitHub.Label

    .EXAMPLE
        New-GitHubLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel -Color BBBBBB

        Creates a new, grey-colored label called "TestLabel" in the PowerShellForGitHub project.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    [OutputType({$script:GitHubLabelTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
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
            Mandatory,
            ValueFromPipeline)]
        [Alias('LabelName')]
        [string] $Label,

        [Parameter(Mandatory)]
        [ValidateScript({if ($_ -match '^#?[ABCDEF0-9]{6}$') { $true } else { throw "Color must be provided in hex." }})]
        [Alias('LabelColor')]
        [string] $Color = "EEEEEE",

        [string] $Description,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
    }

    # Be robust to users who choose to provide a color in hex by specifying the leading # sign
    # (by just stripping it out).
    if ($Color.StartsWith('#'))
    {
        $Color = $Color.Substring(1)
    }

    $hashBody = @{
        'name' = $Label
        'color' = $Color
        'description' = $Description
    }

    if (-not $PSCmdlet.ShouldProcess($Label, 'Create GitHub Label'))
    {
        return
    }

    $params = @{
        'UriFragment' = "repos/$OwnerName/$RepositoryName/labels"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Post'
        'Description' = "Creating label $Label in $RepositoryName"
        'AcceptHeader' = $script:symmetraAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethod @params | Add-GitHubLabelAdditionalProperties)
}

filter Remove-GitHubLabel
{
<#
    .SYNOPSIS
        Deletes a label from a given GitHub repository.

    .DESCRIPTION
        Deletes a label from a given GitHub repository.

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

    .PARAMETER Label
        Name of the label to be deleted.
        Emoji and codes are supported.  For more information, see here: https://www.webpagefx.com/tools/emoji-cheat-sheet/

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
        Remove-GitHubLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel

        Removes the label called "TestLabel" from the PowerShellForGitHub project.

    .EXAMPLE
        $label = $repo | Get-GitHubLabel -Label 'Test Label' -Color '#AAAAAA'
        $label | Remove-GitHubLabel

        Removes the label we just created using the pipeline, but will prompt for confirmation
        because neither -Confirm:$false nor -Force was specified.

    .EXAMPLE
        Remove-GitHubLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel -Confirm:$false

        Removes the label called "TestLabel" from the PowerShellForGitHub project.
        Will not prompt for confirmation, as -Confirm:$false was specified.

    .EXAMPLE
        Remove-GitHubLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel -Force

        Removes the label called "TestLabel" from the PowerShellForGitHub project.
        Will not prompt for confirmation, as -Force was specified.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements',
        ConfirmImpact="High")]
    [Alias('Delete-GitHubLabel')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
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
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('LabelName')]
        [string] $Label,

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
    }

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Label, 'Remove GitHub label'))
    {
        return
    }

    $params = @{
        'UriFragment' = "repos/$OwnerName/$RepositoryName/labels/$Label"
        'Method' = 'Delete'
        'Description' = "Deleting label $Label from $RepositoryName"
        'AcceptHeader' = $script:symmetraAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Set-GitHubLabel
{
<#
    .SYNOPSIS
        Updates an existing label on a given GitHub repository.

    .DESCRIPTION
        Updates an existing label on a given GitHub repository.

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

    .PARAMETER Label
        Current name of the label to be updated.
        Emoji and codes are supported.
        For more information, see here: https://www.webpagefx.com/tools/emoji-cheat-sheet/

    .PARAMETER NewName
        New name for the label being updated.
        Emoji and codes are supported.
        For more information, see here: https://www.webpagefx.com/tools/emoji-cheat-sheet/

    .PARAMETER Color
        Color (in HEX) for the new label.

    .PARAMETER Description
        A short description of the label.

    .PARAMETER PassThru
        Returns the updated Label.  By default, this cmdlet does not generate any output.
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
        GitHub.Label

    .EXAMPLE
        Set-GitHubLabel  -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel -NewName NewTestLabel -Color BBBB00

        Updates the existing label called TestLabel in the PowerShellForGitHub project to be called
        'NewTestLabel' and be colored yellow.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    [OutputType({$script:GitHubLabelTypeName})]
    [Alias('Update-GitHubLabel')] # Non-standard usage of the Update verb, but done to avoid a breaking change post 0.14.0
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
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('LabelName')]
        [string] $Label,

        [Alias('NewLabelName')]
        [string] $NewName,

        [Alias('LabelColor')]
        [ValidateScript({if ($_ -match '^#?[ABCDEF0-9]{6}$') { $true } else { throw "Color must be provided in hex." }})]
        [string] $Color = "EEEEEE",

        [string] $Description,

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
    }

    # Be robust to users who choose to provide a color in hex by specifying the leading # sign
    # (by just stripping it out).
    if ($Color.StartsWith('#'))
    {
        $Color = $Color.Substring(1)
    }

    $hashBody = @{}
    if ($PSBoundParameters.ContainsKey('NewName')) { $hashBody['name'] = $NewName }
    if ($PSBoundParameters.ContainsKey('Description')) { $hashBody['description'] = $Description }
    if ($PSBoundParameters.ContainsKey('Color')) { $hashBody['color'] = $Color }

    if (-not $PSCmdlet.ShouldProcess($Label, 'Update GitHub Label'))
    {
        return
    }

    $params = @{
        'UriFragment' = "repos/$OwnerName/$RepositoryName/labels/$Label"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Patch'
        'Description' = "Updating label $Label"
        'AcceptHeader' = $script:symmetraAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubLabelAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Initialize-GitHubLabel
{
<#
    .SYNOPSIS
        Replaces the entire set of Labels on the given GitHub repository to match the provided list
        of Labels.

    .DESCRIPTION
        Replaces the entire set of Labels on the given GitHub repository to match the provided list
        of Labels.

        Will update the color/description for any Labels already in the repository that match the
        name of a Label in the provided list.  All other existing Labels will be removed, and then
        new Labels will be created to match the others in the Label list.

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

    .PARAMETER Label
        The array of Labels (name, color, description) that the repository should be aligning to.
        A default list of labels will be used if no Labels are provided.

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
        Initialize-GitHubLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label @(@{'name' = 'TestLabel'; 'color' = 'EEEEEE'}, @{'name' = 'critical'; 'color' = 'FF000000'; 'description' = 'Needs immediate attention'})

        Removes any labels not in this Label array, ensure the current assigned color and descriptions
        match what's in the array for the labels that do already exist, and then creates new labels
        for any remaining ones in the Label list.

    .NOTES
        This method does not rename any existing labels, as it doesn't have any context regarding
        which Label the new name is for.  Therefore, it is possible that by running this function
        on a repository with Issues that have already been assigned Labels, you may experience data
        loss as a minor correction to you (maybe fixing a typo) will result in the old Label being
        removed (and thus unassigned from existing Issues) and then the new one created.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
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

        [Parameter(ValueFromPipelineByPropertyName)]
        [object[]] $Label,

        [string] $AccessToken
    )

    Write-InvocationLog

    if (($null -eq $Label) -or ($Label.Count -eq 0))
    {
        $Label = $script:defaultGitHubLabels
    }

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $commonParams = @{
        'OwnerName' = $OwnerName
        'RepositoryName' = $RepositoryName
        'AccessToken' = $AccessToken
    }

    $labelNames = $Label.name
    $existingLabels = Get-GitHubLabel @commonParams
    $existingLabelNames = $existingLabels.name

    if (-not $PSCmdlet.ShouldProcess(($Label -join ', '), 'Set GitHub Label'))
    {
        return
    }

    foreach ($labelToConfigure in $Label)
    {
        if ($labelToConfigure.name -notin $existingLabelNames)
        {
            # Create label if it doesn't exist
            $newGitHubLabelParms = @{
                Label = $labelToConfigure.name
                Color = $labelToConfigure.color
                Confirm = $false
                WhatIf = $false
            }

            $null = New-GitHubLabel @newGitHubLabelParms @commonParams
        }
        else
        {
            # Update label's color if it already exists
            $setGitHubLabelParms = @{
                Label = $labelToConfigure.name
                NewName = $labelToConfigure.name
                Color = $labelToConfigure.color
                Confirm = $false
                WhatIf = $false
            }

            $null = Set-GitHubLabel @setGitHubLabelParms @commonParams
        }
    }

    foreach ($labelName in $existingLabelNames)
    {
        if ($labelName -notin $labelNames)
        {
            # Remove label if it exists but is not in desired label list
            $removeGitHubLabelParms = @{
                Label = $labelName
                Confirm = $false
                WhatIf = $false
            }

            $null = Remove-GitHubLabel @removeGitHubLabelParms @commonParams
        }
    }
}

function Add-GitHubIssueLabel
{
<#
    .SYNOPSIS
        Adds a label to an issue in the given GitHub repository.

    .DESCRIPTION
        Adds a label to an issue in the given GitHub repository.

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

    .PARAMETER Issue
        Issue number to add the label to.

    .PARAMETER Label
        Array of label names to add to the issue

    .PARAMETER PassThru
        Returns the added Label.  By default, this cmdlet does not generate any output.
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
        GitHub.Label

    .EXAMPLE
        Add-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 1 -Label $labels

        Adds labels to an issue in the PowerShellForGitHub project.

    .NOTES
        This is implemented as a function rather than a filter because the ValueFromPipeline
        parameter (Name) is itself an array which we want to ensure is processed only a single time.
        This API endpoint doesn't add labels to a repository, it replaces the existing labels with
        the new set provided, so we need to make sure that we have all the requested labels available
        to us at the time that the API endpoint is called.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    [OutputType({$script:GitHubLabelTypeName})]
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
            ValueFromPipelineByPropertyName)]
        [Alias('IssueNumber')]
        [int64] $Issue,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('LabelName')]
        [ValidateNotNullOrEmpty()]
        [string[]] $Label,

        [switch] $PassThru,

        [string] $AccessToken
    )

    begin
    {
        $labelNames = @()
    }

    process
    {
        foreach ($name in $Label)
        {
            $labelNames += $name
        }
    }

    end
    {
        Write-InvocationLog

        $elements = Resolve-RepositoryElements
        $OwnerName = $elements.ownerName
        $RepositoryName = $elements.repositoryName

        $telemetryProperties = @{
            'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
            'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
            'LabelCount' = $Label.Count
        }

        $hashBody = @{
            'labels' = $labelNames
        }

        if (-not $PSCmdlet.ShouldProcess(($Label -join ', '), 'Add GitHub Issue Label'))
        {
            return
        }

        $params = @{
            'UriFragment' = "repos/$OwnerName/$RepositoryName/issues/$Issue/labels"
            'Body' = (ConvertTo-Json -InputObject $hashBody)
            'Method' = 'Post'
            'Description' = "Adding labels to issue $Issue in $RepositoryName"
            'AcceptHeader' = $script:symmetraAcceptHeader
            'AccessToken' = $AccessToken
            'TelemetryEventName' = $MyInvocation.MyCommand.Name
            'TelemetryProperties' = $telemetryProperties
        }

        $result = (Invoke-GHRestMethod @params | Add-GitHubLabelAdditionalProperties)
        if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
        {
            return $result
        }
    }
}

function Set-GitHubIssueLabel
{
<#
    .SYNOPSIS
        Replaces labels on an issue in the given GitHub repository.

    .DESCRIPTION
        Replaces labels on an issue in the given GitHub repository.

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

    .PARAMETER Issue
        Issue number to replace the labels.

    .PARAMETER Label
        Array of label names that will be set on the issue.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER PassThru
        Returns the updated Label.  By default, this cmdlet does not generate any output.
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
        GitHub.Label

    .EXAMPLE
        Set-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 1 -Label $labels

        Replaces labels on an issue in the PowerShellForGitHub project.

    .EXAMPLE
        ('help wanted', 'good first issue') | Set-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 1

        Replaces labels on an issue in the PowerShellForGitHub project
        with 'help wanted' and 'good first issue'.

    .EXAMPLE
        Set-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 1 -Confirm:$false

        Removes all labels from issue 1 in the PowerShellForGitHub project.
        Will not prompt for confirmation, as -Confirm:$false was specified.

        This is the same result as having called
        Remove-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 1 -Confirm:$false

    .EXAMPLE
        Set-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 1 -Force

        Removes all labels from issue 1 in the PowerShellForGitHub project.
        Will not prompt for confirmation, as -Force was specified.

        This is the same result as having called
        Remove-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 1 -Force

    .NOTES
        This is implemented as a function rather than a filter because the ValueFromPipeline
        parameter (Name) is itself an array which we want to ensure is processed only a single time.
        This API endpoint doesn't add labels to a repository, it replaces the existing labels with
        the new set provided, so we need to make sure that we have all the requested labels available
        to us at the time that the API endpoint is called.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements')]
    [OutputType({$script:GitHubLabelTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
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
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('IssueNumber')]
        [int64] $Issue,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('LabelName')]
        [string[]] $Label,

        [switch] $Force,

        [switch] $PassThru,

        [string] $AccessToken
    )

    begin
    {
        $labelNames = @()
    }

    process
    {
        foreach ($name in $Label)
        {
            $labelNames += $name
        }
    }

    end
    {
        Write-InvocationLog

        $elements = Resolve-RepositoryElements
        $OwnerName = $elements.ownerName
        $RepositoryName = $elements.repositoryName

        $telemetryProperties = @{
            'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
            'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
            'LabelCount' = $Label.Count
        }

        $hashBody = @{
            'labels' = $labelNames
        }

        $shouldProcessMessage = "Set GitHub Issue Label(s) $($Label -join ', ')"

        if ([System.String]::IsNullOrEmpty($Label))
        {
            $ConfirmPreference = 'Low'
            $shouldProcessMessage = 'Remove all GitHub Issue Labels'
        }

        if ($Force -and (-not $Confirm))
        {
            $ConfirmPreference = 'None'
        }

        if (-not $PSCmdlet.ShouldProcess("Issue #$Issue", $shouldProcessMessage))
        {
            return
        }

        $params = @{
            'UriFragment' = "repos/$OwnerName/$RepositoryName/issues/$Issue/labels"
            'Body' = (ConvertTo-Json -InputObject $hashBody)
            'Method' = 'Put'
            'Description' = "Replacing labels to issue $Issue in $RepositoryName"
            'AcceptHeader' = $script:symmetraAcceptHeader
            'AccessToken' = $AccessToken
            'TelemetryEventName' = $MyInvocation.MyCommand.Name
            'TelemetryProperties' = $telemetryProperties
        }

        $result = (Invoke-GHRestMethod @params | Add-GitHubLabelAdditionalProperties)
        if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
        {
            return $result
        }
    }
}

filter Remove-GitHubIssueLabel
{
<#
    .SYNOPSIS
        Deletes a label from an issue in the given GitHub repository.

    .DESCRIPTION
        Deletes a label from an issue in the given GitHub repository.

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

    .PARAMETER Issue
        Issue number to remove the label from.

    .PARAMETER Label
        Name of the label to be deleted. If not provided, will delete all labels on the issue.
        Emoji and codes are supported.
        For more information, see here: https://www.webpagefx.com/tools/emoji-cheat-sheet/

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
        Remove-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel -Issue 1

        Removes the label called "TestLabel" from issue 1 in the PowerShellForGitHub project.

    .EXAMPLE
        Remove-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel -Issue 1 -Confirm:$false

        Removes the label called "TestLabel" from issue 1 in the PowerShellForGitHub project.
        Will not prompt for confirmation, as -Confirm:$false was specified.

    .EXAMPLE
        Remove-GitHubIssueLabel -OwnerName microsoft -RepositoryName PowerShellForGitHub -Label TestLabel -Issue 1 -Force

        Removes the label called "TestLabel" from issue 1 in the PowerShellForGitHub project.
        Will not prompt for confirmation, as -Force was specified.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements',
        ConfirmImpact="High")]
    [Alias('Delete-GitHubLabel')]
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
            ValueFromPipelineByPropertyName)]
        [Alias('IssueNumber')]
        [int64] $Issue,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('LabelName')]
        [string] $Label,

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
    }

    $description = [String]::Empty
    if ($PSBoundParameters.ContainsKey('Label'))
    {
        $description = "Deleting label $Label from issue $Issue in $RepositoryName"
    }
    else
    {
        $description = "Deleting all labels from issue $Issue in $RepositoryName"
    }

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($Label, 'Remove GitHub Issue label'))
    {
        return
    }

    $params = @{
        'UriFragment' = "/repos/$OwnerName/$RepositoryName/issues/$Issue/labels/$Label"
        'Method' = 'Delete'
        'Description' = $description
        'AcceptHeader' = $script:symmetraAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Add-GitHubLabelAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Label objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER RepositoryUrl
        Optionally supplied if the Label object doesn't have this value already
        (as is the case for GitHub.LabelSummary).

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Label
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

        [string] $RepositoryUrl,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubLabelTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            if (-not [System.String]::IsNullOrEmpty($item.url))
            {
                $elements = Split-GitHubUri -Uri $item.url
                $RepositoryUrl = Join-GitHubUri @elements
            }

            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $RepositoryUrl -MemberType NoteProperty -Force

            if ($null -ne $item.id)
            {
                Add-Member -InputObject $item -Name 'LabelId' -Value $item.id -MemberType NoteProperty -Force
            }

            Add-Member -InputObject $item -Name 'LabelName' -Value $item.name -MemberType NoteProperty -Force
        }

        Write-Output $item
    }
}

# A set of labels that a project might want to initially populate their repository with
# Used by Set-GitHubLabel when no Label list is provided by the user.
# This list exists to support v0.1.0 users.
$script:defaultGitHubLabels = @(
    @{
        'name' = 'pri:lowest'
        'color' = '4285F4'
    },
    @{
        'name' = 'pri:low'
        'color' = '4285F4'
    },
    @{
        'name' = 'pri:medium'
        'color' = '4285F4'
    },
    @{
        'name' = 'pri:high'
        'color' = '4285F4'
    },
    @{
        'name' = 'pri:highest'
        'color' = '4285F4'
    },
    @{
        'name' = 'bug'
        'color' = 'fc2929'
    },
    @{
        'name' = 'duplicate'
        'color' = 'cccccc'
    },
    @{
        'name' = 'enhancement'
        'color' = '121459'
    },
    @{
        'name' = 'up for grabs'
        'color' = '159818'
    },
    @{
        'name' = 'question'
        'color' = 'cc317c'
    },
    @{
        'name' = 'discussion'
        'color' = 'fe9a3d'
    },
    @{
        'name' = 'wontfix'
        'color' = 'dcb39c'
    },
    @{
        'name' = 'in progress'
        'color' = 'f0d218'
    },
    @{
        'name' = 'ready'
        'color' = '145912'
    }
)

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCByMZePM4uqMoEn
# +KmS4gM0LrWi36rl9DD0+LU5efIVGKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFnnV8IbKbv79XDF9Vax4vod
# yqg4KMQxubTdsAqJzBK3MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA0nSPlqfrkMT2u1tc31aSzwpbIq5TuHCbpRiE00nqMgsCj2UE+/Vc5
# vs9p+Pqih3llcLKEcDZGQIvOC3DrqapwscWugjRfod9xsgIJbc0DleML90VO08NV
# D1lXxJZgpbxEG1f6WopXK6Bxs4c9pM89oO5q7eoIU3YjY9jguQqOr0wvUGqKAWPb
# 9n8a0EGjJ560eBpbwXvt0Euo5Gl8kTeWuB+JT5EKWAm5PD2Iklik0NxrBOQHY6Ck
# y0pDa23sv5twB5sWVYGXcKukIX5tLgAEEmnoc25FKDu2AbqbUmFPoGrXV7sxE3sK
# kPM3qqUnq6Z0y8L1g7XPQHPOY09g640woYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPTkcNTAWLnCYk3baLT09DjR9zK1O6S3CLNKIixzd0V0AgZlVsbo
# h+oYEzIwMjMxMTIxMTczNTM4Ljg3OFowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBMDAw
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAAB0HcIqu+jF8bdAAEAAAHQMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIxNFoXDTI0MDIwMTE5MTIxNFowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBMDAwLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAN8yV+ffl+8zRcBRKYjmqIbRTE+LbkeRLIGDOTfO
# lg7fXV3U4QQXPRCkArbezV0kWuMHmAP5IzDnPoTDELgKtdT0ppDhY0eoeuFZ+2mC
# jcyQl7H1+uY70yV1R+NQbnqwhbphUXpiNf72tPUkN0IMdujmdmJqwyKAYprAZvYe
# oPv+SNFHrtG9WHtDidq0BW7jpl/kwu+JHTE3lw0bbTHAHCC21pgSTleVQtoEfk6d
# fPZ5agjH5KMM7sG3kG4AFZjxK+ZFB8HJPZymkTNOO39+zTGngHVwAdUPCUbBm6/1
# F9zed13GAWsoDwxYdskXT5pZRRggFHwXLaC4VUegd47N7sixvK9GtrH//zeBiqjx
# zln/X+7uSMtxOCKmLJnxcRGwsQQInmjHUEEtjoCOZuADMN02XYt56P6oht0Gv9JS
# 8oQL5fDjGMUw5NRVYpZ6a3aSHCd1R8E1Hs3O7XP0vRa/tMBj+/6/qk2EB6iE8wIU
# lz5qTq4wPxMpLNYWPDloAOSYP2Ya4LzrK9IqQgjgxrLOhR2x5PSd+TxjR8+O13DZ
# ad6OXrMse5hfBwNq7Y7UMy6iJ501WNMXftQSZhP6jEL84VdQY8MRC323OBtH2Dwc
# u1R8R5Y6w4QPnGBvmvDJ+8iyzsf9x0cVwiIhzPNCBiewvIQZ6mhkOQqFIxHl4IHo
# py/9AgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUM+EBhZLSgD6U60hN+Mm3KXSSdFEw
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAJeH5yQKRloDTpI1b6rG1L2AdCnjHsb6
# B2KSeAoi0Svyi2RciuZY9itqtFYGVj3WWoaKKUfIiVneI0FRto0SZooAYxnlhxLs
# hlQo9qrWNTSazKX7yiDS30L9nbr5q3He+yEesVC5KDBMdlWnO/uTwJicFijF2EjW
# 4aGofn3maou+0yzEQ3/WyjtT5vdTosKvLm7DBzPn6Pw6PQZRfdv6JmD4CzTFM3pP
# RBrwE15z8vBzKpg0RoyRbZUAquaG9Yfw4INNxeA42ecAFAcF9cr98sBscUZLVc06
# 2vrb+JocEYCSsIaXoGLw9/Czp+z7D6wT2veFf1WDSCxEygdG4xqJeysaYay5icuf
# cDBOC4xq3D1HxTm8m1ZKW7UIU7k/QsS9BCIxnXaxBKxACQ0NOz2tONU2OMhSChnp
# c8zGVw8gNyPHDxt95vjLjADEzZFGhZzGmTH7ogh/Yv5vuAse0HFcJYnlsxbtbBQL
# YuW1u6tTAG/RKCOkO1sSrD+4OBYF6sJP5m3Lc1z3ruIZpCPJhAfof+H1dzyyabaf
# pWPJJHHazCdbeGvpDHrdT/Fj0cvoU2GsaIUQPtlEqufC+9e8xVBQgSQHsZQR43qF
# 5jyAcu3SMtXfLMOJADxHynlgaAYBW30wTCAAk1jWIe8f/y/OElJkU2Qfyy9HO07+
# LdO8quNvxnHCMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTAwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# ALy3yFPwopRf3WVTkWpE/0J+70yJoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpBzOWMCIYDzIwMjMxMTIxMTM0
# ODA2WhgPMjAyMzExMjIxMzQ4MDZaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOkH
# M5YCAQAwCgIBAAICFF8CAf8wBwIBAAICEwcwCgIFAOkIhRYCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEAAvrznTHY3j1W37ir2o3xAJipjESxpoP6WIRr2hjQ
# fO5x09k1UM6tzUL4z36fF5gII5cSWgvSWtWi29tUIfjTnb9/HOvl4hbo2r2Os7xS
# b/9MZyugg4wZCoy8QYsSyKpWQjRocLMPeArcI8tj0sbutPORXH38RZr6GtFXaRBO
# OkYHLSh9gRXU1cVn6k73kdzwRiu3g+AX4om9xH7rdjg4qLF0NyMDI86lesRSau/0
# LQ3Sr9OO42bElZKg7aq+KgbLedi9vcXWfxmYi2oVH++mYIoiwLIO4DQy3AJHv6w5
# r5+6+EqjgStG+cMRIFYnZmNiplEdrPRc/MAfoWghriD2bzGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB0HcIqu+jF8bdAAEA
# AAHQMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIHpfgHr5geSxx+iwTgZP0myRdFdkdBYuNpRRT/RM
# zSjbMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgCJVABl+00/8x3UTZjD58
# Fdr3Dp+OZNnlYB6utNI/CdcwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAdB3CKrvoxfG3QABAAAB0DAiBCD7k6DsUXnwKNRlQDIrKZAy
# hvlTILPtWBwzHkvazY60CjANBgkqhkiG9w0BAQsFAASCAgA9q5ffRvI31JX/wWnv
# w+u7zdVYgmaX4GcvTosTwsXXg3SniQAylC6nOXFCzNsv8a08cmui71OeTPwccgM9
# 9uqccHc58+8ueEPxAuI5rVZiK3Vxat7Hcm6BG+qCJtw8fe1osHTA9ahERx4E5JyZ
# gzW/Xw7rxh7mQUJrOWpuqAxHjDPswd6tdnMSXkB9angmO5gZLbJdtd7aACmPndRn
# n6vXXinGuu7rSaZ9h9rodcxgagUrCTgAyzYbNwOcFCF9PNZ9TqKgmgMcWwM7tSRP
# QGnJlPcZ84y9WDZIKIE4VJJM4QwPl98wdMavZJDwarCjGI+Wimhwqfnug7usyxLE
# UphCsGDAn22aoGJ7Vu+6OUG+IRYsFvdfuZtXsVZr2SDtR6837Bj0oPKQZPcvi1HP
# 1LLEN0Quwd2vmXxpAQBzcPoB+QiWGF9h4g9+lxw1HDmmqJ3XTq9SHQm6QMye4dqt
# 4Y/6z9r3NuYNBOh+QN+z9jcVwpmT4QTmcdS6qlc2/2EutDEq14tFDHm/bimVbstB
# xxkyXLwQaJQi6u/s2dAAhKtEqC4cJfpzgRc8K0JYwaojWPBehNGLEbh5dYibGHt8
# UsPsWBH/4zwkWMnNnUkzuRTSm7d7ucS7lR8Ea8BgATwJUe5zECIaI8woRySdFu0r
# 6dQIKF2siEYB3jFIa8TjVDTXvg==
# SIG # End signature block
