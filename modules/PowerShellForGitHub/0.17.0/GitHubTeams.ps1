# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubTeamTypeName = 'GitHub.Team'
    GitHubTeamSummaryTypeName = 'GitHub.TeamSummary'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubTeam
{
<#
    .SYNOPSIS
        Retrieve a team or teams within an organization or repository on GitHub.

    .DESCRIPTION
        Retrieve a team or teams within an organization or repository on GitHub.

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

    .PARAMETER OrganizationName
        The name of the organization.

    .PARAMETER TeamName
        The name of the specific team to retrieve.
        Note: This will be slower than querying by TeamSlug since it requires retrieving
        all teams first.

    .PARAMETER TeamSlug
        The slug (a unique key based on the team name) of the specific team to retrieve.

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
        GitHub.Organization
        GitHub.PullRequest
        GitHub.Project
        GitHub.ProjectCard
        GitHub.ProjectColumn
        GitHub.Reaction
        GitHub.Release
        GitHub.ReleaseAsset
        GitHub.Repository
        GitHub.Team

    .OUTPUTS
        GitHub.Team
        GitHub.TeamSummary

    .EXAMPLE
        Get-GitHubTeam -OrganizationName PowerShell
#>
    [CmdletBinding(DefaultParameterSetName = 'Elements')]
    [OutputType(
        {$script:GitHubTeamTypeName},
        {$script:GitHubTeamSummaryTypeName})]
    param
    (
        [Parameter(ParameterSetName='Elements')]
        [Parameter(ParameterSetName='TeamName')]
        [string] $OwnerName,

        [Parameter(ParameterSetName='Elements')]
        [Parameter(ParameterSetName='TeamName')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Uri')]
        [Parameter(
            ValueFromPipelineByPropertyName,
            ParameterSetName='TeamName')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Organization')]
        [Parameter(
            ValueFromPipelineByPropertyName,
            ParameterSetName='TeamName')]
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='TeamSlug')]
        [ValidateNotNullOrEmpty()]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ParameterSetName='TeamName')]
        [ValidateNotNullOrEmpty()]
        [string] $TeamName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='TeamSlug')]
        [ValidateNotNullOrEmpty()]
        [string] $TeamSlug,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{}

    $uriFragment = [String]::Empty
    $description = [String]::Empty
    $teamType = [String]::Empty

    if ($PSBoundParameters.ContainsKey('TeamName') -and
        (-not $PSBoundParameters.ContainsKey('OrganizationName')))
    {
        $elements = Resolve-RepositoryElements
        $OwnerName = $elements.ownerName
        $RepositoryName = $elements.repositoryName
    }

    if ((-not [String]::IsNullOrEmpty($OwnerName)) -and
        (-not [String]::IsNullOrEmpty($RepositoryName)))
    {
        $telemetryProperties['OwnerName'] = Get-PiiSafeString -PlainText $OwnerName
        $telemetryProperties['RepositoryName'] = Get-PiiSafeString -PlainText $RepositoryName

        $uriFragment = "/repos/$OwnerName/$RepositoryName/teams"
        $description = "Getting teams for $RepositoryName"
        $teamType = $script:GitHubTeamSummaryTypeName
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'TeamSlug')
    {
        $telemetryProperties['TeamSlug'] = Get-PiiSafeString -PlainText $TeamSlug

        $uriFragment = "/orgs/$OrganizationName/teams/$TeamSlug"
        $description = "Getting team $TeamSlug"
        $teamType = $script:GitHubTeamTypeName
    }
    else
    {
        $telemetryProperties['OrganizationName'] = Get-PiiSafeString -PlainText $OrganizationName

        $uriFragment = "/orgs/$OrganizationName/teams"
        $description = "Getting teams in $OrganizationName"
        $teamType = $script:GitHubTeamSummaryTypeName
    }

    $params = @{
        'UriFragment' = $uriFragment
        'AcceptHeader' = $script:hellcatAcceptHeader
        'Description' = $description
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = Invoke-GHRestMethodMultipleResult @params |
        Add-GitHubTeamAdditionalProperties -TypeName $teamType

    if ($PSBoundParameters.ContainsKey('TeamName'))
    {
        $team = $result | Where-Object -Property name -eq $TeamName

        if ($null -eq $team)
        {
            $message = "Team '$TeamName' not found"
            Write-Log -Message $message -Level Error
            throw $message
        }
        else
        {
            $uriFragment = "/orgs/$($team.OrganizationName)/teams/$($team.slug)"
            $description = "Getting team $($team.slug)"

            $params = @{
                UriFragment = $uriFragment
                Description =  $description
                Method = 'Get'
                AccessToken = $AccessToken
                TelemetryEventName = $MyInvocation.MyCommand.Name
                TelemetryProperties = $telemetryProperties
            }

            $result = Invoke-GHRestMethod @params | Add-GitHubTeamAdditionalProperties
        }
    }

    return $result
}

filter Get-GitHubTeamMember
{
<#
    .SYNOPSIS
        Retrieve list of team members within an organization.

    .DESCRIPTION
        Retrieve list of team members within an organization.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OrganizationName
        The name of the organization.

    .PARAMETER TeamName
        The name of the team in the organization.

    .PARAMETER TeamSlug
        The slug (a unique key based on the team name) of the team in the organization.

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
        GitHub.Release
        GitHub.ReleaseAsset
        GitHub.Repository
        GitHub.Team

    .OUTPUTS
        GitHub.User

    .EXAMPLE
        $members = Get-GitHubTeamMember -Organization PowerShell -TeamName Everybody
#>
    [CmdletBinding(DefaultParameterSetName = 'Slug')]
    [OutputType({$script:GitHubUserTypeName})]
    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $OrganizationName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Name')]
        [ValidateNotNullOrEmpty()]
        [String] $TeamName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='Slug')]
        [string] $TeamSlug,

        [string] $AccessToken
    )

    Write-InvocationLog

    if ($PSCmdlet.ParameterSetName -eq 'Name')
    {
        $teams = Get-GitHubTeam -OrganizationName $OrganizationName -AccessToken $AccessToken
        $team = $teams | Where-Object {$_.name -eq $TeamName}
        if ($null -eq $team)
        {
            $message = "Unable to find the team [$TeamName] within the organization [$OrganizationName]."
            Write-Log -Message $message -Level Error
            throw $message
        }

        $TeamSlug = $team.slug
    }

    $telemetryProperties = @{
        'OrganizationName' = (Get-PiiSafeString -PlainText $OrganizationName)
        'TeamName' = (Get-PiiSafeString -PlainText $TeamName)
        'TeamSlug' = (Get-PiiSafeString -PlainText $TeamSlug)
    }

    $params = @{
        'UriFragment' = "orgs/$OrganizationName/teams/$TeamSlug/members"
        'Description' = "Getting members of team $TeamSlug"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubUserAdditionalProperties)
}

function New-GitHubTeam
{
<#
    .SYNOPSIS
        Creates a team within an organization on GitHub.

    .DESCRIPTION
        Creates a team within an organization on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OrganizationName
        The name of the organization to create the team in.

    .PARAMETER TeamName
        The name of the team.

    .PARAMETER Description
        The description for the team.

    .PARAMETER MaintainerName
        A list of GitHub user names for organization members who will become team maintainers.

    .PARAMETER RepositoryName
        The name of repositories to add the team to.

    .PARAMETER Privacy
        The level of privacy this team should have.

    .PARAMETER ParentTeamName
        The name of a team to set as the parent team.

    .PARAMETER ParentTeamId
        The ID of the team to set as the parent team.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Team
        GitHub.User
        System.String

    .OUTPUTS
        GitHub.Team

    .EXAMPLE
        New-GitHubTeam -OrganizationName PowerShell -TeamName 'Developers'

        Creates a new GitHub team called 'Developers' in the 'PowerShell' organization.

    .EXAMPLE
        $teamName = 'Team1'
        $teamName | New-GitHubTeam -OrganizationName PowerShell

        You can also pipe in a team name that was returned from a previous command.

    .EXAMPLE
        $users = Get-GitHubUsers -OrganizationName PowerShell
        $users | New-GitHubTeam -OrganizationName PowerShell -TeamName 'Team1'

        You can also pipe in a list of GitHub users that were returned from a previous command.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false,
        DefaultParameterSetName = 'ParentId'
    )]
    [OutputType({$script:GitHubTeamTypeName})]
    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $TeamName,

        [string] $Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('UserName')]
        [string[]] $MaintainerName,

        [string[]] $RepositoryName,

        [ValidateSet('Secret', 'Closed')]
        [string] $Privacy,

        [Parameter(ParameterSetName='ParentName')]
        [string] $ParentTeamName,

        [Parameter(
            ValueFromPipelineByPropertyName,
            ParameterSetName='ParentId')]
        [Alias('TeamId')]
        [int64] $ParentTeamId,

        [string] $AccessToken
    )

    begin
    {
        $maintainerNames = @()
    }

    process
    {
        foreach ($user in $MaintainerName)
        {
            $maintainerNames += $user
        }
    }

    end
    {
        Write-InvocationLog

        $telemetryProperties = @{
            OrganizationName = (Get-PiiSafeString -PlainText $OrganizationName)
            TeamName = (Get-PiiSafeString -PlainText $TeamName)
        }

        $uriFragment = "/orgs/$OrganizationName/teams"

        $hashBody = @{
            name = $TeamName
        }

        if ($PSBoundParameters.ContainsKey('Description')) { $hashBody['description'] = $Description }
        if ($PSBoundParameters.ContainsKey('RepositoryName'))
        {
            $repositoryFullNames = @()
            foreach ($repository in $RepositoryName)
            {
                $repositoryFullNames += "$OrganizationName/$repository"
            }
            $hashBody['repo_names'] = $repositoryFullNames
        }
        if ($PSBoundParameters.ContainsKey('Privacy')) { $hashBody['privacy'] = $Privacy.ToLower() }
        if ($MaintainerName.Count -gt 0)
        {
            $hashBody['maintainers'] = $maintainerNames
        }
        if ($PSBoundParameters.ContainsKey('ParentTeamName'))
        {
            $getGitHubTeamParms = @{
                OrganizationName = $OrganizationName
                TeamName = $ParentTeamName
            }
            if ($PSBoundParameters.ContainsKey('AccessToken'))
            {
                $getGitHubTeamParms['AccessToken'] = $AccessToken
            }

            $team = Get-GitHubTeam @getGitHubTeamParms
            $ParentTeamId = $team.id
        }

        if ($ParentTeamId -gt 0)
        {
            $hashBody['parent_team_id'] = $ParentTeamId
        }

        if (-not $PSCmdlet.ShouldProcess($TeamName, 'Create GitHub Team'))
        {
            return
        }

        $params = @{
            UriFragment = $uriFragment
            Body = (ConvertTo-Json -InputObject $hashBody)
            Method = 'Post'
            Description =  "Creating $TeamName"
            AccessToken = $AccessToken
            TelemetryEventName = $MyInvocation.MyCommand.Name
            TelemetryProperties = $telemetryProperties
        }

        return (Invoke-GHRestMethod @params | Add-GitHubTeamAdditionalProperties)
    }
}

filter Set-GitHubTeam
{
<#
    .SYNOPSIS
        Updates a team within an organization on GitHub.

    .DESCRIPTION
        Updates a team within an organization on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OrganizationName
        The name of the team's organization.

    .PARAMETER TeamName
        The name of the team.

        When TeamSlug is specified, specifying a name here that is different from the existing
        name will cause the team to be renamed. TeamSlug and TeamName are specified for you
        automatically when piping in a GitHub.Team object, so a rename would only occur if
        intentionally specify this parameter and provide a different name.

    .PARAMETER TeamSlug
        The slug (a unique key based on the team name) of the team to update.

    .PARAMETER Description
        The description for the team.

    .PARAMETER Privacy
        The level of privacy this team should have.

    .PARAMETER ParentTeamName
        The name of a team to set as the parent team.

    .PARAMETER ParentTeamId
        The ID of the team to set as the parent team.

    .PARAMETER PassThru
        Returns the updated GitHub Team.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Organization
        GitHub.Team

    .OUTPUTS
        GitHub.Team

    .EXAMPLE
        Set-GitHubTeam -OrganizationName PowerShell -TeamName Developers -Description 'New Description'

        Updates the description for the 'Developers' GitHub team in the 'PowerShell' organization.

    .EXAMPLE
        $team = Get-GitHubTeam -OrganizationName PowerShell -TeamName Developers
        $team | Set-GitHubTeam -Description 'New Description'

        You can also pipe in a GitHub team that was returned from a previous command.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false,
        DefaultParameterSetName = 'ParentName'
    )]
    [OutputType( { $script:GitHubTeamTypeName } )]
    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $TeamName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $TeamSlug,

        [string] $Description,

        [ValidateSet('Secret','Closed')]
        [string] $Privacy,

        [Parameter(ParameterSetName='ParentTeamName')]
        [string] $ParentTeamName,

        [Parameter(ParameterSetName='ParentTeamId')]
        [int64] $ParentTeamId,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{
        OrganizationName = (Get-PiiSafeString -PlainText $OrganizationName)
        TeamSlug = (Get-PiiSafeString -PlainText $TeamSlug)
        TeamName = (Get-PiiSafeString -PlainText $TeamName)
    }

    if ((-not $PSBoundParameters.ContainsKey('TeamSlug')) -or
        $PSBoundParameters.ContainsKey('ParentTeamName'))
    {
        $getGitHubTeamParms = @{
            OrganizationName = $OrganizationName
        }
        if ($PSBoundParameters.ContainsKey('AccessToken'))
        {
            $getGitHubTeamParms['AccessToken'] = $AccessToken
        }

        $orgTeams = Get-GitHubTeam @getGitHubTeamParms

        if ($PSBoundParameters.ContainsKey('TeamName'))
        {
            $team = $orgTeams | Where-Object -Property name -eq $TeamName
            $TeamSlug = $team.slug
        }
    }

    $uriFragment = "/orgs/$OrganizationName/teams/$TeamSlug"

    $hashBody = @{
        name = $TeamName
    }

    if ($PSBoundParameters.ContainsKey('Description')) { $hashBody['description'] = $Description }
    if ($PSBoundParameters.ContainsKey('Privacy')) { $hashBody['privacy'] = $Privacy.ToLower() }
    if ($PSBoundParameters.ContainsKey('ParentTeamName'))
    {
        $parentTeam = $orgTeams | Where-Object -Property name -eq $ParentTeamName
        $hashBody['parent_team_id'] = $parentTeam.id
    }
    elseif ($PSBoundParameters.ContainsKey('ParentTeamId'))
    {
        if ($ParentTeamId -gt 0)
        {
            $hashBody['parent_team_id'] = $ParentTeamId
        }
        else
        {
            $hashBody['parent_team_id'] = $null
        }
    }

    if (-not $PSCmdlet.ShouldProcess($TeamSlug, 'Set GitHub Team'))
    {
        return
    }

    $params = @{
        UriFragment = $uriFragment
        Body = (ConvertTo-Json -InputObject $hashBody)
        Method = 'Patch'
        Description =  "Updating $TeamName"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubTeamAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Rename-GitHubTeam
{
<#
    .SYNOPSIS
        Renames a team within an organization on GitHub.

    .DESCRIPTION
        Renames a team within an organization on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OrganizationName
        The name of the team's organization.

    .PARAMETER TeamName
        The existing name of the team.

    .PARAMETER TeamSlug
        The slug (a unique key based on the team name) of the team to update.

    .PARAMETER NewTeamName
        The new name for the team.

    .PARAMETER PassThru
        Returns the updated GitHub Team.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Organization
        GitHub.Team

    .OUTPUTS
        GitHub.Team

    .EXAMPLE
        Rename-GitHubTeam -OrganizationName PowerShell -TeamName Developers -NewTeamName DeveloperTeam

        Renames the 'Developers' GitHub team in the 'PowerShell' organization to be 'DeveloperTeam'.

    .EXAMPLE
        $team = Get-GitHubTeam -OrganizationName PowerShell -TeamName Developers
        $team | Rename-GitHubTeam -NewTeamName 'DeveloperTeam'

        You can also pipe in a GitHub team that was returned from a previous command.

    .NOTES
        This is a helper/wrapper for Set-GitHubTeam which can also rename a GitHub Team.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        DefaultParameterSetName = 'TeamSlug')]
    [OutputType( { $script:GitHubTeamTypeName } )]
    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2,
            ParameterSetName='TeamName')]
        [ValidateNotNullOrEmpty()]
        [string] $TeamName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='TeamSlug')]
        [ValidateNotNullOrEmpty()]
        [string] $TeamSlug,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $NewTeamName,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    if (-not $PSBoundParameters.ContainsKey('TeamSlug'))
    {
        $team = Get-GitHubTeam -OrganizationName $OrganizationName -TeamName $TeamName -AccessToken:$AccessToken
        $TeamSlug = $team.slug
    }

    $params = @{
        OrganizationName = $OrganizationName
        TeamSlug = $TeamSlug
        TeamName = $NewTeamName
        PassThru = (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
        AccessToken = $AccessToken
    }

    return Set-GitHubTeam @params
}

filter Remove-GitHubTeam
{
<#
    .SYNOPSIS
        Removes a team from an organization on GitHub.

    .DESCRIPTION
        Removes a team from an organization on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OrganizationName
        The name of the organization the team is in.

    .PARAMETER TeamName
        The name of the team to remove.

    .PARAMETER TeamSlug
        The slug (a unique key based on the team name) of the team to remove.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Organization
        GitHub.Team

    .OUTPUTS
        None

    .EXAMPLE
        Remove-GitHubTeam -OrganizationName PowerShell -TeamName Developers

        Removes the 'Developers' GitHub team from the 'PowerShell' organization.

    .EXAMPLE
        Remove-GitHubTeam -OrganizationName PowerShell -TeamName Developers -Force

        Removes the 'Developers' GitHub team from the 'PowerShell' organization without prompting.

    .EXAMPLE
        $team = Get-GitHubTeam -OrganizationName PowerShell -TeamName Developers
        $team | Remove-GitHubTeam -Force

        You can also pipe in a GitHub team that was returned from a previous command.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        PositionalBinding = $false,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'TeamSlug')]
    [Alias('Delete-GitHubTeam')]
    param
    (
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            Position = 2,
            ParameterSetName='TeamName')]
        [ValidateNotNullOrEmpty()]
        [string] $TeamName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName='TeamSlug')]
        [ValidateNotNullOrEmpty()]
        [string] $TeamSlug,

        [switch] $Force,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{
        OrganizationName = (Get-PiiSafeString -PlainText $RepositoryName)
        TeamSlug = (Get-PiiSafeString -PlainText $TeamSlug)
        TeamName = (Get-PiiSafeString -PlainText $TeamName)
    }

    if ($PSBoundParameters.ContainsKey('TeamName'))
    {
        $getGitHubTeamParms = @{
            OrganizationName = $OrganizationName
            TeamName = $TeamName
        }
        if ($PSBoundParameters.ContainsKey('AccessToken'))
        {
            $getGitHubTeamParms['AccessToken'] = $AccessToken
        }

        $team = Get-GitHubTeam @getGitHubTeamParms
        $TeamSlug = $team.slug
    }

    $uriFragment = "/orgs/$OrganizationName/teams/$TeamSlug"

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($TeamName, 'Remove Github Team'))
    {
        return
    }

    $params = @{
        UriFragment = $uriFragment
        Method = 'Delete'
        Description =  "Deleting $TeamSlug"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    Invoke-GHRestMethod @params | Out-Null
}

filter Add-GitHubTeamAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Team objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Team
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
        [string] $TypeName = $script:GitHubTeamTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            Add-Member -InputObject $item -Name 'TeamName' -Value $item.name -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'TeamId' -Value $item.id -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'TeamSlug' -Value $item.slug -MemberType NoteProperty -Force

            $organizationName = [String]::Empty
            if ($item.organization)
            {
                $organizationName = $item.organization.login
            }
            else
            {
                $hostName = $(Get-GitHubConfiguration -Name 'ApiHostName')

                if ($item.html_url -match "^https?://$hostName/orgs/([^/]+)/.*$")
                {
                    $organizationName = $Matches[1]
                }
            }

            Add-Member -InputObject $item -Name 'OrganizationName' -Value $organizationName -MemberType NoteProperty -Force

            # Apply these properties to any embedded parent teams as well.
            if ($null -ne $item.parent)
            {
                $null = Add-GitHubTeamAdditionalProperties -InputObject $item.parent
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDusFBOFNJl7wBU
# nCPAOK2gCwbxAIl35s1QZjzz1O8oMKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPqy9eIk6v8i/BB3UM9npHhg
# jNPV4y83zbPLYt5MFGE8MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB1CbAVjPc1ldO0j+l60KUADx/aC299euQCr6JTK4i4/Fy1g3iof1gA
# fOlA9a9kkYCuacVXZf7MGweY4RnlxNW/ypZ3B9HCo2nMnsRGNfBmUB4OBBE9QX/0
# 41a3HC01ustiNZOM7aJKW6zMK6A89O6TOMBkD+dMoTla4bk73B3kZNiTlT47BL9g
# MV2lTMzaiSAu9pjCS+ZBH11NXhJEI6RCcE9k3RsDtp7zuAq8EJmydtimA2CvZWZ/
# gY/CBeVojk37LE6CBUaqe1Y3w3wpjEWQMFS3ro3Xwxmx9BISH4NO2lOUnRjxhR4c
# ay8TeZ6AYB8w7Z9+sRTEnKvxYByTHGJfoYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIFJYVkIbGfVU57+Xl4D/fgNP3GhAHXfCVf/EjU8Avfl1AgZlVuGY
# qE0YEzIwMjMxMTIxMTczNjA1LjkyOFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAePfvZuaHGiDIgABAAAB4zAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MzEwMTIxOTA3MjlaFw0yNTAxMTAxOTA3MjlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvqQNaB5Gn5/FIFQPo3/K
# 4QmleCDMF40bkoHwz0BshZ4SiQmA6CGUyDwmaqQ2wHhaXU0RdHtwvq+U8KxYYsyH
# KqaxxC7fr/yHZvHpNTgzx1VkR3pXhT6X2Cm175UX3WQ4jfl86onp5AMzBIFDlz0S
# U8VSKNMDvNXtjk9FitLgUv2nj3hOJ0KkEQfk3oA7m7zA0D+Mo73hmR+OC7uwsXxJ
# R2tzUZE0STYX3UvenFH7fYWy5BNmLyGq2sWkQ5HFvJKCJAE/dwft8+V43U3KeExF
# /pPtcLUvQ9HIrL0xnpMFau7Yd5aK+TEi57WctBv87+fSPZBV3jZl/QCtcH9WrniB
# Dwki9QfRxu/JYzw+iaEWLqrYXuF7jeOGvHK+fVeLWnAc5WxsfbpjEMpNbGXbSF9A
# t3PPhFVOjxwVEx1ALGUqRKehw9ap9X/gfkA9I9eTSvwJz9wya9reDgS+6kXgSttI
# 7RQ2cJG/tQPGVIaLCIaSafLneaq0Bns0t4+EW3B/GnoBMiiOXwleOvf5udBZQIMJ
# 3k5qnnh8Z4ZhTwrE6iGbPrTgGBPXh7exFYAGlb6hdhILIVDdJlDf8s1NVvL0Q2y4
# SHZQhApZTuW/tyGsGscIPDSMz5bA6NhRLtjEwCFpLI5qGlu50Au9FRelCEQsWg7q
# 07H/rqHOqCNJM4Rjem7joEUCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBSxrg1mvjUV
# t6Fnxj56nabZiJipAzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAt76bLqnU08wR
# bW3vRrxjaEbGPqyINK6UYCzhTGaR/PEwCJziPT4ZM9sfGTX3eZDQVE9r121tFtp7
# NXQYuQSxRZMYXa0/pawN2Xn+UPjBRDvoCsU56dwKkrmy8TSw7QXKGskdnEwsI5yW
# 93q8Ag86RkBiKEEf9FdzHNuKWI4Kv//fDtESewu46n/u+VckCwbOYl6wE//QRGrG
# Mq509a4EbP+p1GUm06Xme/01mTIuKDgPmHL2nYRzXNqi2IuIecn2aWwkRxQOFiPw
# +dicmOOwLG/7InNqjZpQeIhDMxsWr4zTxzy4ER/6zfthtlDtcAXHB7YRUkBTClaO
# a0ndvfNJZMyYVa6cWvZouTq9V5LS7UzIR8S/7RsOT43eOawLBsuQz0VoOLurYe1S
# ffPqTsCcRNzbx0C8t/+KipStVhPAGttEfhdUUS9ohD6Lt6wNCJxZbV0IMD8nfE6g
# IQJXrzrXWOuJqN91WDyjRan4UKDkIBS2yWA4W6JhQuBzGerOSY/aLnxkRrSubgtn
# KYcHOwgxTTIya5WYCRjFt0QOLleqVki6k+mqYPr98uMPi5vRIQS206mDSenStr8w
# 0J+/+1WEm3PnCCIQgpf6zhqRrAt9j7XrEMHrg2bQegaz8bLzbe6UibgbKtRyk1nG
# de8To5kyMj9XUCBICDxT+F4xa5lNZVQwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQA9iJe7w5FDiG8py4TsYrQI6DFaeqCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6QdOejAiGA8yMDIzMTEyMTIzNDI1MFoYDzIwMjMxMTIyMjM0MjUwWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDpB056AgEAMAcCAQACAgKbMAcCAQACAhF3MAoC
# BQDpCJ/6AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAJC9qXPsCCBBExJv/
# gtyPhVfiCE5pUMtZnoR7KTgS2Fox/zivi3FDcCLBTOHsSjSGmscKd+29H0MWoF0K
# LmFgDRxClZBRh102Sb9Hx3RyzeuQORkMQNdwbtrsgn5FjDAAgUKmeSUjX80ujseE
# ZFoNpfX3uek2MBlAbaT/UYkvHXYxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAePfvZuaHGiDIgABAAAB4zANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCBzc8PSeNEY0SFb1/F7mDQ+iM5sA2RqpBQpPCeTz6Vt2jCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIDPUI6vlsP5k90SBCNa9wha4MlxBt2Crw12PTHIy
# 5iYqMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHj
# 372bmhxogyIAAQAAAeMwIgQgAd26ZylHjs38VDlKqnZ0Wsgslt1EweWo5nkAkt3d
# 2V4wDQYJKoZIhvcNAQELBQAEggIAC6N+j2T3xewidlp6Isp5zjYZfOuWLTZyxRbI
# LXyTZUDr3koSPbhmjA8Jo+JqeaNKrNU43oKO9WFRUhT3w66TPrtbJ7WbLSFkzYhi
# WdF4fkf8HrQuQJe2rj6tnrn6uMEh3qlbISNlDAIVDiNkvjl59lUOkWsI91yP+U+r
# +8H2x4QnTRbELnXQF6F2IA1RF9G2r0y8UVw/kV83ml6Ogi2/dCNXqdWNLn+xBqgf
# oU6f8rvXlwrqxrQt2C0bd7eYC/0CkO8izADhnE+nCORuhHiwhppZJNjjPjf63jy/
# QeFoW2e/IhRcxFAn1Aw2Qu2yxMtGACPteEfJR0dcjx/Ok2+zVmqq6Xtx9XOgcPIM
# bVMJHzlKEqVUMaJLnydAfqlH7fCLEIl6atpa6Exib4ngDJg0O+hvKVbZRqIZFMBp
# vlL2AINYkW8e3SAeGGe4HxUfDuKuawZaIFYDHuJAbrCSCuK/+tIrfJWi+NQAVsH3
# wWPCh0FgpjYE5k0aS8Oi9bnBOSxmQZ8EE+WWvHhXy23aEvReROCCQJsQhYjH53ka
# DVbC+b9EvsGLbXUMRyJCkxSzHP2QGDNrPqiJvLH+LBUK6foGhZtOMhxbUv/YxTyv
# P21kUbrHL6cJhXji7TlYuIiOBgPA8zIiaaVrGk04xosdiCSxrQdgoO7RRYRAwIby
# RnEWQco=
# SIG # End signature block
