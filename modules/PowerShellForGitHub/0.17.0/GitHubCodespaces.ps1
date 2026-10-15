# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubCodespaceTypeName = 'GitHub.Codespace'
}.GetEnumerator() | ForEach-Object {
    Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
}

filter Get-GitHubCodespace
{
    <#
    .SYNOPSIS
        Retrieves information about a Codespace or list of codespaces on GitHub.

    .DESCRIPTION
        Retrieves information about a Codespace or list of codespaces on GitHub.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OwnerName
        Owner of the Codespace.
        If not supplied here, the DefaultOwnerName configuration property value will be used.

    .PARAMETER RepositoryName
        Name of the repository.
        If not supplied here, the DefaultRepositoryName configuration property value will be used.

    .PARAMETER Uri
        Uri for the Codespace.
        The OwnerName and CodespaceName will be extracted from here instead of needing to provide
        them individually.

    .PARAMETER OrganizationName
        Name of the Organization.

    .PARAMETER UserName
        The handle for the GitHub user account.

    .PARAMETER CodespaceName
        Name of the Codespace.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Codespace
        GitHub.Project
        GitHub.Repository
        GitHub.User

    .OUTPUTS
        GitHub.Codespace

    .EXAMPLE
        Get-GitHubCodespace

        Gets all codespaces for the current authenticated user.

    .EXAMPLE
        Get-GitHubCodespace -OwnerName octocat

        Gets all of the codespaces for the user octocat

    .EXAMPLE
        Get-GitHubUser -UserName octocat | Get-GitHubCodespace

        Gets all of the codespaces for the user octocat

    .EXAMPLE
        Get-GitHubCodespace -Uri https://github.com/microsoft/PowerShellForGitHub

        Gets information about the microsoft/PowerShellForGitHub Codespace.

    .EXAMPLE
        $repo | Get-GitHubCodespace

        You can pipe in a previous Codespace to get its refreshed information.

    .EXAMPLE
        Get-GitHubCodespace -OrganizationName PowerShell

        Gets all of the codespaces in the PowerShell organization.

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#get-a-codespace-for-the-authenticated-user

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#list-codespaces-in-a-repository-for-the-authenticated-user

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#list-codespaces-for-the-authenticated-user

    .LINK
        https://docs.github.com/en/rest/codespaces/organizations?apiVersion=2022-11-28#list-codespaces-for-the-organization

    .LINK
        https://docs.github.com/en/rest/codespaces/organizations?apiVersion=2022-11-28#list-codespaces-for-a-user-in-organization
#>
    [CmdletBinding(DefaultParameterSetName = 'AuthenticatedUser')]
    [OutputType({ $script:GitHubCodespaceTypeName })]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Organization')]
        [string] $OrganizationName,

        [Parameter(
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Organization')]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'CodespaceName')]
        [string] $CodespaceName,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{
        UsageType = $PSCmdlet.ParameterSetName
    }

    $uriFragment = [String]::Empty
    $description = [String]::Empty
    switch ($PSCmdlet.ParameterSetName)
    {
        'AuthenticatedUser'
        {
            $uriFragment = 'user/codespaces'
            $description = 'Getting codespaces for current authenticated user'

            break
        }

        'CodespaceName'
        {
            $telemetryProperties['CodespaceName'] = Get-PiiSafeString -PlainText $CodespaceName

            $uriFragment = "user/codespaces/$CodespaceName"
            $description = "Getting user/codespaces/$CodespaceName"

            break
        }

        'Organization'
        {
            $telemetryProperties['OrganizationName'] = Get-PiiSafeString -PlainText $OrganizationName
            if ([string]::IsNullOrWhiteSpace($UserName))
            {
                $uriFragment = "orgs/$OrganizationName/codespaces"
                $description = "Getting codespaces for $OrganizationName"
            }
            else
            {
                $telemetryProperties['UserName'] = Get-PiiSafeString -PlainText $UserName
                $uriFragment = "orgs/$OrganizationName/members/$UserName/codespaces"
                $description = "Getting codespaces for $OrganizationName"
            }

            break
        }

        { $_ -in ('Elements', 'Uri') }
        {
            $elements = Resolve-RepositoryElements
            $OwnerName = $elements.ownerName
            $RepositoryName = $elements.repositoryName

            $telemetryProperties['OwnerName'] = Get-PiiSafeString -PlainText $OwnerName
            $telemetryProperties['RepositoryName'] = Get-PiiSafeString -PlainText $RepositoryName

            $uriFragment = "repos/$OwnerName/$RepositoryName/codespaces"
            $description = "Getting $OwnerName/$RepositoryName/codespaces"

            break
        }
    }

    $params = @{
        UriFragment = $uriFragment
        Description = $description
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    $result = Invoke-GHRestMethodMultipleResult @params
    if ($null -ne $result.codespaces)
    {
        $result = $result.codespaces
    }

    return ($result | Add-GitHubCodespaceAdditionalProperties)
}

function New-GitHubCodespace
{
    <#
    .SYNOPSIS
        Creates a codespace.

    .DESCRIPTION
        Creates a codespace.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OwnerName
        Owner of the Codespace.
        If not supplied here, the DefaultOwnerName configuration property value will be used.

    .PARAMETER RepositoryName
        Name of the repository.
        If not supplied here, the DefaultRepositoryName configuration property value will be used.

    .PARAMETER Uri
        Uri for the Codespace.
        The OwnerName and CodespaceName will be extracted from here instead of needing to provide
        them individually.

    .PARAMETER PullRequest
        The pull request number for this codespace.

    .PARAMETER RepositoryId
        The ID for a Repository.  Only applicable when creating a codespace for the current authenticated user.

    .PARAMETER Ref
        Git ref (typically a branch name) for this codespace

    .PARAMETER ClientIp
        IP for geo auto-detection when proxying a request.

    .PARAMETER DevContainerPath
        Path to devcontainer.json config to use for this codespace.

    .PARAMETER DisplayName
        Display name for this codespace

    .PARAMETER Geo
        The geographic area for this codespace.
        Assigned by IP if not provided.

    .PARAMETER Machine
        Machine type to use for this codespace.

    .PARAMETER NoMultipleRepoPermissions
        Whether to authorize requested permissions to other repos from devcontainer.json.

    .PARAMETER IdleRetentionPeriodMinutes
        Duration in minutes (up to 30 days) after codespace has gone idle in which it will be deleted.

    .PARAMETER TimeoutMinutes
        Time in minutes before codespace stops from inactivity.

    .PARAMETER WorkingDirectory
        Working directory for this codespace.

    .PARAMETER Wait
        If present will wait for the codespace to be available.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Codespace
        GitHub.Project
        GitHub.PullRequest
        GitHub.Repository

    .OUTPUTS
        GitHub.Codespace

    .EXAMPLE
        New-GitHubCodespace -RepositoryId 582779513

        Creates a new codespace for the current authenticated user in the specified repository.

    .EXAMPLE
        New-GitHubCodespace -RepositoryId 582779513 -PullRequest 508

        Creates a new codespace for the current authenticated user in the specified repository from a pull request.

    .EXAMPLE
        New-GitHubCodespace -OwnerName marykay -RepositoryName one

        Creates a codespace owned by the authenticated user in the specified repository.

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#create-a-codespace-for-the-authenticated-user

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#create-a-codespace-in-a-repository

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#create-a-codespace-from-a-pull-request
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'AuthenticatedUser')]
    [OutputType({ $script:GitHubCodespaceTypeName })]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1, and most of the others get dynamically accessed via $propertyMap.')]
    param(
        [Parameter(
            Mandatory,
            ParameterSetName = 'Elements')]
        [Parameter(
            Mandatory,
            ParameterSetName = 'ElementsPullRequest')]
        [string] $OwnerName,

        [Parameter(
            Mandatory,
            ParameterSetName = 'Elements')]
        [Parameter(
            Mandatory,
            ParameterSetName = 'ElementsPullRequest')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [Alias('PullRequestUrl')]
        [string] $Uri,

        [Parameter(ParameterSetName = 'AuthenticatedUser')]
        [Parameter(
            Mandatory,
            ParameterSetName = 'ElementsPullRequest')]
        [Alias('PullRequestNumber')]
        [int64] $PullRequest,

        [Parameter(
            Mandatory,
            ParameterSetName = 'AuthenticatedUser')]
        [Int64] $RepositoryId,

        [Parameter(ParameterSetName = 'AuthenticatedUser')]
        [Parameter(ParameterSetName = 'Elements')]
        [string] $Ref,

        [string] $ClientIp,

        [string] $DevContainerPath,

        [string] $DisplayName,

        [ValidateSet('EuropeWest', 'SoutheastAsia', 'UsEast', 'UsWest')]
        [string] $Geo,

        [string] $Machine,

        [switch] $NoMultipleRepoPermissions,

        [ValidateRange(0, 43200)]
        [int] $IdleRetentionPeriodMinutes,

        [ValidateRange(5, 240)]
        [int] $TimeoutMinutes,

        [string] $WorkingDirectory,

        [switch] $Wait,

        [string] $AccessToken
    )

    begin
    {
        Write-InvocationLog

        $propertyMap = @{
            ClientIp = 'client_ip'
            DevContainerPath = 'devcontainer_path'
            DisplayName = 'display_name'
            Geo = 'geo'
            Machine = 'machine'
            Ref = 'ref'
            IdleRetentionPeriodMinutes = 'retention_period_minutes'
            TimeoutMinutes = 'idle_timeout_minutes'
            WorkingDirectory = 'working_directory'
        }
    }

    process
    {
        $telemetryProperties = @{
            UsageType = $PSCmdlet.ParameterSetName
            Wait = $Wait.IsPresent
        }

        $uriFragment = [String]::Empty
        $description = [String]::Empty
        if ($PSCmdlet.ParameterSetName -eq 'AuthenticatedUser')
        {
            $uriFragment = 'user/codespaces'
            $description = 'Create a codespace for current authenticated user'
        }
        else
        {
            # ParameterSets: Elements, ElementsPullRequest, Uri
            # ElementsPullRequest prevents Ref for /repos/{owner}/{repo}/pulls/{pull_number}/codespaces
            $elements = Resolve-RepositoryElements
            $OwnerName = $elements.ownerName
            $RepositoryName = $elements.repositoryName

            $telemetryProperties['OwnerName'] = Get-PiiSafeString -PlainText $OwnerName
            $telemetryProperties['RepositoryName'] = Get-PiiSafeString -PlainText $RepositoryName

            if ($PSCmdlet.ParameterSetName -eq 'ElementsPullRequest')
            {
                $description = "Create a codespace from $OwnerName/$RepositoryName/pulls/$PullRequest"
                $telemetryProperties['PullRequest'] = $PullRequest
                $uriFragment = "repos/$OwnerName/$RepositoryName/pulls/$PullRequest/codespaces"
            }
            else
            {
                $description = "Create a codepace in $OwnerName/$RepositoryName"
                $uriFragment = "repos/$OwnerName/$RepositoryName/codespaces"
            }
        }

        $hashBody = @{
            multi_repo_permissions_opt_out = $NoMultipleRepoPermissions.IsPresent
        }

        # Map params to hashBody properties
        foreach ($p in $PSBoundParameters.GetEnumerator())
        {
            if ($propertyMap.ContainsKey($p.Key) -and (-not [string]::IsNullOrWhiteSpace($p.Value)))
            {
                $hashBody.Add($propertyMap[$p.Key], $p.Value)
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'AuthenticatedUser')
        {
            if ($PSBoundParameters.ContainsKey('PullRequest'))
            {
                $hashBody.Add('pull_request',
                    [PSCustomObject]@{
                        pull_request_number = $PullRequest
                        repository_id = $RepositoryId
                    }
                )
            }
            else
            {
                $hashBody.Add('repository_id', $RepositoryId)
            }
        }

        $params = @{
            UriFragment = $uriFragment
            Body = (ConvertTo-Json -InputObject $hashBody -Depth 5)
            Method = 'Post'
            Description = $description
            AccessToken = $AccessToken
            TelemetryEventName = $MyInvocation.MyCommand.Name
            TelemetryProperties = $telemetryProperties
        }

        if (-not $PSCmdlet.ShouldProcess($RepositoryName, 'Create GitHub Codespace'))
        {
            return
        }

        $result = (Invoke-GHRestMethod @params | Add-GitHubCodespaceAdditionalProperties)

        if ($Wait.IsPresent)
        {
            $waitParams = @{
                CodespaceName = $result.CodespaceName
                AccessToken = $AccessToken
            }

            $result = Wait-GitHubCodespaceAction @waitParams
        }

        return $result
    }
}

filter Remove-GitHubCodespace
{
    <#
    .SYNOPSIS
        Remove a Codespace.

    .DESCRIPTION
        Remove a Codespace.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER OrganizationName
        Name of the Organization.

    .PARAMETER UserName
        The handle for the GitHub user account.

    .PARAMETER CodespaceName
        Name of the Codespace.

    .PARAMETER Force
        If this switch is specified, you will not be prompted for confirmation of command execution.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Codespace

    .OUTPUTS
        None

    .EXAMPLE
        Get-GitHubCodespace -Name vercellone-effective-goggles-qrv997q6j9929jx8 | Remove-GitHubCodespace

    .EXAMPLE
        Remove-GitHubCodespace -Name vercellone-effective-goggles-qrv997q6j9929jx8

    .EXAMPLE
        Remove-GitHubCodespace -OrganizationName myorg -UserName jetsong -Name jetsong-button-masher-zzz788y6j8288xp1

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#delete-a-codespace-for-the-authenticated-user

    .LINK
        https://docs.github.com/en/rest/codespaces/organizations?apiVersion=2022-11-28#delete-a-codespace-from-the-organization
#>
    [CmdletBinding(
        DefaultParameterSetName = 'AuthenticatedUser',
        SupportsShouldProcess,
        ConfirmImpact = 'High')]
    [Alias('Delete-GitHubCodespace')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Organization')]
        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Organization')]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string] $CodespaceName,

        [switch] $Force,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{
        CodespaceName = Get-PiiSafeString -PlainText $CodespaceName
    }

    $uriFragment = [String]::Empty
    if ($PSCmdlet.ParameterSetName -eq 'AuthenticatedUser')
    {
        $uriFragment = "user/codespaces/$CodespaceName"
    }
    else
    {
        $uriFragment = "orgs/$OrganizationName/members/$UserName/codespaces/$CodespaceName"
    }

    $params = @{
        UriFragment = $uriFragment
        Method = 'Delete'
        Description = "Remove Codespace $CodespaceName"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($CodespaceName, "Remove Codespace $CodespaceName"))
    {
        return
    }

    Invoke-GHRestMethod @params | Out-Null
}

filter Start-GitHubCodespace
{
    <#
    .SYNOPSIS
        Start a Codespace for the currently authenticated user.

    .DESCRIPTION
        Start a Codespace for the currently authenticated user.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER CodespaceName
        Name of the Codespace.

    .PARAMETER Wait
        If present will wait for the codespace to start.

    .PARAMETER PassThru
        Returns the start action result.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Codespace

    .OUTPUTS
        GitHub.Codespace

    .EXAMPLE
        Start-GitHubCodespace -Name vercellone-effective-goggles-qrv997q6j9929jx8

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#start-a-codespace-for-the-authenticated-user

    .NOTES
        You must authenticate using an access token with the codespace scope to use this endpoint.
        GitHub Apps must have write access to the codespaces_lifecycle_admin repository permission to use this endpoint.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'Low')]
    [OutputType({ $script:GitHubCodespaceTypeName })]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string] $CodespaceName,

        [switch] $Wait,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{
        CodespaceName = Get-PiiSafeString -PlainText $CodespaceName
        Wait = $Wait.IsPresent
    }

    $params = @{
        UriFragment = "user/codespaces/$CodespaceName/start"
        Method = 'Post'
        Description = "Start Codespace $CodespaceName"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    if (-not $PSCmdlet.ShouldProcess($CodespaceName, "Start Codespace $CodespaceName"))
    {
        return
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubCodespaceAdditionalProperties)

    if ($Wait.IsPresent)
    {
        $waitParams = @{
            CodespaceName = $CodespaceName
            AccessToken = $AccessToken
        }

        $result = Wait-GitHubCodespaceAction @waitParams
    }

    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Stop-GitHubCodespace
{
    <#
    .SYNOPSIS
        Stop a Codespace for the currently authenticated user.

    .DESCRIPTION
        Stop a Codespace for the currently authenticated user.

        The Git repo for this module can be found here: http://aka.ms/PowerShellForGitHub

    .PARAMETER CodespaceName
        Name of the Codespace.

    .PARAMETER Wait
        If present will wait for the codespace to stop.

    .PARAMETER PassThru
        Returns the updated GitHub Issue.  By default, this cmdlet does not generate any output.
        You can use "Set-GitHubConfiguration -DefaultPassThru" to control the default behavior
        of this switch.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Codespace

    .OUTPUTS
        GitHub.Codespace

    .EXAMPLE
        Stop-GitHubCodespace -Name vercellone-effective-goggles-qrv997q6j9929jx8

    .LINK
        https://docs.github.com/en/rest/codespaces/codespaces?apiVersion=2022-11-28#stop-a-codespace-for-the-authenticated-user

    .NOTES
        You must authenticate using an access token with the codespace scope to use this endpoint.
        GitHub Apps must have write access to the codespaces_lifecycle_admin repository permission to use this endpoint.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        ConfirmImpact = 'Low')]
    [OutputType({ $script:GitHubCodespaceTypeName })]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'PassThru is accessed indirectly via Resolve-ParameterWithDefaultConfigurationValue')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string] $CodespaceName,

        [switch] $Wait,

        [switch] $PassThru,

        [string] $AccessToken
    )

    Write-InvocationLog

    $telemetryProperties = @{
        CodespaceName = Get-PiiSafeString -PlainText $CodespaceName
        Wait = $Wait.IsPresent
    }

    $params = @{
        UriFragment = "user/codespaces/$CodespaceName/stop"
        Method = 'Post'
        Description = "Stop Codespace $CodespaceName"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    if (-not $PSCmdlet.ShouldProcess($CodespaceName, "Stop Codespace $CodespaceName"))
    {
        return
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubCodespaceAdditionalProperties)

    if ($Wait.IsPresent)
    {
        $waitParams = @{
            CodespaceName = $CodespaceName
            AccessToken = $AccessToken
        }

        $result = Wait-GitHubCodespaceAction @waitParams
    }

    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

function Wait-GitHubCodespaceAction
{
    <#
    .SYNOPSIS
        Wait for a Codespace start or stop action.

    .PARAMETER CodespaceName
        Name of the Codespace.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Codespace

    .OUTPUTS
        GitHub.Codespace

    .EXAMPLE
        Wait-GitHubCodespace -Name vercellone-effective-goggles-qrv997q6j9929jx8

     .NOTES
        Internal-only helper method.
#>
    [CmdletBinding()]
    [OutputType({ $script:GitHubCodespaceTypeName })]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [string] $CodespaceName,

        [string] $AccessToken
    )

    begin
    {
        $sleepSeconds = $(Get-GitHubConfiguration -Name 'StateChangeDelaySeconds')

        # 2s minimum
        if ($sleepSeconds -lt 2)
        {
            $sleepSeconds = 2
        }
    }

    process
    {
        Write-InvocationLog

        # Expected states for happy paths:
        # Shutdown  > Queued > Starting     > Available
        # Available > Queued > ShuttingDown > ShutDown
        #
        # To allow for unexpected results, loop until the state is something other than Queued or *ing
        # All known states:
        # *ings: Awaiting, Exporting, Provisioning, Rebuilding, ShuttingDown, Starting, Updating
        # Other: Archived, Available, Created, Deleted, Failed, Moved, Queued, Shutdown, Unavailable, Unknown
        do
        {
            Start-Sleep -Seconds $sleepSeconds
            $codespace = (Get-GitHubCodespace @PSBoundParameters)
            Write-Log -Message "[$CodespaceName] state is $($codespace.state)" -Level Verbose
        }
        until ($codespace.state -notmatch 'Queued|ing')

        return $codespace
    }
}

filter Add-GitHubCodespaceAdditionalProperties
{
    <#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Repository objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Codespace
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification = "Internal helper that is definitely adding more than one property.")]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubCodespaceTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            if ($item.name)
            {
                Add-Member -InputObject $item -Name 'CodespaceUrl' -Value "user/codespaces/$($item.name)" -MemberType NoteProperty -Force
                Add-Member -InputObject $item -Name 'CodespaceName' -Value $item.name -MemberType NoteProperty -Force
            }

            if ($null -ne $item.billable_owner)
            {
                $null = Add-GitHubUserAdditionalProperties -InputObject $item.billable_owner
            }

            if ($null -ne $item.owner)
            {
                $null = Add-GitHubUserAdditionalProperties -InputObject $item.owner
            }

            if ($null -ne $item.repository)
            {
                $null = Add-GitHubRepositoryAdditionalProperties -InputObject $item.repository
                Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $item.repository.RepositoryUrl -MemberType NoteProperty -Force
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIInxAYJKoZIhvcNAQcCoIIntTCCJ7ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCATbu4hmnvSMQdl
# 7SlfbpIbhFnV12sztEFN72izDEQLN6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaQwghmgAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBncIf/0vv+U4N44KNI9OgxV
# B+ecASk0kWfAmfeQStzyMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQC1isyIAO3uIOjHFpmT69Dz9QVxpXVWEK3oY1F6jvv+LTSgTeTV90fj
# s3ojvEvCHQGGGT8jetnGByFS6LXL6PWYouu6VxuiTrB8VEaRANYCANga0M+MG3tG
# E93m7ptkiuT+c+wWDV49XbDHPjBv2oXm7CyOcuJED+ABeVIai+jIf3Vf7XDJ09B+
# ucvc5fscX/nbrRGOLs9ysxf4HnzqxdKJGnTaxlXcMtBJBfKAo3/dwjlEltaFdtTB
# MOoRBMeruVYclsnNXRhht8j03znxoSYrUI0CIfiC5DV/sTTeZvVthQys7RA/rXBl
# Tha+3dFBAHPbAHTT9uk+v3pZlgHQdEiIoYIXLDCCFygGCisGAQQBgjcDAwExghcY
# MIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEID/vtJJhW2cballkl51OLbQAjSdYyQZE94Ob8aDz//BVAgZlVuY6
# XQ0YEzIwMjMxMTIxMTczNTE1LjU3OVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAeKZmZXx3OMg6wABAAAB4jAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MzEwMTIxOTA3MjVaFw0yNTAxMTAxOTA3MjVaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEt
# NEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtWO1mFX6QWZvxwpCmDab
# OKwOVEj3vwZvZqYa9sCYJ3TglUZ5N79AbMzwptCswOiXsMLuNLTcmRys+xaL1alX
# CwhyRFDwCRfWJ0Eb0eHIKykBq9+6/PnmSGXtus9DHsf31QluwTfAyamYlqw9amAX
# TnNmW+lZANQsNwhjKXmVcjgdVnk3oxLFY7zPBaviv3GQyZRezsgLEMmvlrf1JJ48
# AlEjLOdohzRbNnowVxNHMss3I8ETgqtW/UsV33oU3EDPCd61J4+DzwSZF7OvZPcd
# MUSWd4lfJBh3phDt4IhzvKWVahjTcISD2CGiun2pQpwFR8VxLhcSV/cZIRGeXMmw
# ruz9kY9Th1odPaNYahiFrZAI6aSCM6YEUKpAUXAWaw+tmPh5CzNjGrhzgeo+dS7i
# FPhqqm9Rneog5dt3JTjak0v3dyfSs9NOV45Sw5BuC+VF22EUIF6nF9vqduynd9xl
# o8F9Nu1dVryctC4wIGrJ+x5u6qdvCP6UdB+oqmK+nJ3soJYAKiPvxdTBirLUfJid
# K1OZ7hP28rq7Y78pOF9E54keJKDjjKYWP7fghwUSE+iBoq802xNWbhBuqmELKSev
# AHKqisEIsfpuWVG0kwnCa7sZF1NCwjHYcwqqmES2lKbXPe58BJ0+uA+GxAhEWQdk
# a6KEvUmOPgu7cJsCaFrSU6sCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBREhA4R2r7t
# B2yWm0mIJE2leAnaBTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA5FREMatVFNue
# 6V+yDZxOzLKHthe+FVTs1kyQhMBBiwUQ9WC9K+ILKWvlqneRrvpjPS3/qXG5zMjr
# Du1eryfhbFRSByPnACGc2iuGcPyWNiptyTft+CBgrf7ATAuE/U8YLm29crTFiiZT
# WdT6Vc7L1lGdKEj8dl0WvDayuC2xtajD04y4ANLmWDuiStdrZ1oI4afG5oPUg77r
# kTuq/Y7RbSwaPsBZ06M12l7E+uykvYoRw4x4lWaST87SBqeEXPMcCdaO01ad5TXV
# ZDoHG/w6k3V9j3DNCiLJyC844kz3eh3nkQZ5fF8Xxuh8tWVQTfMiKShJ537yzrU0
# M/7H1EzJrabAr9izXF28OVlMed0gqyx+a7e+79r4EV/a4ijJxVO8FCm/92tEkPrx
# 6jjTWaQJEWSbL/4GZCVGvHatqmoC7mTQ16/6JR0FQqZf+I5opnvm+5CDuEKIEDnE
# iblkhcNKVfjvDAVqvf8GBPCe0yr2trpBEB5L+j+5haSa+q8TwCrfxCYqBOIGdZJL
# +5U9xocTICufIWHkb6p4IaYvjgx8ScUSHFzexo+ZeF7oyFKAIgYlRkMDvffqdAPx
# +fjLrnfgt6X4u5PkXlsW3SYvB34fkbEbM5tmab9zekRa0e/W6Dt1L8N+tx3WyfYT
# iCThbUvWN1EFsr3HCQybBj4Idl4xK8EwggdxMIIFWaADAgECAhMzAAAAFcXna54C
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
# ahC0HVUzWLOhcGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAWm5lp+nRuekl0iF+IHV3ylOiGb6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6QdTFzAiGA8yMDIzMTEyMjAwMDIzMVoYDzIwMjMxMTIzMDAwMjMxWjB3MD0G
# CisGAQQBhFkKBAExLzAtMAoCBQDpB1MXAgEAMAoCAQACAiGvAgH/MAcCAQACAhGB
# MAoCBQDpCKSXAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAGLDDSs7ArTd0
# olj8BJvSyJmIjNOyanyVf1C6gfXu/hMi9XcprQDUPpjDaSRCI+owo4eXqxSzddy9
# RmEcR2lk1EvxRYxhW8eKIOly1N3OjnOTm29ohjUt3s7OI4dfp9/g7NsemHCMxpT6
# cGAppGUCwcOEk4IEsxQZlgV7MzE9Mm0xggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAeKZmZXx3OMg6wABAAAB4jANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCBIkJQtJCBwdNEeZi2ppQkALslLe0er/+/03NtydOa85TCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EICuJKkoQ/Sa4xsFQRM4Ogvh3ktToj9uO5whm
# Q4kIj3//MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAHimZmV8dzjIOsAAQAAAeIwIgQgqvzaLYxDTBsl41dBF0nCwsGccg85uorAv7zS
# P5sykSEwDQYJKoZIhvcNAQELBQAEggIAE7uiu5vZOVNoC/xNp8d0LVkOvmd864Gq
# 7l4201RryGgROiou+s5a7HqmRnRtHk3HjyTTGwzR5K+LpdEgPwVVPXXUp1eccOF/
# OVaMeddwVjXIoeiRJLWjTTUVFOv3KTg4UcpjsaHb8RKn9uHDf1nxJeaHcv8crSy/
# 47ioDdu580rgEZl4T5cw2LqL2BnUNeB6SDdp/w3xydwPcgQzChLbx4/30TI7FDOa
# 5Fk7l/iJ4K6yxs7+hXelpxciiTTbMZ2sEbBgi2kMlMey8EHmCEhlp75rZ3RlZFzs
# DtY986cm7SbvSXL4HhBLKZKxHxteVL7Ipt6EpVXijeIY6+Ydt4YeqCunDA+locpq
# Hcj45dyp2+s6ZtwcTX24/3bjU08FCy23gSAbnsW7clBWoAxoiHcM3Uttqb1QXc9T
# /j9RYP5YzOxZ1E2FyI+GPohoNc43YYKcSppg2mwZgPg4CFIfYOzTcbUPqKd4vryV
# QfeE8Wj8AEF846I5NZ+2OhBrtWUfWLmOv9RD+HlhPeDgeKXzZaUUBAazSlmN8OCM
# Oh+KyAb755PmrAHRkxVxr3KgeJIgzJv63vOciDhwRYHrr7wvZeKO8gzWWAS5YhBF
# 0w3o1JchHDB082GJ/+NsjO/onuh9Y+U1XPfwPkGR7Uwtdm4huBiiPeyz0Mr83Y+y
# TKhEh+vg0/k=
# SIG # End signature block
