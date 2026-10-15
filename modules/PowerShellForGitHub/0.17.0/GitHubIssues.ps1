# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubIssueTypeName = 'GitHub.Issue'
 }.GetEnumerator() | ForEach-Object {
     Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
 }

filter Get-GitHubIssue
{
<#
    .SYNOPSIS
        Retrieve Issues from GitHub.

    .DESCRIPTION
        Retrieve Issues from GitHub.

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
        The organization whose issues should be retrieved.

    .PARAMETER RepositoryType
        all: Retrieve issues across owned, member and org repositories
        ownedAndMember: Retrieve issues across owned and member repositories

    .PARAMETER Issue
        The number of specific Issue to retrieve.  If not supplied, will return back all
        Issues for this Repository that match the specified criteria.

    .PARAMETER IgnorePullRequests
        GitHub treats Pull Requests as Issues.  Specify this switch to skip over any
        Issue that is actually a Pull Request.

    .PARAMETER Filter
        Indicates the type of Issues to return:
        assigned: Issues assigned to the authenticated user.
        created: Issues created by the authenticated user.
        mentioned: Issues mentioning the authenticated user.
        subscribed: Issues the authenticated user has been subscribed to updates for.
        all: All issues the authenticated user can see, regardless of participation or creation.

    .PARAMETER State
        Indicates the state of the issues to return.

    .PARAMETER Label
        The label (or labels) that returned Issues should have.

    .PARAMETER Sort
        The property to sort the returned Issues by.

    .PARAMETER Direction
        The direction of the sort.

    .PARAMETER Since
        If specified, returns only issues updated at or after this time.

    .PARAMETER MilestoneType
        If specified, indicates what milestone Issues must be a part of to be returned:
          specific: Only issues with the milestone specified via the Milestone parameter will be returned.
          all: All milestones will be returned.
          none: Only issues without milestones will be returned.

    .PARAMETER MilestoneNumber
        Only issues with this milestone will be returned.

    .PARAMETER AssigneeType
        If specified, indicates who Issues must be assigned to in order to be returned:
          specific: Only issues assigned to the user specified by the Assignee parameter will be returned.
          all: Issues assigned to any user will be returned.
          none: Only issues without an assigned user will be returned.

    .PARAMETER Assignee
        Only issues assigned to this user will be returned.

    .PARAMETER Creator
        Only issues created by this specified user will be returned.

    .PARAMETER Mentioned
        Only issues that mention this specified user will be returned.

    .PARAMETER MediaType
        The format in which the API will return the body of the issue.

        Raw  - Return the raw markdown body.
               Response will include body.
               This is the default if you do not pass any specific media type.
        Text - Return a text only representation of the markdown body.
               Response will include body_text.
        Html - Return HTML rendered from the body's markdown.
               Response will include body_html.
        Full - Return raw, text and HTML representations.
               Response will include body, body_text, and body_html.

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
        GitHub.User

    .OUTPUTS
        GitHub.Issue

    .EXAMPLE
        Get-GitHubIssue -OwnerName microsoft -RepositoryName PowerShellForGitHub -State Open

        Gets all the currently open issues in the microsoft\PowerShellForGitHub repository.

    .EXAMPLE
        Get-GitHubIssue -OwnerName microsoft -RepositoryName PowerShellForGitHub -State All -Assignee Octocat

        Gets every issue in the microsoft\PowerShellForGitHub repository that is assigned to Octocat.
#>
    [CmdletBinding(DefaultParameterSetName = 'Elements')]
    [OutputType({$script:GitHubIssueTypeName})]
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
        [string] $OrganizationName,

        [ValidateSet('All', 'OwnedAndMember')]
        [string] $RepositoryType = 'All',

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('IssueNumber')]
        [int64] $Issue,

        [switch] $IgnorePullRequests,

        [ValidateSet('Assigned', 'Created', 'Mentioned', 'Subscribed', 'All')]
        [string] $Filter = 'Assigned',

        [ValidateSet('Open', 'Closed', 'All')]
        [string] $State = 'Open',

        [string[]] $Label,

        [ValidateSet('Created', 'Updated', 'Comments')]
        [string] $Sort = 'Created',

        [ValidateSet('Ascending', 'Descending')]
        [string] $Direction = 'Descending',

        [DateTime] $Since,

        [ValidateSet('Specific', 'All', 'None')]
        [string] $MilestoneType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [int64] $MilestoneNumber,

        [ValidateSet('Specific', 'All', 'None')]
        [string] $AssigneeType,

        [string] $Assignee,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('UserName')]
        [string] $Creator,

        [string] $Mentioned,

        [ValidateSet('Raw', 'Text', 'Html', 'Full')]
        [string] $MediaType ='Raw',

        [string] $AccessToken
    )

    Write-InvocationLog

    # Intentionally disabling validation here because parameter sets exist that do not require
    # an OwnerName and RepositoryName.  Therefore, we will do futher parameter validation further
    # into the function.
    $elements = Resolve-RepositoryElements -DisableValidation
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        'OwnerName' = (Get-PiiSafeString -PlainText $OwnerName)
        'RepositoryName' = (Get-PiiSafeString -PlainText $RepositoryName)
        'OrganizationName' = (Get-PiiSafeString -PlainText $OrganizationName)
        'ProvidedIssue' = $PSBoundParameters.ContainsKey('Issue')
    }

    $uriFragment = [String]::Empty
    $description = [String]::Empty
    if ($OwnerName -xor $RepositoryName)
    {
        $message = 'You must specify BOTH Owner Name and Repository Name when one is provided.'
        Write-Log -Message $message -Level Error
        throw $message
    }

    if (-not [String]::IsNullOrEmpty($RepositoryName))
    {
        $uriFragment = "/repos/$OwnerName/$RepositoryName/issues"
        $description = "Getting issues for $RepositoryName"
        if ($PSBoundParameters.ContainsKey('Issue'))
        {
            $uriFragment = $uriFragment + "/$Issue"
            $description = "Getting issue $Issue for $RepositoryName"
        }
    }
    elseif (-not [String]::IsNullOrEmpty($OrganizationName))
    {
        $uriFragment = "/orgs/$OrganizationName/issues"
        $description = "Getting issues for $OrganizationName"
    }
    elseif ($RepositoryType -eq 'All')
    {
        $uriFragment = "/issues"
        $description = "Getting issues across owned, member and org repositories"
    }
    elseif ($RepositoryType -eq 'OwnedAndMember')
    {
        $uriFragment = "/user/issues"
        $description = "Getting issues across owned and member repositories"
    }
    else
    {
        throw "Parameter set not supported."
    }

    $directionConverter = @{
        'Ascending' = 'asc'
        'Descending' = 'desc'
    }

    $getParams = @(
        "filter=$($Filter.ToLower())",
        "state=$($State.ToLower())",
        "sort=$($Sort.ToLower())",
        "direction=$($directionConverter[$Direction])"
    )

    if ($PSBoundParameters.ContainsKey('Label'))
    {
        $getParams += "labels=$($Label -join ',')"
    }

    if ($PSBoundParameters.ContainsKey('Since'))
    {
        $getParams += "since=$($Since.ToUniversalTime().ToString('o'))"
    }

    if ($PSBoundParameters.ContainsKey('Mentioned'))
    {
        $getParams += "mentioned=$Mentioned"
    }

    if ($PSBoundParameters.ContainsKey('MilestoneType'))
    {
        if ($MilestoneType -eq 'All')
        {
            $getParams += 'mentioned=*'
        }
        elseif ($MilestoneType -eq 'None')
        {
            $getParams += 'mentioned=none'
        }
        elseif ($PSBoundParameters.ContainsKey('$MilestoneNumber'))
        {
            $message = "MilestoneType was set to [$MilestoneType], but no value for MilestoneNumber was provided."
            Write-Log -Message $message -Level Error
            throw $message
        }
    }

    if ($PSBoundParameters.ContainsKey('MilestoneNumber'))
    {
        $getParams += "milestone=$MilestoneNumber"
    }

    if ($PSBoundParameters.ContainsKey('AssigneeType'))
    {
        if ($AssigneeType -eq 'all')
        {
            $getParams += 'assignee=*'
        }
        elseif ($AssigneeType -eq 'none')
        {
            $getParams += 'assignee=none'
        }
        elseif ([String]::IsNullOrEmpty($Assignee))
        {
            $message = "AssigneeType was set to [$AssigneeType], but no value for Assignee was provided."
            Write-Log -Message $message -Level Error
            throw $message
        }
    }

    if ($PSBoundParameters.ContainsKey('Assignee'))
    {
        $getParams += "assignee=$Assignee"
    }

    if ($PSBoundParameters.ContainsKey('Creator'))
    {
        $getParams += "creator=$Creator"
    }

    if ($PSBoundParameters.ContainsKey('Mentioned'))
    {
        $getParams += "mentioned=$Mentioned"
    }

    $params = @{
        'UriFragment' = $uriFragment + '?' +  ($getParams -join '&')
        'Description' = $description
        'AcceptHeader' = (Get-MediaAcceptHeader -MediaType $MediaType -AsJson -AcceptHeader $symmetraAcceptHeader)
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    try
    {
        $result = (Invoke-GHRestMethodMultipleResult @params | Add-GitHubIssueAdditionalProperties)

        if ($IgnorePullRequests)
        {
            return ($result | Where-Object { $null -eq (Get-Member -InputObject $_ -Name pull_request) })
        }
        else
        {
            return $result
        }

    }
    finally {}
}

filter Get-GitHubIssueTimeline
{
<#
    .SYNOPSIS
        Retrieves various events that occur around an issue or pull request on GitHub.

    .DESCRIPTION
        Retrieves various events that occur around an issue or pull request on GitHub.

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
        The Issue to get the timeline for.

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
        GitHub.Event

    .EXAMPLE
        Get-GitHubIssueTimeline -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 24
#>
    [CmdletBinding(DefaultParameterSetName = 'Elements')]
    [OutputType({$script:GitHubEventTypeName})]
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

    $params = @{
        'UriFragment' = "repos/$OwnerName/$RepositoryName/issues/$Issue/timeline"
        'Description' = "Getting timeline for Issue #$Issue in $RepositoryName"
        'AcceptHeader' = $script:mockingbirdAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubEventAdditionalProperties)
}

filter New-GitHubIssue
{
<#
    .SYNOPSIS
        Create a new Issue on GitHub.

    .DESCRIPTION
        Create a new Issue on GitHub.

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
        The title of the issue

    .PARAMETER Body
        The contents of the issue

    .PARAMETER Assignee
        Login(s) for Users to assign to the issue.

    .PARAMETER Milestone
        The number of the milestone to associate this issue with.

    .PARAMETER Label
        Label(s) to associate with this issue.

    .PARAMETER MediaType
        The format in which the API will return the body of the issue.

        Raw  - Return the raw markdown body.
               Response will include body.
               This is the default if you do not pass any specific media type.
        Text - Return a text only representation of the markdown body.
               Response will include body_text.
        Html - Return HTML rendered from the body's markdown.
               Response will include body_html.
        Full - Return raw, text and HTML representations.
               Response will include body, body_text, and body_html.

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
        GitHub.Issue

    .EXAMPLE
        New-GitHubIssue -OwnerName microsoft -RepositoryName PowerShellForGitHub -Title 'Test Issue'
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    [OutputType({$script:GitHubIssueTypeName})]
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

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Title,

        [string] $Body,

        [string[]] $Assignee,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('MilestoneNumber')]
        [int64] $Milestone,

        [string[]] $Label,

        [ValidateSet('Raw', 'Text', 'Html', 'Full')]
        [string] $MediaType ='Raw',

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

    $hashBody = @{
        'title' = $Title
    }

    if ($PSBoundParameters.ContainsKey('Body')) { $hashBody['body'] = $Body }
    if ($PSBoundParameters.ContainsKey('Assignee')) { $hashBody['assignees'] = @($Assignee) }
    if ($PSBoundParameters.ContainsKey('Milestone')) { $hashBody['milestone'] = $Milestone }
    if ($PSBoundParameters.ContainsKey('Label')) { $hashBody['labels'] = @($Label) }

    if (-not $PSCmdlet.ShouldProcess($Title, 'Create GitHub Issue'))
    {
        return
    }

    $params = @{
        'UriFragment' = "/repos/$OwnerName/$RepositoryName/issues"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Post'
        'Description' = "Creating new Issue ""$Title"" on $RepositoryName"
        'AcceptHeader' = (Get-MediaAcceptHeader -MediaType $MediaType -AsJson -AcceptHeader $symmetraAcceptHeader)
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethod @params | Add-GitHubIssueAdditionalProperties)
}

filter Set-GitHubIssue
{
<#
    .SYNOPSIS
        Updates an Issue on GitHub.

    .DESCRIPTION
        Updates an Issue on GitHub.

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
        The issue to be updated.

    .PARAMETER Title
        The title of the issue

    .PARAMETER Body
        The contents of the issue

    .PARAMETER Assignee
        Login(s) for Users to assign to the issue.
        Provide an empty array to clear all existing assignees.

    .PARAMETER MilestoneNumber
        The number of the milestone to associate this issue with.
        Set to 0/$null to remove current.

    .PARAMETER Label
        Label(s) to associate with this issue.
        Provide an empty array to clear all existing labels.

    .PARAMETER State
        Modify the current state of the issue.

    .PARAMETER MediaType
        The format in which the API will return the body of the issue.

        Raw  - Return the raw markdown body.
               Response will include body.
               This is the default if you do not pass any specific media type.
        Text - Return a text only representation of the markdown body.
               Response will include body_text.
        Html - Return HTML rendered from the body's markdown.
               Response will include body_html.
        Full - Return raw, text and HTML representations.
               Response will include body, body_text, and body_html.

    .PARAMETER PassThru
        Returns the updated Issue.  By default, this cmdlet does not generate any output.
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
        GitHub.Issue

    .EXAMPLE
        Set-GitHubIssue -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 4 -Title 'Test Issue' -State Closed
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
    [OutputType({$script:GitHubIssueTypeName})]
    [Alias('Update-GitHubIssue')] # Non-standard usage of the Update verb, but done to avoid a breaking change post 0.14.0
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

        [string] $Title,

        [string] $Body,

        [string[]] $Assignee,

        [int64] $MilestoneNumber,

        [string[]] $Label,

        [ValidateSet('Open', 'Closed')]
        [string] $State,

        [ValidateSet('Raw', 'Text', 'Html', 'Full')]
        [string] $MediaType ='Raw',

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

    $hashBody = @{}

    if ($PSBoundParameters.ContainsKey('Title')) { $hashBody['title'] = $Title }
    if ($PSBoundParameters.ContainsKey('Body')) { $hashBody['body'] = $Body }
    if ($PSBoundParameters.ContainsKey('Assignee')) { $hashBody['assignees'] = @($Assignee) }
    if ($PSBoundParameters.ContainsKey('Label')) { $hashBody['labels'] = @($Label) }
    if ($PSBoundParameters.ContainsKey('State')) { $hashBody['state'] = $State.ToLower() }
    if ($PSBoundParameters.ContainsKey('MilestoneNumber'))
    {
        $hashBody['milestone'] = $MilestoneNumber
        if ($MilestoneNumber -in (0, $null))
        {
            $hashBody['milestone'] = $null
        }
    }

    if (-not $PSCmdlet.ShouldProcess($Issue, 'Update GitHub Issue'))
    {
        return
    }

    $params = @{
        'UriFragment' = "/repos/$OwnerName/$RepositoryName/issues/$Issue"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Patch'
        'Description' = "Updating Issue #$Issue on $RepositoryName"
        'AcceptHeader' = (Get-MediaAcceptHeader -MediaType $MediaType -AsJson -AcceptHeader $symmetraAcceptHeader)
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    $result = (Invoke-GHRestMethod @params | Add-GitHubIssueAdditionalProperties)
    if (Resolve-ParameterWithDefaultConfigurationValue -Name PassThru -ConfigValueName DefaultPassThru)
    {
        return $result
    }
}

filter Lock-GitHubIssue
{
<#
    .SYNOPSIS
        Lock an Issue or Pull Request conversation on GitHub.

    .DESCRIPTION
        Lock an Issue or Pull Request conversation on GitHub.

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
        The issue to be locked.

    .PARAMETER Reason
        The reason for locking the issue or pull request conversation.

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
        Lock-GitHubIssue -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 4 -Title 'Test Issue' -Reason Spam
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName='Elements')]
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

        [ValidateSet('OffTopic', 'TooHeated', 'Resolved', 'Spam')]
        [string] $Reason,

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

    $hashBody = @{
        'locked' = $true
    }

    if ($PSBoundParameters.ContainsKey('Reason'))
    {
        $reasonConverter = @{
            'OffTopic' = 'off-topic'
            'TooHeated' = 'too heated'
            'Resolved' = 'resolved'
            'Spam' = 'spam'
        }

        $telemetryProperties['Reason'] = $Reason
        $hashBody['lock_reason'] = $reasonConverter[$Reason]
    }

    if (-not $PSCmdlet.ShouldProcess($Issue, 'Lock GitHub Issue'))
    {
        return
    }

    $params = @{
        'UriFragment' = "/repos/$OwnerName/$RepositoryName/issues/$Issue/lock"
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Put'
        'Description' = "Locking Issue #$Issue on $RepositoryName"
        'AcceptHeader' = $script:sailorVAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Unlock-GitHubIssue
{
<#
    .SYNOPSIS
        Unlocks an Issue or Pull Request conversation on GitHub.

    .DESCRIPTION
        Unlocks an Issue or Pull Request conversation on GitHub.

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
        The issue to be unlocked.

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
        Unlock-GitHubIssue -OwnerName microsoft -RepositoryName PowerShellForGitHub -Issue 4
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

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('IssueNumber')]
        [int64] $Issue,

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

    if (-not $PSCmdlet.ShouldProcess($Issue, 'Unlock GitHub Issue'))
    {
        return
    }

    $params = @{
        'UriFragment' = "/repos/$OwnerName/$RepositoryName/issues/$Issue/lock"
        'Method' = 'Delete'
        'Description' = "Unlocking Issue #$Issue on $RepositoryName"
        'AcceptHeader' = $script:sailorVAcceptHeader
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return Invoke-GHRestMethod @params
}

filter Add-GitHubIssueAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Issue objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Issue
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
        [string] $TypeName = $script:GitHubIssueTypeName
    )

    foreach ($item in $InputObject)
    {
        # Pull requests are _also_ issues.  A pull request that is retrieved through the
        # Issue endpoint will also have a 'pull_request' property.  Let's make sure that
        # we mark it up appropriately.
        if ($null -ne $item.pull_request)
        {
            $null = Add-GitHubPullRequestAdditionalProperties -InputObject $item
            Write-Output $item
            continue
        }

        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $elements = Split-GitHubUri -Uri $item.html_url
            $repositoryUrl = Join-GitHubUri @elements
            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'IssueId' -Value $item.id -MemberType NoteProperty -Force
            Add-Member -InputObject $item -Name 'IssueNumber' -Value $item.number -MemberType NoteProperty -Force

            @('assignee', 'assignees', 'user') |
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

            if ($null -ne $item.closed_by)
            {
                $null = Add-GitHubUserAdditionalProperties -InputObject $item.closed_by
            }

            if ($null -ne $item.repository)
            {
                $null = Add-GitHubRepositoryAdditionalProperties -InputObject $item.repository
            }
        }

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfeeyfyIWbRgCO
# hX3kpTB4bH39KGGMlz5B9r+T/2NK9KCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGmmy+g2lk0Qhn6oPRNMNCMX
# XKCpiWXMlq0SV8Oa7C4jMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB5dNbIVSETOoLenulXMSStQ9Cn9NDG9Uv/gwcOcilAELI9NxFmv5mw
# gWjJ59Mw2Og1Vq5lq3hhFLC6RjIuEZSCGZdR5At8siCEm8Hpix/39TZH/nLr0Scv
# oY56plJwaj5C8NyP+uq8MCnl22h2fASL8FzHYWGS/Uy5Z5BGyowYdZ76dq7XVSLy
# v1uegsuCZ8eOKSPcH7DO97CzlcEpeg1gUXRDhtTlrQswykFT8Nk5hHV/V+YHw+LT
# iGTwaozdoy4lHtWitoc/7U5fbo9B4hssrm49G6NCM8BzxOg3oKs6EzmFPuXJnjIe
# ZSCvLNRFTZgIqSqdNm+aaR8kd8cZVuLDoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILbkLJ3H9qKTmt+D1PKhaDxP48zRUARfXwvE01yXRjuAAgZlVtVS
# yskYEzIwMjMxMTIxMTczNTM1LjA0M1owBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjozMzAz
# LTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaCCEe0wggcgMIIFCKADAgECAhMzAAABzIal3Dfr2WEtAAEAAAHMMA0GCSqGSIb3
# DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDUyNTE5
# MTIwMVoXDTI0MDIwMTE5MTIwMVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjozMzAzLTA1RTAtRDk0NzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAMyxIgXx702YRz7zc1VkaBZZmL/AFi3zOHEB9IYz
# vHDsrsJsD/UDgaGi8++Qhjzve2fLN3Jl77pgdfH5F3rXyVAOaablfh66Jgbnct3t
# Ygr4N36HKLQf3sPoczhnMaqi+bAHR9neWH6mEkug9P73KtMsXOSQrDZVxvvBcwHO
# IPQxVVhubBGVFrKlOe2Xf0gQ0ISKNb2PowSVPJc/bOtzQ62FA3lGsxNjmJmNrczI
# cIWZgwaKeYd+2xobdh2LwZrwFCN22hObl1WGeqzaoo0Q6plKifbxHhd9/S2UkvlQ
# fIjdvLAf/7NB4m7yqexIKLxUU86xkRvpxnOFcdoCJIa10oBtBFoAiETFshSl4nKk
# LuX7CooLcE70AMa6kH1mBQVtK/kQIWMwPNt+bwznPPYDjFg09Bepm/TAZYv6NO9v
# uQViIM8977NHIFvOatKk5sHteqOrNQU0qXCn4zHXmTUXsUyzkQza4brwhCx0AYGR
# ltIOa4aaM9tnt22Kb5ce6Hc1LomZdg9LuuKSkJtSwxkyfl5bGJYUiTp/TSyRHhEt
# aaHQ3o6r4pgjV8Dn0vMaIBs6tzGC9CRGjc4PijUlb3PVM0zARuTM+tcyjyusay4a
# jJhZyyb3GF3QZchEccLrifNsjd7QbmOoSxZBzi5pB5JHKvvQpGKPNXJaONh+wS29
# UyUnAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUgqYcZF08h0tFe2xHldFLIzf7aQww
# HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0
# JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAw
# XjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQw
# DAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAHkZQyj1e+JSXeDva7yhBOisgoOgB2BZ
# ngtD350ARAKZp62xOGTFs2bXmx67sabCll2ExA3xM110aSLmzkh75oDZUSj29nPf
# WWW6wcFcBWtC2m59Cq0gD7aee6x9pi+KK2vqnmRVPrT0shM5iB0pFYSl/H/jJPlH
# 3Ix4rGjGSTy3IaIY9krjRJPlnXg490l9VuRh4K+UtByWxfX5YFk3H9dm9rMmZeO9
# iNO4bRBtmnHDhk7dmh99BjFlhHOfTPjVTswMWVejaKF9qx1se65rqSkfEn0AihR6
# +HebO9TFinS7TPfBgM+ku6j4zZViHxc4JQHS7vnEbdLn73xMqYVupliCmCvo/5gp
# 5qjZikHWLOzznRhLO7BpfuRHEBRGWY3+Pke/jBpuc59lvfqYOomngh4abA+3Ajy0
# Q+y5ECbKt56PKGRlXt1+Ang3zdAGGkdVmUHgWaUlHzIXdoHXlBbq3DgJof48wgO5
# 3oZ44k7hxAT6VNzqsgmY3hx+LZNMbt7j1O+EJd8FLanM7Jv1h6ZKbSSuTyMmHrOB
# 4arO2TvN7B8T7eyFBFzvixctjnym9WjOd+B8a/LWWVurg57L3oqi7CK6EO3G4qVO
# dbunDvFo0+Egyw7Fbx2lKn3XkW0p86opH918k6xscNIlj+KInPiZYoAajJ14szrM
# uaiFEI9aT9DmMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkq
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
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzMwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMV
# AE5O5ne5h+KKFLjNFOjGKwO32YmkoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDpB0J8MCIYDzIwMjMxMTIxMTQ1
# MTQwWhgPMjAyMzExMjIxNDUxNDBaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOkH
# QnwCAQAwCgIBAAICE9kCAf8wBwIBAAICEtwwCgIFAOkIk/wCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQsFAAOCAQEAgVrVapv+BZfWUgGuap8gDW2qRIMzUlkZ2zmFGPgK
# kKC0DlKP06awnSeFydihWHYBVe2oPlH1OQ1uMVTNVSIoqPjkB92CsU2wjMjPJIhq
# EB2b4r/WQ04PRzfACgtT4vcndyzXHJogPbC9NTrSIBRGYjvrZJBaPUzKMvR5ENmX
# gSX2yeZ8hjZC81xYScmBnxYfm6c1a8CjBPycVU17UKPbtwRJKR+s0Tbqhz54+pjq
# 0ygOxfMDaCgaefKBsQysQWIr6zExnDS2nhIyyyPvom4t8ANx23NMGLdDkWbIa0oc
# 9at3Y0xQdSpDzsczP4AoxFxSxlLXSsbY3Dba3L1MMAn4ZDGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABzIal3Dfr2WEtAAEA
# AAHMMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIC8koUkq/cFlyQ/piEO6yg+MQEUrLUu0dVhqJRiV
# TtQlMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg1u5lAcL+wwIT5yApVKTA
# qkMgJ+d58VliANsXgetwWOYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAcyGpdw369lhLQABAAABzDAiBCD6EBxxQ5xKVakysJwYEcZO
# 6oRFEUCYp7BqLkC37iLtwTANBgkqhkiG9w0BAQsFAASCAgBSFESVkqyeg0j3+IvA
# emP11xCnDa9bzC6RojHQJSILlcRKPrN7fhNe77JwbsULHRF4udcIzAK61S5G8BXK
# vzPQVi+WrftZoe8dvaUuyBoDyg9y7K80+1RrdwTjaFuvJb/5E4M97E0+IH9RyKCx
# 2IfWxbGxw/oKdjvftAHOz06dq4+c6yXM9KZz0os4UjvRFqwTlTnYZrYhUvaDpDLJ
# roVJYBDTcxGSFrhOXBoTIAUfMyIhSCnOry2FT0OVf6AxmG1KHUBolDQA/bvf9e9s
# vN0SCxG+ef1aJlljXnbtO2xgnvfylRHpvk9HliPr2ivomckxLzurV1WWHS6UGQmx
# TaelJOeP5il1F5xu5G4tSvxF2bXJiDJHwFBgWufoymPaorE743Iqz0hwK2IUnSJ6
# SpMZsWMnKXXz3Ifm5WYEc7XfBds/CubEFPCTZvdmpENuSDisuZgXSreEDxMFG4iu
# D3XW7QOWBFIGMBIUZECJRxsbhXfDyPzzNXR+4OWx0quAvJMKn8JjlTXjmgVpwwQd
# nFOfoboYq51oGetdzwfXdq55yJRF+zPu9bc6ANlIPPjgEA+IVnOvoXs2+wLB2yqW
# FbXMSHUXLXsCiEnkGMUmm4XXqbZQ+tj8EPrnJc57u5dd6lsIRn01bBcwhbWJ+kY5
# gMcuH2EgtzcnVYjdptG7M2V3MQ==
# SIG # End signature block
