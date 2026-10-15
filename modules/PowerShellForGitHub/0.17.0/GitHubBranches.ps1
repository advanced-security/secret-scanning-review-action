# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

@{
    GitHubBranchTypeName = 'GitHub.Branch'
    GitHubBranchProtectionRuleTypeName = 'GitHub.BranchProtectionRule'
    GitHubBranchPatternProtectionRuleTypeName = 'GitHub.BranchPatternProtectionRule'
    MaxProtectionRules = 100
    MaxPushAllowances = 100
    MaxReviewDismissalAllowances = 100
}.GetEnumerator() | ForEach-Object {
    Set-Variable -Scope Script -Option ReadOnly -Name $_.Key -Value $_.Value
}

filter Get-GitHubRepositoryBranch
{
<#
    .SYNOPSIS
        Retrieve branches for a given GitHub repository.

    .DESCRIPTION
        Retrieve branches for a given GitHub repository.

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

    .PARAMETER Name
        Name of the specific branch to be retrieved.  If not supplied, all branches will be retrieved.

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
        GitHub.Branch
        List of branches within the given repository.

    .EXAMPLE
        Get-GitHubRepositoryBranch -OwnerName microsoft -RepositoryName PowerShellForGitHub

        Gets all branches for the specified repository.

    .EXAMPLE
        $repo = Get-GitHubRepository -OwnerName microsoft -RepositoryName PowerShellForGitHub
        $repo | Get-GitHubRepositoryBranch

        Gets all branches for the specified repository.

    .EXAMPLE
        Get-GitHubRepositoryBranch -Uri 'https://github.com/PowerShell/PowerShellForGitHub' -BranchName master

        Gets information only on the master branch for the specified repository.

    .EXAMPLE
        $repo = Get-GitHubRepository -OwnerName microsoft -RepositoryName PowerShellForGitHub
        $repo | Get-GitHubRepositoryBranch -BranchName master

        Gets information only on the master branch for the specified repository.

    .EXAMPLE
        $repo = Get-GitHubRepository -OwnerName microsoft -RepositoryName PowerShellForGitHub
        $branch = $repo | Get-GitHubRepositoryBranch -BranchName master
        $branch | Get-GitHubRepositoryBranch

        Gets information only on the master branch for the specified repository, and then does it
        again.  This tries to show some of the different types of objects you can pipe into this
        function.
#>
    [CmdletBinding(DefaultParameterSetName = 'Elements')]
    [OutputType({$script:GitHubBranchTypeName})]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
    [Alias('Get-GitHubBranch')]
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
        [string] $BranchName,

        [switch] $ProtectedOnly,

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

    $uriFragment = "repos/$OwnerName/$RepositoryName/branches"
    if (-not [String]::IsNullOrEmpty($BranchName)) { $uriFragment = $uriFragment + "/$BranchName" }

    $getParams = @()
    if ($ProtectedOnly) { $getParams += 'protected=true' }

    $params = @{
        'UriFragment' = $uriFragment + '?' + ($getParams -join '&')
        'Description' = "Getting branches for $RepositoryName"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethodMultipleResult @params | Add-GitHubBranchAdditionalProperties)
}

filter New-GitHubRepositoryBranch
{
    <#
    .SYNOPSIS
        Creates a new branch for a given GitHub repository.

    .DESCRIPTION
        Creates a new branch for a given GitHub repository.

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

    .PARAMETER BranchName
        The name of the origin branch to create the new branch from.

    .PARAMETER TargetBranchName
        Name of the branch to be created.

    .PARAMETER Sha
        The SHA1 value of the commit that this branch should be based on.
        If not specified, will use the head of BranchName.

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
        GitHub.Repository

    .OUTPUTS
        GitHub.Branch

    .EXAMPLE
        New-GitHubRepositoryBranch -OwnerName microsoft -RepositoryName PowerShellForGitHub -TargetBranchName new-branch

        Creates a new branch in the specified repository from the master branch.

    .EXAMPLE
        New-GitHubRepositoryBranch -Uri 'https://github.com/microsoft/PowerShellForGitHub' -BranchName develop -TargetBranchName new-branch

        Creates a new branch in the specified repository from the 'develop' origin branch.

    .EXAMPLE
        $repo = Get-GithubRepository -Uri https://github.com/You/YourRepo
        $repo | New-GitHubRepositoryBranch -TargetBranchName new-branch

        You can also pipe in a repo that was returned from a previous command.

    .EXAMPLE
        $branch = Get-GitHubRepositoryBranch -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchName main
        $branch | New-GitHubRepositoryBranch -TargetBranchName beta

        You can also pipe in a branch that was returned from a previous command.

    .EXAMPLE
        New-GitHubRepositoryBranch -Uri 'https://github.com/microsoft/PowerShellForGitHub' -Sha 1c3b80b754a983f4da20e77cfb9bd7f0e4cb5da6 -TargetBranchName new-branch

        You can also create a new branch based off of a specific SHA1 commit value.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements',
        PositionalBinding = $false
    )]
    [OutputType({$script:GitHubBranchTypeName})]
    [Alias('New-GitHubBranch')]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $BranchName = 'master',

        [Parameter(
            Mandatory,
            ValueFromPipeline,
            Position = 2)]
        [string] $TargetBranchName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string] $Sha,

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

    $originBranch = $null

    if (-not $PSBoundParameters.ContainsKey('Sha'))
    {
        try
        {
            $getGitHubRepositoryBranchParms = @{
                OwnerName = $OwnerName
                RepositoryName = $RepositoryName
                BranchName = $BranchName
            }
            if ($PSBoundParameters.ContainsKey('AccessToken'))
            {
                $getGitHubRepositoryBranchParms['AccessToken'] = $AccessToken
            }

            Write-Log -Level Verbose "Getting $BranchName branch for sha reference"
            $originBranch = Get-GitHubRepositoryBranch @getGitHubRepositoryBranchParms
            $Sha = $originBranch.commit.sha
        }
        catch
        {
            # Temporary code to handle current differences in exception object between PS5 and PS7
            $throwObject = $_

            if ($PSVersionTable.PSedition -eq 'Core')
            {
                if ($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException] -and
                ($_.ErrorDetails.Message | ConvertFrom-Json).message -eq 'Branch not found')
                {
                    $throwObject = "Origin branch $BranchName not found"
                }
            }
            else
            {
                if ($_.Exception.Message -like '*Not Found*')
                {
                    $throwObject = "Origin branch $BranchName not found"
                }
            }

            Write-Log -Message $throwObject -Level Error
            throw $throwObject
        }
    }

    $uriFragment = "repos/$OwnerName/$RepositoryName/git/refs"

    $hashBody = @{
        ref = "refs/heads/$TargetBranchName"
        sha = $Sha
    }

    if (-not $PSCmdlet.ShouldProcess($BranchName, 'Create Repository Branch'))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Body' = (ConvertTo-Json -InputObject $hashBody)
        'Method' = 'Post'
        'Description' = "Creating branch $TargetBranchName for $RepositoryName"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    return (Invoke-GHRestMethod @params | Add-GitHubBranchAdditionalProperties)
}

filter Remove-GitHubRepositoryBranch
{
    <#
    .SYNOPSIS
        Removes a branch from a given GitHub repository.

    .DESCRIPTION
        Removes a branch from a given GitHub repository.

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

    .PARAMETER BranchName
        Name of the branch to be removed.

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
        GitHub.Release
        GitHub.Repository

    .OUTPUTS
        None

    .EXAMPLE
        Remove-GitHubRepositoryBranch -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchName develop

        Removes the 'develop' branch from the specified repository.

    .EXAMPLE
        Remove-GitHubRepositoryBranch -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchName develop -Force

        Removes the 'develop' branch from the specified repository without prompting for confirmation.

    .EXAMPLE
        $branch = Get-GitHubRepositoryBranch -Uri https://github.com/You/YourRepo -BranchName BranchToDelete
        $branch | Remove-GitHubRepositoryBranch -Force

        You can also pipe in a repo that was returned from a previous command.
#>
    [CmdletBinding(
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements',
        PositionalBinding = $false,
        ConfirmImpact = 'High')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
    [Alias('Remove-GitHubBranch')]
    [Alias('Delete-GitHubRepositoryBranch')]
    [Alias('Delete-GitHubBranch')]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [string] $BranchName,

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

    $uriFragment = "repos/$OwnerName/$RepositoryName/git/refs/heads/$BranchName"

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    if (-not $PSCmdlet.ShouldProcess($BranchName, "Remove Repository Branch"))
    {
        return
    }

    $params = @{
        'UriFragment' = $uriFragment
        'Method' = 'Delete'
        'Description' = "Deleting branch $BranchName from $RepositoryName"
        'AccessToken' = $AccessToken
        'TelemetryEventName' = $MyInvocation.MyCommand.Name
        'TelemetryProperties' = $telemetryProperties
    }

    Invoke-GHRestMethod @params | Out-Null
}


filter Get-GitHubRepositoryBranchProtectionRule
{
    <#
    .SYNOPSIS
        Retrieve branch protection rules for a given GitHub repository.

    .DESCRIPTION
        Retrieve branch protection rules for a given GitHub repository.

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

    .PARAMETER BranchName
        Name of the specific branch to be retrieved.  If not supplied, all branches will be retrieved.

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
        GitHub.Repository

    .OUTPUTS
        GitHub.BranchProtectionRule

    .EXAMPLE
        Get-GitHubRepositoryBranchProtectionRule -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchName master

        Retrieves branch protection rules for the master branch of the PowerShellForGithub repository.

    .EXAMPLE
        Get-GitHubRepositoryBranchProtectionRule -Uri 'https://github.com/microsoft/PowerShellForGitHub' -BranchName master

        Retrieves branch protection rules for the master branch of the PowerShellForGithub repository.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        DefaultParameterSetName = 'Elements')]
    [OutputType({ $script:GitHubBranchProtectionRuleTypeName })]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            Position = 1,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [string] $BranchName,

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
        UriFragment = "repos/$OwnerName/$RepositoryName/branches/$BranchName/protection"
        Description = "Getting branch protection status for $RepositoryName"
        Method = 'Get'
        AcceptHeader = $script:lukeCageAcceptHeader
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    return (Invoke-GHRestMethod @params | Add-GitHubBranchProtectionRuleAdditionalProperties)
}

filter New-GitHubRepositoryBranchProtectionRule
{
    <#
    .SYNOPSIS
        Creates a branch protection rule for a branch on a given GitHub repository.

    .DESCRIPTION
        Creates a branch protection rules for a branch on a given GitHub repository.

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

    .PARAMETER BranchName
        Name of the specific branch to create the protection rule on.

    .PARAMETER StatusChecks
        The list of status checks to require in order to merge into the branch.

    .PARAMETER RequireUpToDateBranches
        Require branches to be up to date before merging. This setting will not take effect unless
        at least one status check is defined.

    .PARAMETER EnforceAdmins
        Enforce all configured restrictions for administrators.

    .PARAMETER DismissalUsers
        Specify the user names of users who can dismiss pull request reviews. This can only be
        specified for organization-owned repositories.

    .PARAMETER DismissalTeams
        Specify which teams can dismiss pull request reviews.

    .PARAMETER DismissStaleReviews
        If specified, approving reviews when someone pushes a new commit are automatically
        dismissed.

    .PARAMETER RequireCodeOwnerReviews
        Blocks merging pull requests until code owners review them.

    .PARAMETER RequiredApprovingReviewCount
        Specify the number of reviewers required to approve pull requests. Use a number between 1
        and 6.

    .PARAMETER RestrictPushUsers
        Specify which users have push access.

    .PARAMETER RestrictPushTeams
        Specify which teams have push access.

    .PARAMETER RestrictPushApps
        Specify which apps have push access.

    .PARAMETER RequireLinearHistory
        Enforces a linear commit Git history, which prevents anyone from pushing merge commits to a
        branch. Your repository must allow squash merging or rebase merging before you can enable a
        linear commit history.

    .PARAMETER AllowForcePushes
        Permits force pushes to the protected branch by anyone with write access to the repository.

    .PARAMETER AllowDeletions
        Allows deletion of the protected branch by anyone with write access to the repository.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Repository
        GitHub.Branch

    .OUTPUTS
        GitHub.BranchRepositoryRule

    .NOTES
        Protecting a branch requires admin or owner permissions to the repository.

    .EXAMPLE
        New-GitHubRepositoryBranchProtectionRule -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchName master -EnforceAdmins

        Creates a branch protection rule for the master branch of the PowerShellForGithub repository
        enforcing all configuration restrictions for administrators.

    .EXAMPLE
        New-GitHubRepositoryBranchProtectionRule -Uri 'https://github.com/microsoft/PowerShellForGitHub' -BranchName master -RequiredApprovingReviewCount 1

        Creates a branch protection rule for the master branch of the PowerShellForGithub repository
        requiring one approving review.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements')]
    [OutputType({$script:GitHubBranchProtectionRuleTypeName })]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [string] $BranchName,

        [string[]] $StatusChecks,

        [switch] $RequireUpToDateBranches,

        [switch] $EnforceAdmins,

        [string[]] $DismissalUsers,

        [string[]] $DismissalTeams,

        [switch] $DismissStaleReviews,

        [switch] $RequireCodeOwnerReviews,

        [ValidateRange(1, 6)]
        [int] $RequiredApprovingReviewCount,

        [string[]] $RestrictPushUsers,

        [string[]] $RestrictPushTeams,

        [string[]] $RestrictPushApps,

        [switch] $RequireLinearHistory,

        [switch] $AllowForcePushes,

        [switch] $AllowDeletions,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    $telemetryProperties = @{
        OwnerName = (Get-PiiSafeString -PlainText $OwnerName)
        RepositoryName = (Get-PiiSafeString -PlainText $RepositoryName)
    }

    $getGitHubRepositoryBranchProtectRuleParms = @{
        OwnerName = $OwnerName
        RepositoryName = $RepositoryName
        BranchName = $BranchName
    }

    $ruleExists = $true

    try
    {
        Get-GitHubRepositoryBranchProtectionRule @getGitHubRepositoryBranchProtectRuleParms |
            Out-Null
    }
    catch
    {
        # Temporary code to handle current differences in exception object between PS5 and PS7
        if ($PSVersionTable.PSedition -eq 'Core')
        {
            if ($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException] -and
                ($_.ErrorDetails.Message | ConvertFrom-Json).message -eq 'Branch not protected')
            {
                $ruleExists = $false
            }
            else
            {
                throw $_
            }
        }
        else
        {
            if ($_.Exception.Message -like '*Branch not protected*')
            {
                $ruleExists = $false
            }
            else
            {
                throw $_
            }
        }
    }

    if ($ruleExists)
    {
        $message = ("Branch protection rule for branch $BranchName already exists on Repository " +
            $RepositoryName)
        Write-Log -Message $message -Level Error
        throw $message
    }

    if ($PSBoundParameters.ContainsKey('DismissalTeams') -or
        $PSBoundParameters.ContainsKey('RestrictPushTeams'))
    {
        $teams = Get-GitHubTeam -OwnerName $OwnerName -RepositoryName $RepositoryName
    }

    $requiredStatusChecks = $null
    if ($PSBoundParameters.ContainsKey('StatusChecks') -or
        $PSBoundParameters.ContainsKey('RequireUpToDateBranches'))
    {
        if ($null -eq $StatusChecks)
        {
            $StatusChecks = @()
        }
        $requiredStatusChecks = @{
            strict = $RequireUpToDateBranches.ToBool()
            contexts = $StatusChecks
        }
    }

    $dismissalRestrictions = @{}

    if ($PSBoundParameters.ContainsKey('DismissalUsers'))
    {
        $dismissalRestrictions['users'] = $DismissalUsers
    }
    if ($PSBoundParameters.ContainsKey('DismissalTeams'))
    {
        $dismissalTeamList = $teams | Where-Object -FilterScript { $DismissalTeams -contains $_.name }
        $dismissalRestrictions['teams'] = @($dismissalTeamList.slug)
    }

    $requiredPullRequestReviews = @{}

    if ($PSBoundParameters.ContainsKey('DismissStaleReviews'))
    {
        $requiredPullRequestReviews['dismiss_stale_reviews'] = $DismissStaleReviews.ToBool()
    }
    if ($PSBoundParameters.ContainsKey('RequireCodeOwnerReviews'))
    {
        $requiredPullRequestReviews['require_code_owner_reviews'] = $RequireCodeOwnerReviews.ToBool()
    }
    if ($dismissalRestrictions.count -gt 0)
    {
        $requiredPullRequestReviews['dismissal_restrictions'] = $dismissalRestrictions
    }
    if ($PSBoundParameters.ContainsKey('RequiredApprovingReviewCount'))
    {
        $requiredPullRequestReviews['required_approving_review_count'] = $RequiredApprovingReviewCount
    }

    if ($requiredPullRequestReviews.count -eq 0)
    {
        $requiredPullRequestReviews = $null
    }

    if ($PSBoundParameters.ContainsKey('RestrictPushUsers') -or
        $PSBoundParameters.ContainsKey('RestrictPushTeams') -or
        $PSBoundParameters.ContainsKey('RestrictPushApps'))
    {
        if ($null -eq $RestrictPushUsers)
        {
            $RestrictPushUsers = @()
        }

        if ($null -eq $RestrictPushTeams)
        {
            $restrictPushTeamSlugs = @()
        }
        else
        {
            $restrictPushTeamList = $teams | Where-Object -FilterScript {
                $RestrictPushTeams -contains $_.name }
            $restrictPushTeamSlugs = @($restrictPushTeamList.slug)
        }

        $restrictions = @{
            users = $RestrictPushUsers
            teams = $restrictPushTeamSlugs
        }

        if ($PSBoundParameters.ContainsKey('RestrictPushApps'))
        {
            $restrictions['apps'] = $RestrictPushApps
        }
    }
    else
    {
        $restrictions = $null
    }

    $hashBody = @{
        required_status_checks = $requiredStatusChecks
        enforce_admins = $EnforceAdmins.ToBool()
        required_pull_request_reviews = $requiredPullRequestReviews
        restrictions = $restrictions
    }

    if ($PSBoundParameters.ContainsKey('RequireLinearHistory'))
    {
        $hashBody['required_linear_history'] = $RequireLinearHistory.ToBool()
    }
    if ($PSBoundParameters.ContainsKey('AllowForcePushes'))
    {
        $hashBody['allow_force_pushes'] = $AllowForcePushes.ToBool()
    }
    if ($PSBoundParameters.ContainsKey('AllowDeletions'))
    {
        $hashBody['allow_deletions'] = $AllowDeletions.ToBool()
    }

    if (-not $PSCmdlet.ShouldProcess(
            "'$BranchName' branch of repository '$RepositoryName'",
            'Create GitHub Repository Branch Protection Rule'))
    {
        return
    }

    $jsonConversionDepth = 3

    $params = @{
        UriFragment = "repos/$OwnerName/$RepositoryName/branches/$BranchName/protection"
        Body = (ConvertTo-Json -InputObject $hashBody -Depth $jsonConversionDepth)
        Description = "Setting $BranchName branch protection status for $RepositoryName"
        Method = 'Put'
        AcceptHeader = $script:lukeCageAcceptHeader
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    return (Invoke-GHRestMethod @params | Add-GitHubBranchProtectionRuleAdditionalProperties)
}

filter Remove-GitHubRepositoryBranchProtectionRule
{
    <#
    .SYNOPSIS
        Remove branch protection rules from a given GitHub repository.

    .DESCRIPTION
        Remove branch protection rules from a given GitHub repository.

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

    .PARAMETER BranchName
        Name of the specific branch to remove the branch protection rule from.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Repository
        GitHub.Branch

    .OUTPUTS
        None

    .EXAMPLE
        Remove-GitHubRepositoryBranchProtectionRule -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchName master

        Removes branch protection rules from the master branch of the PowerShellForGithub repository.

    .EXAMPLE
        Removes-GitHubRepositoryBranchProtection -Uri 'https://github.com/microsoft/PowerShellForGitHub' -BranchName master

        Removes branch protection rules from the master branch of the PowerShellForGithub repository.

    .EXAMPLE
        Removes-GitHubRepositoryBranchProtection -Uri 'https://github.com/master/PowerShellForGitHub' -BranchName master -Force

        Removes branch protection rules from the master branch of the PowerShellForGithub repository
        without prompting for confirmation.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements',
        ConfirmImpact = "High")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "", Justification="The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
    [Alias('Delete-GitHubRepositoryBranchProtectionRule')]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            Position = 1,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 2)]
        [string] $BranchName,

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

    if (-not $PSCmdlet.ShouldProcess("'$BranchName' branch of repository '$RepositoryName'",
            'Remove GitHub Repository Branch Protection Rule'))
    {
        return
    }

    $params = @{
        UriFragment = "repos/$OwnerName/$RepositoryName/branches/$BranchName/protection"
        Description = "Removing $BranchName branch protection rule for $RepositoryName"
        Method = 'Delete'
        AcceptHeader = $script:lukeCageAcceptHeader
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    return Invoke-GHRestMethod @params | Out-Null
}

filter New-GitHubRepositoryBranchPatternProtectionRule
{
    <#
    .SYNOPSIS
        Creates a branch protection rule for a branch on a given GitHub repository.

    .DESCRIPTION
        Creates a branch protection rules for a branch on a given GitHub repository.

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
        Name of the Organization.

    .PARAMETER BranchPatternName
        The branch name pattern to create the protection rule on.

    .PARAMETER StatusCheck
        The list of status checks to require in order to merge into the branch.

    .PARAMETER RequireStrictStatusChecks
        Require branches to be up to date before merging. This setting will not take effect unless
        at least one status check is defined.

    .PARAMETER IsAdminEnforced
        Enforce all configured restrictions for administrators.

    .PARAMETER DismissalUser
        Specify the user names of users who can dismiss pull request reviews.

    .PARAMETER DismissalTeam
        Specify which teams can dismiss pull request reviews. This can only be
        specified for organization-owned repositories.

    .PARAMETER DismissStaleReviews
        If specified, approving reviews when someone pushes a new commit are automatically
        dismissed.

    .PARAMETER RequireCodeOwnerReviews
        Blocks merging pull requests until code owners review them.

    .PARAMETER RequiredApprovingReviewCount
        Specify the number of reviewers required to approve pull requests. Use a number between 1
        and 6.

    .PARAMETER RestrictPushUser
        Specify which users have push access.

    .PARAMETER RestrictPushTeam
        Specify which teams have push access.

    .PARAMETER RestrictPushApp
        Specify which apps have push access.

    .PARAMETER RequireLinearHistory
        Enforces a linear commit Git history, which prevents anyone from pushing merge commits to a
        branch. Your repository must allow squash merging or rebase merging before you can enable a
        linear commit history.

    .PARAMETER RequireCommitSignatures
        Specifies whether commits are required to be signed.

    .PARAMETER AllowForcePushes
        Permits force pushes to the protected branch by anyone with write access to the repository.

    .PARAMETER AllowDeletions
        Allows deletion of the protected branch by anyone with write access to the repository.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Repository
        GitHub.Branch

    .OUTPUTS
        GitHub.BranchPatternProtectionRule

    .NOTES
        Protecting a branch requires admin or owner permissions to the repository.

    .EXAMPLE
        New-GitHubRepositoryBranchPatternProtectionRule -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchName release/**/* -EnforceAdmins

        Creates a branch protection rule for the 'release/**/*' branch pattern of the PowerShellForGithub repository
        enforcing all configuration restrictions for administrators.

    .EXAMPLE
        New-GitHubRepositoryBranchPatternProtectionRule -Uri 'https://github.com/microsoft/PowerShellForGitHub' -BranchName master -RequiredApprovingReviewCount 1

        Creates a branch protection rule for the master branch of the PowerShellForGithub repository
        requiring one approving review.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements')]
    [OutputType( { $script:GitHubBranchPatternProtectionRuleTypeName })]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            ValueFromPipelineByPropertyName,
            Position = 1,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [string] $OrganizationName,

        [Parameter(
            Mandatory,
            Position = 2)]
        [string] $BranchPatternName,

        [ValidateNotNullOrEmpty()]
        [string[]] $StatusCheck,

        [switch] $RequireStrictStatusChecks,

        [switch] $IsAdminEnforced,

        [ValidateNotNullOrEmpty()]
        [string[]] $DismissalUser,

        [ValidateNotNullOrEmpty()]
        [string[]] $DismissalTeam,

        [switch] $DismissStaleReviews,

        [switch] $RequireCodeOwnerReviews,

        [ValidateRange(1, 6)]
        [int] $RequiredApprovingReviewCount,

        [ValidateNotNullOrEmpty()]
        [string[]] $RestrictPushUser,

        [ValidateNotNullOrEmpty()]
        [string[]] $RestrictPushTeam,

        [ValidateNotNullOrEmpty()]
        [string[]] $RestrictPushApp,

        [switch] $RequireLinearHistory,

        [switch] $AllowForcePushes,

        [switch] $AllowDeletions,

        [switch] $RequireCommitSignatures,

        [string] $AccessToken
    )

    Write-InvocationLog

    $elements = Resolve-RepositoryElements
    $OwnerName = $elements.ownerName
    $RepositoryName = $elements.repositoryName

    if ([System.String]::IsNullOrEmpty($OrganizationName))
    {
        $OrganizationName = $OwnerName
    }

    $telemetryProperties = @{
        OwnerName = (Get-PiiSafeString -PlainText $OwnerName)
        RepositoryName = (Get-PiiSafeString -PlainText $RepositoryName)
    }

    $hashbody = @{query = "query repo { repository(name: ""$RepositoryName"", owner: ""$OwnerName"") { id } }" }

    $params = @{
        Body = ConvertTo-Json -InputObject $hashBody
        Description = "Querying Repository $RepositoryName, Owner $OwnerName"
        AccessToken = $AccessToken
        TelemetryEventName = 'Get-GitHubRepositoryQ1'
        TelemetryProperties = $telemetryProperties
    }

    try
    {
        $result = Invoke-GHGraphQl @params
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }

    $repoId = $result.data.repository.id

    $mutationList = @(
        "repositoryId: ""$repoId"", pattern: ""$BranchPatternName"""
    )

    if ($PSBoundParameters.ContainsKey('DismissalTeam') -or
        $PSBoundParameters.ContainsKey('RestrictPushTeam'))
    {
        Write-Debug -Message "Getting details for all GitHub Teams in Organization '$OrganizationName'"

        try
        {
            $orgTeams = Get-GitHubTeam -OrganizationName $OrganizationName -Verbose:$false
        }
        catch
        {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }

    # Process 'Require pull request reviews before merging' properties
    if ($PSBoundParameters.ContainsKey('RequiredApprovingReviewCount') -or
        $PSBoundParameters.ContainsKey('DismissStaleReviews') -or
        $PSBoundParameters.ContainsKey('RequireCodeOwnerReviews') -or
        $PSBoundParameters.ContainsKey('DismissalUser') -or
        $PSBoundParameters.ContainsKey('DismissalTeam'))
    {
        $mutationList += 'requiresApprovingReviews: true'

        if ($PSBoundParameters.ContainsKey('RequiredApprovingReviewCount'))
        {
            $mutationList += 'requiredApprovingReviewCount: ' + $RequiredApprovingReviewCount
        }

        if ($PSBoundParameters.ContainsKey('DismissStaleReviews'))
        {
            $mutationList += 'dismissesStaleReviews: ' + $DismissStaleReviews.ToBool().ToString().ToLower()
        }

        if ($PSBoundParameters.ContainsKey('RequireCodeOwnerReviews'))
        {
            $mutationList += 'requiresCodeOwnerReviews: ' + $RequireCodeOwnerReviews.ToBool().ToString().ToLower()
        }

        if ($PSBoundParameters.ContainsKey('DismissalUser') -or
            $PSBoundParameters.ContainsKey('DismissalTeam'))
        {
            $reviewDismissalActorIds = @()

            if ($PSBoundParameters.ContainsKey('DismissalUser'))
            {
                foreach ($user in $DismissalUser)
                {
                    $hashbody = @{query = "query user { user(login: ""$user"") { id } }"}

                    $params = @{
                        Body = ConvertTo-Json -InputObject $hashBody
                        Description = "Querying for user $user"
                        AccessToken = $AccessToken
                        TelemetryEventName = 'Get-GitHubUserQ1'
                        TelemetryProperties = $telemetryProperties
                    }

                    try
                    {
                        $result = Invoke-GHGraphQl @params
                    }
                    catch
                    {
                        $PSCmdlet.ThrowTerminatingError($_)
                    }

                    $reviewDismissalActorIds += $result.data.user.id
                }
            }

            if ($PSBoundParameters.ContainsKey('DismissalTeam'))
            {
                foreach ($team in $DismissalTeam)
                {
                    $teamDetail = $orgTeams | Where-Object -Property Name -eq $team

                    if ($teamDetail.Count -eq 0)
                    {
                        $newErrorRecordParms = @{
                            ErrorMessage = "Team '$team' not found in organization '$OrganizationName'"
                            ErrorId = 'DismissalTeamNotFound'
                            ErrorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                            TargetObject = $team
                        }
                        $errorRecord = New-ErrorRecord @newErrorRecordParms

                        Write-Log -Exception $errorRecord -Level Error

                        $PSCmdlet.ThrowTerminatingError($errorRecord)
                    }

                    $getGitHubRepositoryTeamPermissionParms = @{
                        TeamSlug = $teamDetail.TeamSlug
                        OwnerName = $ownerName
                        RepositoryName = $repositoryName
                        Verbose = $false
                    }

                    Write-Debug -Message "Getting GitHub Permissions for Team '$team' on Repository '$OwnerName/$RepositoryName'"

                    try
                    {
                        $teamPermission = Get-GitHubRepositoryTeamPermission @getGitHubRepositoryTeamPermissionParms
                    }
                    catch
                    {
                        Write-Debug -Message "Team '$team' has no permissions on Repository '$OwnerName/$RepositoryName'"
                    }

                    if (($teamPermission.permissions.push -eq $true) -or ($teamPermission.permissions.maintain -eq $true))
                    {
                        $reviewDismissalActorIds += $teamDetail.node_id
                    }
                    else
                    {
                        $newErrorRecordParms = @{
                            ErrorMessage = "Team '$team' does not have push or maintain permissions on repository '$OwnerName/$RepositoryName'"
                            ErrorId = 'DismissalTeamNoPermissions'
                            ErrorCategory = [System.Management.Automation.ErrorCategory]::PermissionDenied
                            TargetObject = $team
                        }
                        $errorRecord = New-ErrorRecord @newErrorRecordParms

                        Write-Log -Exception $errorRecord -Level Error

                        $PSCmdlet.ThrowTerminatingError($errorRecord)
                    }
                }
            }

            $mutationList += 'restrictsReviewDismissals: true'
            $mutationList += 'reviewDismissalActorIds: [ "' + ($reviewDismissalActorIds -join ('","')) + '" ]'
        }
    }

    # Process 'Require status checks to pass before merging' properties
    if ($PSBoundParameters.ContainsKey('StatusCheck') -or
        $PSBoundParameters.ContainsKey('RequireStrictStatusChecks'))
    {
        $mutationList += 'requiresStatusChecks: true'

        if ($PSBoundParameters.ContainsKey('RequireStrictStatusChecks'))
        {
            $mutationList += 'requiresStrictStatusChecks: ' + $RequireStrictStatusChecks.ToBool().ToString().ToLower()
        }

        if ($PSBoundParameters.ContainsKey('StatusCheck'))
        {
            $mutationList += 'requiredStatusCheckContexts: [ "' + ($StatusCheck -join ('","')) + '" ]'
        }
    }

    if ($PSBoundParameters.ContainsKey('RequireCommitSignatures'))
    {
        $mutationList += 'requiresCommitSignatures: ' + $RequireCommitSignatures.ToBool().ToString().ToLower()
    }

    if ($PSBoundParameters.ContainsKey('RequireLinearHistory'))
    {
        $mutationList += 'requiresLinearHistory: ' + $RequireLinearHistory.ToBool().ToString().ToLower()
    }

    if ($PSBoundParameters.ContainsKey('IsAdminEnforced'))
    {
        $mutationList += 'isAdminEnforced: ' + $IsAdminEnforced.ToBool().ToString().ToLower()
    }

    # Process 'Restrict who can push to matching branches' properties
    if ($PSBoundParameters.ContainsKey('RestrictPushUser') -or
        $PSBoundParameters.ContainsKey('RestrictPushTeam') -or
        $PSBoundParameters.ContainsKey('RestrictPushApp'))
    {
        $restrictPushActorIds = @()

        if ($PSBoundParameters.ContainsKey('RestrictPushUser'))
        {
            foreach ($user in $RestrictPushUser)
            {
                $hashbody = @{query = "query user { user(login: ""$user"") { id } }" }

                $params = @{
                    Body = ConvertTo-Json -InputObject $hashBody
                    Description = "Querying for User $user"
                    AccessToken = $AccessToken
                    TelemetryEventName = 'GetGitHubUserQ1'
                    TelemetryProperties = $telemetryProperties
                }

                try
                {
                    $result = Invoke-GHGraphQl @params
                }
                catch
                {
                    $PSCmdlet.ThrowTerminatingError($_)
                }

                $restrictPushActorIds += $result.data.user.id
            }
        }

        if ($PSBoundParameters.ContainsKey('RestrictPushTeam'))
        {
            foreach ($team in $RestrictPushTeam)
            {
                $teamDetail = $orgTeams | Where-Object -Property Name -eq $team

                if ($teamDetail.Count -eq 0)
                {
                    $newErrorRecordParms = @{
                        ErrorMessage = "Team '$team' not found in organization '$OrganizationName'"
                        ErrorId = 'RestrictPushTeamNotFound'
                        ErrorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                        TargetObject = $team
                    }
                    $errorRecord = New-ErrorRecord @newErrorRecordParms

                    Write-Log -Exception $errorRecord -Level Error

                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }

                $getGitHubRepositoryTeamPermissionParms = @{
                    TeamSlug = $teamDetail.TeamSlug
                    OwnerName = $ownerName
                    RepositoryName = $repositoryName
                    Verbose = $false
                }

                Write-Debug -Message "Getting GitHub Permissions for Team '$team' on Repository '$OwnerName/$RepositoryName'"
                try
                {
                    $teamPermission = Get-GitHubRepositoryTeamPermission @getGitHubRepositoryTeamPermissionParms
                }
                catch
                {
                    Write-Debug -Message "Team '$team' has no permissions on Repository '$OwnerName/$RepositoryName'"
                }

                if ($teamPermission.permissions.push -eq $true -or $teamPermission.permissions.maintain -eq $true)
                {
                    $restrictPushActorIds += $teamDetail.node_id
                }
                else
                {
                    $newErrorRecordParms = @{
                        ErrorMessage = "Team '$team' does not have push or maintain permissions on repository '$OwnerName/$RepositoryName'"
                        ErrorId = 'RestrictPushTeamNoPermissions'
                        ErrorCategory = [System.Management.Automation.ErrorCategory]::PermissionDenied
                        TargetObject = $team
                    }
                    $errorRecord = New-ErrorRecord @newErrorRecordParms

                    Write-Log -Exception $errorRecord -Level Error

                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }
        }

        if ($PSBoundParameters.ContainsKey('RestrictPushApp'))
        {
            foreach ($app in $RestrictPushApp)
            {
                $hashbody = @{query = "query app { marketplaceListing(slug: ""$app"") { app { id } } }" }

                $params = @{
                    Body = ConvertTo-Json -InputObject $hashBody
                    Description = "Querying for app $app"
                    AccessToken = $AccessToken
                    TelemetryEventName = 'Get-GitHubAppQ1'
                    TelemetryProperties = $telemetryProperties
                }

                try
                {
                    $result = Invoke-GHGraphQl @params
                }
                catch
                {
                    $PSCmdlet.ThrowTerminatingError($_)
                }

                if ($result.data.marketplaceListing)
                {
                    $restrictPushActorIds += $result.data.marketplaceListing.app.id
                }
                else
                {
                    $newErrorRecordParms = @{
                        ErrorMessage = "App '$app' not found in GitHub Marketplace"
                        ErrorId = 'RestictPushAppNotFound'
                        ErrorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
                        TargetObject = $app
                    }
                    $errorRecord = New-ErrorRecord @newErrorRecordParms

                    Write-Log -Exception $errorRecord -Level Error

                    $PSCmdlet.ThrowTerminatingError($errorRecord)
                }
            }
        }

        $mutationList += 'restrictsPushes: true'
        $mutationList += 'pushActorIds: [ "' + ($restrictPushActorIds -join ('","')) + '" ]'
    }

    if ($PSBoundParameters.ContainsKey('AllowForcePushes'))
    {
        $mutationList += 'allowsForcePushes: ' + $AllowForcePushes.ToBool().ToString().ToLower()
    }

    if ($PSBoundParameters.ContainsKey('AllowDeletions'))
    {
        $mutationList += 'allowsDeletions: ' + $AllowDeletions.ToBool().ToString().ToLower()
    }

    $mutationInput = $mutationList -join (',')
    $hashbody = @{query = "mutation ProtectionRule { createBranchProtectionRule(input: { $mutationInput }) " +
        "{ clientMutationId  } } "
    }

    $body = ConvertTo-Json -InputObject $hashBody

    if (-not $PSCmdlet.ShouldProcess(
            "$OwnerName/$RepositoryName",
            "Create GitHub Repository Branch Pattern Protection Rule '$BranchPatternName'"))
    {
        return
    }

    $params = @{
        Body = $body
        Description = "Creating GitHub Repository Branch Pattern Protection Rule '$BranchPatternName' on $OwnerName/$RepositoryName"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    try
    {
        $result = Invoke-GHGraphQl @params
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

filter Get-GitHubRepositoryBranchPatternProtectionRule
{
    <#
    .SYNOPSIS
        Retrieve a branch pattern protection rule for a given GitHub repository.

    .DESCRIPTION
        Retrieve a branch pattern protection rule for a given GitHub repository.

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

    .PARAMETER BranchPatternName
        Name of the specific branch Pattern to be retrieved.

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
        GitHub.Repository

    .OUTPUTS
        GitHub.BranchPatternProtectionRule

    .EXAMPLE
        Get-GitHubRepositoryBranchPatternProtectionRule -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchPatternName release/**/*

        Retrieves branch protection rules for the release/**/* branch pattern of the PowerShellForGithub repository.

    .EXAMPLE
        Get-GitHubQlRepositoryBranchPatternProtectionRule -Uri 'https://github.com/microsoft/PowerShellForGitHub' -BranchPatternName master

        Retrieves branch protection rules for the master branch pattern of the PowerShellForGithub repository.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        DefaultParameterSetName = 'Elements')]
    [OutputType( { $script:GitHubBranchProtectionRuleTypeName })]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "",
        Justification = "The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            Position = 1,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(Position = 2)]
        [string] $BranchPatternName,

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

    $branchProtectionRuleFields = ('allowsDeletions allowsForcePushes dismissesStaleReviews id ' +
        'isAdminEnforced pattern requiredApprovingReviewCount requiredStatusCheckContexts ' +
        'requiresApprovingReviews requiresCodeOwnerReviews requiresCommitSignatures requiresLinearHistory ' +
        'requiresStatusChecks requiresStrictStatusChecks restrictsPushes restrictsReviewDismissals ' +
        "pushAllowances(first: $script:MaxPushAllowances) { nodes { actor { ... on App { __typename name } " +
        '... on Team { __typename name } ... on User { __typename login } } } }' +
        "reviewDismissalAllowances(first: $script:MaxReviewDismissalAllowances)" +
        '{ nodes { actor { ... on Team { __typename name } ... on User { __typename login } } } } ' +
        'repository { url }')

    $hashbody = @{query = "query branchProtectionRule { repository(name: ""$RepositoryName"", " +
        "owner: ""$OwnerName"") { branchProtectionRules(first: $script:MaxProtectionRules) { nodes { " +
        "$branchProtectionRuleFields } } } }"}

    $params = @{
        Body = ConvertTo-Json -InputObject $hashBody
        Description = "Querying $OwnerName/$RepositoryName repository for branch protection rules"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    try
    {
        $result = Invoke-GHGraphQl @params
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }

    if ($result.data.repository.branchProtectionRules)
    {
        if ($PSBoundParameters.ContainsKey('BranchPatternName'))
        {
            $rule = ($result.data.repository.branchProtectionRules.nodes |
                Where-Object -Property pattern -eq $BranchPatternName)
        }
        else
        {
            $rule = $result.data.repository.branchProtectionRules.nodes
        }
    }

    if (!$rule -and $PSBoundParameters.ContainsKey('BranchPatternName'))
    {
        $newErrorRecordParms = @{
            ErrorMessage = "Branch Protection Rule '$BranchPatternName' not found on repository '$OwnerName/$RepositoryName'"
            ErrorId = 'BranchProtectionRuleNotFound'
            ErrorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
            TargetObject = $BranchPatternName
        }
        $errorRecord = New-ErrorRecord @newErrorRecordParms

        Write-Log -Exception $errorRecord -Level Error

        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }

    return ($rule | Add-GitHubBranchPatternProtectionRuleAdditionalProperties)
}

filter Remove-GitHubRepositoryBranchPatternProtectionRule
{
    <#
    .SYNOPSIS
        Remove a branch pattern protection rule from a given GitHub repository.

    .DESCRIPTION
        Remove a branch pattern protection rule from a given GitHub repository.

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

    .PARAMETER BranchPatternName
        Name of the specific branch protection rule pattern to remove.

    .PARAMETER AccessToken
        If provided, this will be used as the AccessToken for authentication with the
        REST Api.  Otherwise, will attempt to use the configured value or will run unauthenticated.

    .INPUTS
        GitHub.Repository

    .OUTPUTS
        None

    .EXAMPLE
        Remove-GitHubRepositoryBranchPatternProtectionRule -OwnerName microsoft -RepositoryName PowerShellForGitHub -BranchPatternName release/**/*

        Removes branch pattern 'release/**/*' protection rules from the PowerShellForGithub repository.

    .EXAMPLE
        Remove-GitHubRepositoryBranchPatternProtectionRule -Uri 'https://github.com/microsoft/PowerShellForGitHub' -BranchPatternName release/**/*

        Removes branch pattern 'release/**/*' protection rules from the PowerShellForGithub repository.

    .EXAMPLE
        Remove-GitHubRepositoryBranchPatternProtectionRule -Uri 'https://github.com/master/PowerShellForGitHub' -BranchPatternName release/**/* -Force

        Removes branch pattern 'release/**/*' protection rules from the PowerShellForGithub repository
        without prompting for confirmation.
#>
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess,
        DefaultParameterSetName = 'Elements',
        ConfirmImpact = "High")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "",
        Justification = "The Uri parameter is only referenced by Resolve-RepositoryElements which get access to it from the stack via Get-Variable -Scope 1.")]
    [Alias('Delete-GitHubRepositoryBranchPatternProtectionRule')]
    param(
        [Parameter(ParameterSetName = 'Elements')]
        [string] $OwnerName,

        [Parameter(ParameterSetName = 'Elements')]
        [string] $RepositoryName,

        [Parameter(
            Mandatory,
            Position = 1,
            ValueFromPipelineByPropertyName,
            ParameterSetName = 'Uri')]
        [Alias('RepositoryUrl')]
        [string] $Uri,

        [Parameter(
            Mandatory,
            Position = 2)]
        [string] $BranchPatternName,

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

    $hashbody = @{query = "query branchProtectionRule { repository(name: ""$RepositoryName"", " +
        "owner: ""$OwnerName"") { branchProtectionRules(first: $script:MaxProtectionRules) { nodes { id pattern } } } }"
    }

    $params = @{
        Body = ConvertTo-Json -InputObject $hashBody
        Description = "Querying $OwnerName/$RepositoryName repository for branch protection rules"
        AccessToken = $AccessToken
        TelemetryEventName = 'Get-GitHubRepositoryQ1'
        TelemetryProperties = $telemetryProperties
    }

    try
    {
        $result = Invoke-GHGraphQl @params
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }

    if ($result.data.repository.branchProtectionRules)
    {
        $ruleId = ($result.data.repository.branchProtectionRules.nodes |
            Where-Object -Property pattern -eq $BranchPatternName).id
    }

    if (!$ruleId)
    {
        $newErrorRecordParms = @{
            ErrorMessage = "Branch Protection Rule '$BranchPatternName' not found on repository '$OwnerName/$RepositoryName'"
            ErrorId = 'BranchProtectionRuleNotFound'
            ErrorCategory = [System.Management.Automation.ErrorCategory]::ObjectNotFound
            TargetObject = $BranchPatternName
        }
        $errorRecord = New-ErrorRecord @newErrorRecordParms

        Write-Log -Exception $errorRecord -Level Error

        $PSCmdlet.ThrowTerminatingError($errorRecord)
    }

    if ($Force -and (-not $Confirm))
    {
        $ConfirmPreference = 'None'
    }

    $hashbody = @{query = "mutation ProtectionRule { deleteBranchProtectionRule(input: " +
        "{ branchProtectionRuleId: ""$ruleId"" } ) { clientMutationId } }"
    }

    $body = ConvertTo-Json -InputObject $hashBody

    if (-not $PSCmdlet.ShouldProcess("$OwnerName/$RepositoryName",
            "Remove GitHub Repository Branch Pattern Protection Rule '$BranchPatternName'"))
    {
        return
    }

    $params = @{
        Body = $body
        Description = "Removing GitHub Repository Branch Pattern Protection Rule '$BranchPatternName' from $OwnerName/$RepositoryName"
        AccessToken = $AccessToken
        TelemetryEventName = $MyInvocation.MyCommand.Name
        TelemetryProperties = $telemetryProperties
    }

    try
    {
        $result = Invoke-GHGraphQl @params
    }
    catch
    {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

filter Add-GitHubBranchAdditionalProperties
{
<#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Branch objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        [PSCustomObject]

    .OUTPUTS
        GitHub.Branch
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
        [string] $TypeName = $script:GitHubBranchTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            if ($null -ne $item.url)
            {
                $elements = Split-GitHubUri -Uri $item.url
            }
            else
            {
                $elements = Split-GitHubUri -Uri $item.commit.url
            }
            $repositoryUrl = Join-GitHubUri @elements

            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force

            $branchName = $item.name
            if ($null -eq $branchName)
            {
                $branchName = $item.ref -replace ('refs/heads/', '')
            }

            Add-Member -InputObject $item -Name 'BranchName' -Value $branchName -MemberType NoteProperty -Force

            if ($null -ne $item.commit)
            {
                Add-Member -InputObject $item -Name 'Sha' -Value $item.commit.sha -MemberType NoteProperty -Force
            }
            elseif ($null -ne $item.object)
            {
                Add-Member -InputObject $item -Name 'Sha' -Value $item.object.sha -MemberType NoteProperty -Force
            }
        }

        Write-Output $item
    }
}

filter Add-GitHubBranchProtectionRuleAdditionalProperties
{
    <#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Branch Protection Rule objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        PSCustomObject

    .OUTPUTS
        GitHub.Branch
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Internal helper that is definitely adding more than one property.')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubBranchProtectionRuleTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $elements = Split-GitHubUri -Uri $item.url
            $repositoryUrl = Join-GitHubUri @elements
            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force

            $hostName = $(Get-GitHubConfiguration -Name 'ApiHostName')

            if ($item.url -match "^https?://(?:www\.|api\.|)$hostName/repos/(?:[^/]+)/(?:[^/]+)/branches/([^/]+)/.*$")
            {
                Add-Member -InputObject $item -Name 'BranchName' -Value $Matches[1] -MemberType NoteProperty -Force
            }
        }

        Write-Output $item
    }
}

filter Add-GitHubBranchPatternProtectionRuleAdditionalProperties
{
    <#
    .SYNOPSIS
        Adds type name and additional properties to ease pipelining to GitHub Branch Pattern Protection Rule objects.

    .PARAMETER InputObject
        The GitHub object to add additional properties to.

    .PARAMETER TypeName
        The type that should be assigned to the object.

    .INPUTS
        PSCustomObject

    .OUTPUTS
        GitHub.BranchPatternProtection Rule
#>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Internal helper that is definitely adding more than one property.')]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]] $InputObject,

        [ValidateNotNullOrEmpty()]
        [string] $TypeName = $script:GitHubBranchPatternProtectionRuleTypeName
    )

    foreach ($item in $InputObject)
    {
        $item.PSObject.TypeNames.Insert(0, $TypeName)

        if (-not (Get-GitHubConfiguration -Name DisablePipelineSupport))
        {
            $elements = Split-GitHubUri -Uri $item.repository.url
            $repositoryUrl = Join-GitHubUri @elements
            Add-Member -InputObject $item -Name 'RepositoryUrl' -Value $repositoryUrl -MemberType NoteProperty -Force
        }

        $restrictPushApps = @()
        $restrictPushTeams = @()
        $restrictPushUsers = @()

        foreach ($actor in $item.pushAllowances.nodes.actor)
        {
            if ($actor.__typename -eq 'App')
            {
                $restrictPushApps += $actor.name
            }
            elseif ($actor.__typename -eq 'Team')
            {
                $restrictPushTeams += $actor.name
            }
            elseif ($actor.__typename -eq 'User')
            {
                $restrictPushUsers += $actor.login
            }
            else
            {
                Write-Log -Message "Unknown restrict push actor type found $($actor.__typename). Ignoring" -Level Warning
            }
        }

        Add-Member -InputObject $item -Name 'RestrictPushApps' -Value $restrictPushApps -MemberType NoteProperty -Force
        Add-Member -InputObject $item -Name 'RestrictPushTeams' -Value $restrictPushTeams -MemberType NoteProperty -Force
        Add-Member -InputObject $item -Name 'RestrictPushUsers' -Value $restrictPushUsers -MemberType NoteProperty -Force

        $dismissalTeams = @()
        $dismissalUsers = @()

        foreach ($actor in $item.reviewDismissalAllowances.nodes.actor)
        {
            if ($actor.__typename -eq 'Team')
            {
                $dismissalTeams += $actor.name
            }
            elseif ($actor.__typename -eq 'User')
            {
                $dismissalUsers += $actor.login
            }
            else
            {
                Write-Log -Message "Unknown dismissal actor type found $($actor.__typename). Ignoring" -Level Warning
            }
        }

        Add-Member -InputObject $item -Name 'DismissalTeams' -Value $dismissalTeams -MemberType NoteProperty -Force
        Add-Member -InputObject $item -Name 'DismissalUsers' -Value $dismissalUsers -MemberType NoteProperty -Force

        Write-Output $item
    }
}

# SIG # Begin signature block
# MIIoLwYJKoZIhvcNAQcCoIIoIDCCKBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDe30XMCRpwSjR9
# DzwHM67nZiuhQlVf2uMVUCMLZAcba6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICrtuje+rofRrGDqv6Z0HvEQ
# bKy6O3WAmOE5J90l8CbQMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCeGZ5HXO2VPwrs4Z0hg66Yrrv78GkOy49ieJi/AsavFQIrhUqoi2c4
# 8rnIVLboLPy7wKuw+oeht+eTI1dgASleTLE77sc1cFuJZ37Nsd4DCAu+tXc1aFMF
# f84KdMt5bVkPnLomNBCo+b/OGD3isW19TUVzU9BaOLcOL8MwVr5wGA7zz8Df1AcN
# WDfYM20wvlYLuCikI6D3PBO9fCkbOJfRtEsRLYeNRbL7E4TFc4/ICe1hWqGy86wc
# zgK1C/U65H+hxE/pcUy0T8HlDVP2kKytcIckfuVhURhJigq4Ei6jmlp2r8GgP0i3
# hu9HJoMV0KUbiB2Dwq/9w+o5gddmiZsyoYIXlzCCF5MGCisGAQQBgjcDAwExgheD
# MIIXfwYJKoZIhvcNAQcCoIIXcDCCF2wCAQMxDzANBglghkgBZQMEAgEFADCCAVIG
# CyqGSIb3DQEJEAEEoIIBQQSCAT0wggE5AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEINS0Wl6opCxWZnV8OM76rGuYl9UKmBkY2UJ1oH134vDJAgZlVsbo
# hQgYEzIwMjMxMTIxMTczNTI2Ljk2NFowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYT
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
# AQQwLwYJKoZIhvcNAQkEMSIEIN1rEEsX23kXcoLjXaZwsKP9fCRQ9LW4tomNI1G5
# uKmLMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgCJVABl+00/8x3UTZjD58
# Fdr3Dp+OZNnlYB6utNI/CdcwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAdB3CKrvoxfG3QABAAAB0DAiBCD7k6DsUXnwKNRlQDIrKZAy
# hvlTILPtWBwzHkvazY60CjANBgkqhkiG9w0BAQsFAASCAgCk1hohkeUvIJRnjyWw
# EFvv3Y4JtnT6KLJC9ZawL+neKdp/12YG0eqw+2C3HFkEgfJcdxGU0frGKYthTeUA
# yjPNhRToawHat+aqjFMdMqaSV4yfTLVfo5K/cs/qKFx0R1M3hhc1AjYO76iftJu3
# quicju2QwrHlZdC/3i+sEJwoUsAX5IZV1lGByi0kWj39P0qV3ojNPnQe3mSN4NkQ
# opWo1M5rYtEHWMJRt4YyF/7mY2Ic4AVcspYGsIZf9nfH9ozzvGFzBtpNkXMdDRNT
# i9yQnOXr4hk4we8LVth4/rN4vTfxVTYOeWcBcvKOe3al80vlEknI6+6ldGZ/H0CT
# nm7enI+z3JXwXWMVu4z962eGyAT0Ktp43ltB2fIrYab6yUa14WTmeEZpmh/Kg/Tp
# r78ZjZRTwDI5rLFrx5F5eaovCK16GlrRZr0SBT9ENo0iStSUMMcnUAnd5DhnWfDz
# PfkBmIPcbVbNLxrUtScz6gzKtXqgmmhjKV7ly8nhVTsgToNayPtmjFiazeXFAm+4
# JfeAeHcJALttAukRqn+xRBcx7IQ93Nu6CKFO5xxFAOJjkI0SuAU573fZnUsrAIbJ
# abAA6y0LspUGGdZcKenKUS1mzX+CRJDPkRXrtSt3e8hiah9Tyxd6AvVXl3MWfYum
# Ewgy8XL1GP/cyEunHyrjGONmYg==
# SIG # End signature block
