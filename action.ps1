<#
.SYNOPSIS
Reviews a pull request for secret scanning alerts that originated in it.

.DESCRIPTION
Finds the secret scanning alerts with a location in the pull request (a commit, the title, the body, a comment, a review,
or a review comment) and reports them as annotations, a workflow summary, a PR comment and the 'alerts' step output.
Runs on 'pull_request' and 'merge_group' events.

Requirements:
- A token with access to the repository's secret scanning alerts (see the token requirements in the README).
  The built-in GITHUB_TOKEN does not have this access.

.EXAMPLE
PS> $env:GITHUB_TOKEN = gh auth token
PS> $env:GITHUB_REPOSITORY = 'octo-org/octo-repo'
PS> $env:GITHUB_REF = 'refs/pull/42/merge'
PS> $env:GITHUB_STEP_SUMMARY = (New-Item -Path (Join-Path ([IO.Path]::GetTempPath()) 'step_summary.md') -ItemType File -Force).FullName
PS> ./action.ps1 -FailOnAlert $true

Reviews pull request #42 of octo-org/octo-repo outside of a workflow. The token and the PowerShellForGitHub settings are
only kept in memory for this PowerShell session.

.PARAMETER GitHubToken
        GitHub token with access to the repository's secret scanning alerts (see the token requirements in the README).
        NOTE: The GITHUB_TOKEN environment variable is used instead when it is set.

.PARAMETER FailOnAlert
        If provided, will fail the action workflow via non-zero exit code if a matching secret scanning alert is found.
        Additionally, annotations will show as errors (vs default warnings).
        Default is false.

.PARAMETER FailOnAlertExcludeClosed
        If provided, will handle failure exit code / annotations as warnings if the alert is found and the alert is marked as closed (state: 'resolved').
        Default is false.

.PARAMETER FailClosed
        If true, any GitHub API error that prevents a complete review (pull request, commits, alerts, alert locations,
        PR comment and review comment lookups, or writing the PR comment) fails the action workflow via non-zero exit code.
        If false, these errors are reported as warnings (annotations and step summary, plus the PR comment when one is
        posted because matching alerts were found) and the review continues with the data that could be retrieved.
        If a required lookup fails (pull request, commits, or alerts), the review is reported as incomplete, no PR
        comment is posted, and the action exits with code 0.
        Secrets in review comments are matched by the pull request number in the alert location's html_url, without
        an API call. Only when html_url is missing or not in the expected format is the review comment looked up; if
        it is not accessible (404, for example a pending or deleted review comment), it is counted as a match when
        true, and skipped with a warning when false.
        Secrets in PR comments are also matched by the pull request number in the alert location's html_url, so a
        comment deleted after detection is still matched. Only when html_url is missing or not in the expected format
        are the PR comments listed to look up the comment.
        Dismissal request lookups are informational only and never fail the workflow.
        Configuration errors (missing token, event other than pull_request or merge_group) always fail the workflow.
        On merge_group events, the merge queue settings of the base branch are read first (see NOTES). A merge queue
        that does not require each pull request to pass its own required checks (grouping strategy HEADGREEN) fails
        the workflow when true, and ends the review as incomplete (exit code 0) when false. An error reading the
        settings fails the workflow when true, and is reported as a warning when false.
        Default is true.

.PARAMETER DisablePRComment
        If provided, will disable the PR comment feature.
        Otherwise, a PR comment with the summary is created when matching alerts are found, and the same comment is
        updated on later runs. When a later run finds no matching alerts, that comment is updated with the new summary,
        but no comment is created, and the comment is left unchanged when the review could not be fully completed
        (FailClosed is false and errors were reported as warnings).
        Default is false.

.PARAMETER DisableWorkflowSummary
        If provided, will disable the workflow summary markdown table output.
        Default is false.

.PARAMETER SkipClosedAlerts
        If provided, will only process open alerts (skips closed/resolved alerts).
        Default is false.

.NOTES
Dependencies
    - Module versions are pinned in requirements.psd1 (PSResourceGet required resource file format)
    - Modules are vendored in ./modules and imported by path; nothing is downloaded from the PowerShell Gallery at runtime
    - Refresh ./modules with scripts/Sync-VendoredModules.ps1 (the release workflow verifies they match via -Check)
    - PowerShellForGitHub is authenticated and configured with -SessionOnly, so the token and settings are not saved
      in the user profile of the runner (PowerShellForGitHub's accessToken.txt and config.json)
    - PowerShellForGitHub logging is disabled with -DisableLogging, so it does not write PowerShellForGitHub.log (a
      list of every API URL called and command run) in the user profile of the runner

Features
    - Actions compatible
        - GitHubActions module ( https://github.com/ebekker/pwsh-github-action-base)
        - options: https://github.com/ebekker/pwsh-github-action-tools/blob/master/docs/GitHubActions/README.md
    - PR File Annotations - https://github.com/actions/toolkit/tree/main/packages/core#annotations
        - warning message - https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-a-warning-message

Merge queues
    - A merge group ref (refs/heads/gh-readonly-queue/:baseBranch/pr-:prNumber-:sha) only names the last pull request in
      the group, which is the one reviewed. The pull requests ahead of it are only covered when the merge queue requires
      each pull request to pass its own required checks (grouping strategy ALLGREEN).
    - The grouping strategy is read from the rulesets that apply to the base branch (REST, metadata permission), then
      from GraphQL (repository.mergeQueue) for a merge queue required by a branch protection rule. When the token cannot
      read it, a notice is written and the review continues. See Get-MergeGroupReviewCoverage in ActionHelpers.psm1.

.LINK
https://github.com/advanced-security/secret-scanning-review-action
#>

param(
    [string]$GitHubToken,
    [bool]$FailOnAlert,
    [bool]$FailOnAlertExcludeClosed,
    [bool]$DisablePRComment,
    [bool]$DisableWorkflowSummary,
    [bool]$SkipClosedAlerts,
    [bool]$FailClosed = $true
)

# List of supported generic secret types as per:
# https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns
# Includes non-provider patterns and copilot patterns
Set-Variable -Name GENERIC_SECRET_TYPES -Value "password,ec_private_key,generic_private_key,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_url,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key" -Option ReadOnly -Scope Script

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Load the exact module versions pinned in requirements.psd1 from the copies vendored in ./modules
# (see scripts/Sync-VendoredModules.ps1). Modules are never downloaded at runtime, so the code that runs
# is exactly what is committed at the action ref the workflow pinned.
$requiredModules = Import-PowerShellDataFile -Path (Join-Path $scriptPath 'requirements.psd1')
foreach ($moduleName in ($requiredModules.Keys | Sort-Object)) {
    $requiredVersion = $requiredModules[$moduleName].version.Trim('[', ']')
    $vendoredManifest = Join-Path -Path $scriptPath -ChildPath 'modules' -AdditionalChildPath $moduleName, $requiredVersion, "$moduleName.psd1"
    if (-not (Test-Path -Path $vendoredManifest -PathType Leaf)) {
        throw "$moduleName $requiredVersion is not vendored at '$vendoredManifest'. Run ./scripts/Sync-VendoredModules.ps1 to refresh ./modules."
    }
    # PowerShellForGitHub starts a background PowerShell Gallery update check (Start-Job) while it is
    # being imported, before Set-GitHubConfiguration -DisableUpdateCheck below can take effect. The
    # module reads its settings only from the user profile, so suppress Start-Job for the import
    # instead of writing persistent configuration on the runner.
    function global:Start-Job { }
    try {
        Import-Module -Name $vendoredManifest -Force
    }
    finally {
        Remove-Item -Path Function:\Start-Job
    }
}

# Import helper functions module
Import-Module (Join-Path $scriptPath 'ActionHelpers.psm1') -Force

#Disable Telemetry and the Gallery update check since we are accessing sensitive apis - https://github.com/microsoft/PowerShellForGitHub/blob/master/USAGE.md#telemetry
#Disable logging before any other PowerShellForGitHub command, so no PowerShellForGitHub.log is written in the user profile - https://github.com/microsoft/PowerShellForGitHub/blob/master/USAGE.md#logging
Set-GitHubConfiguration -DisableTelemetry -DisableUpdateCheck -DisableLogging -SessionOnly

#check if GITHUB_TOKEN is set
Write-ActionDebug "GitHubToken parameter is $([String]::IsNullOrWhiteSpace($GitHubToken) ? "NOT SET" : "SET" ). $($null -ne $env:GITHUB_TOKEN ? "Overridden by environment variable GITHUB_TOKEN" : $null)"
if ($null -ne $env:GITHUB_TOKEN) {
    $GitHubToken = $env:GITHUB_TOKEN
    Write-ActionDebug "GitHubToken is now set from GITHUB_TOKEN environment variable"
}

if ([String]::IsNullOrWhiteSpace($GitHubToken)) {
    Set-ActionFailed -Message "GitHubToken is not set"
}

# Authenticate PowerShellForGitHub for this session only. Without -SessionOnly, the token is saved in the user profile
# (accessToken.txt), where later jobs on a self-hosted runner could read it.
$secureString = ($GitHubToken | ConvertTo-SecureString -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential "username is ignored", $secureString
Set-GitHubAuthentication -Credential $cred -SessionOnly

$GitHubToken = $secureString = $cred = $null # clear this out now that it's no longer needed

#Init Owner/Repo/PR variables
$actionRepo = Get-ActionRepo
$OrganizationName = $actionRepo.Owner
$RepositoryName = $actionRepo.Repo

# Resolve the GitHub API base URL. GITHUB_API_URL is set by the runner and varies between
# github.com (https://api.github.com), ghe.com data-residency tenants (https://api.<tenant>.ghe.com),
# and GHES (https://<hostname>/api/v3). Fall back to public github.com for local/manual runs.
$ApiBaseUrl = if ([String]::IsNullOrWhiteSpace($env:GITHUB_API_URL)) { 'https://api.github.com' } else { $env:GITHUB_API_URL.TrimEnd('/') }
Write-ActionDebug "Using GitHub API base URL: $ApiBaseUrl"

# Resolve the GitHub GraphQL API URL, only used to read merge queue settings for merge group runs. GITHUB_GRAPHQL_URL is
# set by the runner (https://api.github.com/graphql, https://api.<tenant>.ghe.com/graphql, or
# https://<hostname>/api/graphql on GHES). For local/manual runs it is derived from the API base URL.
$GraphQlUrl = if (-not [String]::IsNullOrWhiteSpace($env:GITHUB_GRAPHQL_URL)) { $env:GITHUB_GRAPHQL_URL.TrimEnd('/') } elseif ($ApiBaseUrl -match '/api/v3$') { $ApiBaseUrl -replace '/api/v3$', '/api/graphql' } else { "$ApiBaseUrl/graphql" }

#get the pull request number from the GITHUB_REF environment variable
#supports both the 'pull_request' event (refs/pull/:prNumber/merge) and the 'merge_group' event
#used by merge queues (refs/heads/gh-readonly-queue/:baseBranch/pr-:prNumber-:sha)
$PullRequestNumber = Get-PullRequestNumberFromRef -githubRef $env:GITHUB_REF
if (-not $PullRequestNumber) {
    #https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request
    #https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#merge_group
    Set-ActionFailed -Message "Action workflow must be run on 'pull_request' or 'merge_group'.  GITHUB_REF is not set to a pull request number"
}

# Default owner and repository for PowerShellForGitHub commands, for this session only (not saved to config.json)
Set-GitHubConfiguration -DefaultOwnerName $OrganizationName -DefaultRepositoryName $RepositoryName -SessionOnly

# Errors that were reported as warnings because FailClosed is disabled
$evaluationWarnings = [System.Collections.Generic.List[string]]::new()

# Writes an "incomplete review" step summary and empty step output, then exits successfully.
# Only used when FailClosed is disabled and a required lookup failed.
function Complete-IncompleteReview {
    $prLink = $pr.html_url ? "[PR#$PullRequestNumber]($($pr.html_url))" : "PR#$PullRequestNumber"
    $incompleteSummary = "⚠️ Secret scanning review for PR#$PullRequestNumber could not be completed"
    if ($DisableWorkflowSummary) {
        Write-ActionDebug "Skipping workflow summary - DisableWorkflowSummary is set to $DisableWorkflowSummary"
    }
    elseif ($env:GITHUB_STEP_SUMMARY) {
        "# :unlock: $prLink SECRET SCANNING REVIEW SUMMARY :unlock: `n $incompleteSummary `n$(Get-EvaluationWarningMarkdown -Warnings $evaluationWarnings)" > $env:GITHUB_STEP_SUMMARY
    }
    if ($env:GITHUB_OUTPUT) {
        Add-Content -Path $env:GITHUB_OUTPUT -Value "alerts=[]"
    }
    Write-ActionWarning -Message $incompleteSummary
    exit 0
}

# Handles an API error according to FailClosed:
#   - FailClosed: fail the workflow
#   - otherwise: report a warning and continue. -Fatal ends the review as incomplete (exit 0).
function Invoke-EvaluationError {
    param(
        [string]$Message,
        [switch]$Fatal
    )
    if ($FailClosed) {
        Set-ActionFailed -Message $Message
    }
    Write-ActionWarning -Message "$Message (fail-closed is disabled, continuing)"
    $evaluationWarnings.Add($Message)
    if ($Fatal) {
        Complete-IncompleteReview
    }
}

# Merge queues: a merge group contains the base branch and every pull request ahead of it in the queue, but its ref only
# names the last pull request, which is the one reviewed. That covers the group only when the merge queue requires each
# pull request to pass its own required checks (grouping strategy ALLGREEN). When it does not (HEADGREEN), the review
# cannot be completed. When the setting cannot be read with the token, a notice is written and the review continues.
# No API call is made for pull_request events.
try {
    $mergeGroupCoverage = Get-MergeGroupReviewCoverage -githubRef $env:GITHUB_REF -owner $OrganizationName -repo $RepositoryName -pullNumber $PullRequestNumber -apiBaseUrl $ApiBaseUrl -graphQlUrl $GraphQlUrl
}
catch {
    $mergeGroupCoverage = $null
    Invoke-EvaluationError -Message $_.Exception.Message
}
switch ($mergeGroupCoverage.Status) {
    'Covered' { Write-ActionInfo $mergeGroupCoverage.Message }
    'Unverified' { Write-ActionNotice -Message $mergeGroupCoverage.Message }
    'NotCovered' { Invoke-EvaluationError -Fatal -Message $mergeGroupCoverage.Message }
}

<# API: GET PR
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#get-a-pull-request
    - format: /repos/{owner}/{repo}/pulls/{pull_number}
#>
# Call the API directly with an absolute URL rather than Get-GitHubPullRequest, because
# PowerShellForGitHub's ApiHostName only supports github.com and GHES (it appends /api/v3
# for any non-github.com host), which breaks against ghe.com data-residency tenants.
$prUrl = "$ApiBaseUrl/repos/$OrganizationName/$RepositoryName/pulls/$PullRequestNumber"
try {
    $pr = Invoke-GHRestMethod -Method GET -Uri $prUrl
    # PowerShellForGitHub may not include the 'url' field on the returned object; ensure it's set
    # to the API URL we built so location comparisons against the alert API responses succeed.
    $pr | Add-Member -MemberType NoteProperty -Name 'url' -Value $prUrl -Force
}
catch {
    $pr = $null
    Invoke-EvaluationError -Fatal -Message "Error getting '$OrganizationName/$RepositoryName' PR#$PullRequestNumber info.  Ensure the 'token' input has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}
Write-ActionInfo "PR#$PullRequestNumber '$($pr.Title)' has $($pr.commits) commit$($pr.commits -eq 1 ? '' : 's')"

<# API: GET PR Commits
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#list-commits-on-a-pull-request
    - format: /repos/{owner}/{repo}/pulls/{pull_number}/commits
    - note: This endpoint returns at most 250 commits. Larger PRs are read from the compare endpoint.
#>
try {
    $prCommitShaList = @(Get-PullRequestCommitSha -pullRequest $pr -owner $OrganizationName -repo $RepositoryName -pullNumber $PullRequestNumber -apiBaseUrl $ApiBaseUrl)
}
catch {
    Invoke-EvaluationError -Fatal -Message "Error getting '$OrganizationName/$RepositoryName' PR#$PullRequestNumber commits.  Ensure the 'token' input has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}
if ($prCommitShaList.Count -lt [int]$pr.commits) {
    Invoke-EvaluationError -Message "Only $($prCommitShaList.Count) of $($pr.commits) commits could be listed for '$OrganizationName/$RepositoryName' PR#$PullRequestNumber. Secrets in the remaining commits are not reviewed."
}
Write-ActionInfo "PR#$PullRequestNumber Commit SHA list: $($prCommitShaList -join ",")"

<# API: GET Secret Scanning Alerts
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
    - format: /repos/{owner}/{repo}/secret-scanning/alerts
    - note: This endpoint is only available for organizations and repositories in the Enterprise Cloud.
    - note: This endpoint returns ALL (both: open and resolved) secret scanning alerts.
    - note: We make two calls: one for default provider-based patterns, and another for generic secrets
#>
$perPage = 100

# First call: Get default provider-based secret scanning alerts
$repoAlertsUrl = "$ApiBaseUrl/repos/$OrganizationName/$RepositoryName/secret-scanning/alerts?per_page=$perPage"
if ($SkipClosedAlerts) {
    $repoAlertsUrl += "&state=open"
}
try {
    $alerts = [System.Collections.ArrayList]@(Get-PagedResult -url $repoAlertsUrl)
    Write-ActionInfo "Found $($alerts.Count) default secret scanning alert$($alerts.Count -eq 1 ? '' : 's') for '$OrganizationName/$RepositoryName'"
}
catch {
    # Provide helpful guidance - 99% of failures are due to using GITHUB_TOKEN which doesn't have secret scanning access
    Write-ActionInfo "NOTE: The built-in GITHUB_TOKEN does not have access to the secret scanning API."
    Write-ActionInfo "You must use a PAT with 'repo' scope, or a fine-grained PAT with 'secret_scanning_alerts:read' permission."
    Write-ActionInfo "See: https://github.com/advanced-security/secret-scanning-review-action#token-requirements"

    # Try to get the X-Accepted-GitHub-Permissions header from the error response
    # Note: This header is only returned on 403 Forbidden responses. If the token lacks basic repo access,
    # GitHub returns 404 Not Found instead (to avoid leaking repo existence), and won't include this header.
    try {
        $acceptedPermissions = $_.Exception.Response.Headers.GetValues('X-Accepted-GitHub-Permissions')
        if ($acceptedPermissions) {
            Write-ActionInfo "Required permissions for this endpoint: $($acceptedPermissions -join ', ')"
        }
    }
    catch {
        # Header not available, continue without it
    }

    Invoke-EvaluationError -Fatal -Message "Error getting '$OrganizationName/$RepositoryName' secret scanning alerts. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}

# Second call: Get generic secret scanning alerts (non-provider patterns and copilot patterns)
$genericAlertsUrl = "$ApiBaseUrl/repos/$OrganizationName/$RepositoryName/secret-scanning/alerts?per_page=$perPage&secret_type=$GENERIC_SECRET_TYPES"
if ($SkipClosedAlerts) {
    $genericAlertsUrl += "&state=open"
}
$genericAlerts = @()
try {
    $genericAlerts = @(Get-PagedResult -url $genericAlertsUrl)
    Write-ActionInfo "Found $($genericAlerts.Count) generic secret scanning alert$($genericAlerts.Count -eq 1 ? '' : 's') for '$OrganizationName/$RepositoryName'"
}
catch {
    # FailClosed is disabled: still review any generic alerts that were read before the error
    $genericAlerts = @($_.Exception.Data['PartialResult'] | Where-Object { $null -ne $_ })
    Invoke-EvaluationError -Message "Error getting generic secret scanning alerts for '$OrganizationName/$RepositoryName'. Generic secret scanning alerts that could not be read are not reviewed. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}

# Merge alerts and deduplicate by alert number
$alertNumbers = @{}
foreach ($alert in $alerts) {
    $alertNumbers[$alert.number] = $true
}
foreach ($genericAlert in $genericAlerts) {
    if ($null -ne $genericAlert -and $null -ne $genericAlert.number -and -not $alertNumbers.ContainsKey($genericAlert.number)) {
        [void]$alerts.Add($genericAlert)
        $alertNumbers[$genericAlert.number] = $true
    }
}
Write-ActionInfo "Found $($alerts.Count) total secret scanning alert$($alerts.Count -eq 1 ? '' : 's') after merging and deduplication"

# PR issue comments are only listed for 'pull_request_comment' locations without a usable html_url, once on first use
$prComments = $null
$listPrComments = {
    if ($null -eq $script:prComments) {
        try {
            $script:prComments = @(Get-PullRequestComment -owner $OrganizationName -repo $RepositoryName -pullNumber $PullRequestNumber -apiBaseUrl $ApiBaseUrl)
        }
        catch {
            # FailClosed is disabled: still review any comments that were read before the error
            $script:prComments = @($_.Exception.Data['PartialResult'] | Where-Object { $null -ne $_ })
            # This script block's output is used as the comment list, so send the workflow command to the host
            Invoke-EvaluationError -Message "Error reading comments from '$OrganizationName/$RepositoryName' PR#$PullRequestNumber. Secrets in PR comments that could not be read are not reviewed. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)" | Out-Host
        }
    }
    return $script:prComments
}

#for each secret scanning alert, keep the locations that are in the PR
$alertCount = 0
$alertsInitiatedFromPr = @()
foreach ($alert in $alerts) {
    # Use the alert's locations_url, or the URL built from its number when it is missing. An alert with neither cannot
    # be reviewed, so it is reported as an evaluation error rather than skipped (a skipped alert would make an
    # incomplete review look complete).
    $alertLocationsUrl = Get-AlertLocationsUrl -alert $alert -owner $OrganizationName -repo $RepositoryName -apiBaseUrl $ApiBaseUrl
    if (-not $alertLocationsUrl) {
        Invoke-EvaluationError -Message "A '$OrganizationName/$RepositoryName' secret scanning alert without a number or locations_url could not be reviewed."
        continue
    }

    <# API: GET Secret Scanning Alert List Locations
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
    - format: /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations
    - returns: 1 "location" object per file where secret detected
    - note: details.commit_sha - SHA of the commit where the secret was detected
    #>
    $repoAlertLocationUrl = [uri]"$($alertLocationsUrl)?per_page=$perPage"
    $locations = @()
    try {
        $locations = @(Get-PagedResult -url $repoAlertLocationUrl.AbsoluteUri)
        Write-ActionDebug "Found $($locations.Count) secret scanning alert locations for alert #$($alert.number)"
    }
    catch {
        # FailClosed is disabled: still review any location pages that were read before the error
        $locations = @($_.Exception.Data['PartialResult'] | Where-Object { $null -ne $_ })
        Write-ActionDebug "Alert number: $($alert.number), locations_url: '$alertLocationsUrl'"
        Invoke-EvaluationError -Message "Error getting '$OrganizationName/$RepositoryName' secret scanning alert #$($alert.number) locations.  Ensure the 'token' input has proper permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
    }

    $locationMatches = @()
    foreach ($location in $locations) {
        $matchFound = $false

        # Check different location types
        switch ($location.type) {
            'commit' {
                $alertInitialCommitSha = $location.details.commit_sha
                if ($alertInitialCommitSha -in $prCommitShaList) {
                    Write-ActionDebug "MATCH FOUND: Alert $($alert.number) is in a commit in the PR."
                    $matchFound = $true
                }
            }
            'pull_request_title' {
                if ($location.details.pull_request_title_url -eq $pr.url) {
                    Write-ActionDebug "MATCH FOUND: Alert $($alert.number) is in the PR title."
                    $matchFound = $true
                }
            }
            'pull_request_body' {
                if ($location.details.pull_request_body_url -eq $pr.url) {
                    Write-ActionDebug "MATCH FOUND: Alert $($alert.number) is in the PR body."
                    $matchFound = $true
                }
            }
            'pull_request_comment' {
                # The PR number is read from the location's html_url without an API call, so a comment deleted after
                # detection is still matched to the PR it was posted on. Only when html_url is missing or not in the
                # expected format are the PR comments listed (once) and the comment looked up by its ID.
                if (Test-PullRequestCommentInPullRequest -location $location -owner $OrganizationName -repo $RepositoryName -pullNumber $PullRequestNumber -listPullRequestComments $listPrComments) {
                    Write-ActionDebug "MATCH FOUND: Alert $($alert.number) is in a PR comment."
                    $matchFound = $true
                }
            }
            'pull_request_review' {
                # Remove '/reviews/{review_id}' from the end of the pull_request_review_url to compare against the PR URL
                # Example: https://api.github.com/repos/owner/repo/pulls/123/reviews/456 -> https://api.github.com/repos/owner/repo/pulls/123
                $reviewUri = [uri]$location.details.pull_request_review_url
                $pathSegments = $reviewUri.AbsolutePath.TrimEnd('/') -split '/'
                # Keep all segments except the last 2 ("reviews" and "{review_id}"), but only if there are enough segments
                if ($pathSegments.Length -ge 3) {
                    $shortenedPath = ($pathSegments[0..($pathSegments.Length - 3)] -join '/')
                    $shortenedPrReviewUrl = "$($reviewUri.Scheme)://$($reviewUri.Host)$shortenedPath"
                    if ($shortenedPrReviewUrl -eq $pr.url) {
                        Write-ActionDebug "MATCH FOUND: Alert $($alert.number) is in a PR review."
                        $matchFound = $true
                    }
                }
                else {
                    Write-ActionDebug "Skipping PR review URL comparison for alert $($alert.number): unexpected path format '$($reviewUri.AbsolutePath)'."
                }
            }
            'pull_request_review_comment' {
                # The PR number is read from the location's html_url without an API call, so pending review
                # comments (which the API cannot return, 404) and comments deleted after detection are matched
                # only to the PR they were posted on. Only when html_url is missing or not in the expected format
                # is the review comment looked up to compare its pull_request_url. Then a 404 is counted as a
                # match when FailClosed is enabled, and skipped with a warning otherwise.
                $reviewCommentUrl = $location.details.pull_request_review_comment_url
                try {
                    if (Test-ReviewCommentInPullRequest -location $location -owner $OrganizationName -repo $RepositoryName -pullNumber $PullRequestNumber -pullRequestApiUrl $pr.url -expectedApiBaseUrl $ApiBaseUrl) {
                        Write-ActionDebug "MATCH FOUND: Alert $($alert.number) is in a PR review comment."
                        $matchFound = $true
                    }
                }
                catch {
                    if ((Get-ErrorStatusCode -ErrorRecord $_) -eq 404) {
                        if ($FailClosed) {
                            Write-ActionInfo "Alert $($alert.number) review comment '$reviewCommentUrl' is not accessible (pending or deleted). Counting it as a match because fail-closed is enabled."
                            $matchFound = $true
                        }
                        else {
                            $warningMessage = "Alert $($alert.number) review comment '$reviewCommentUrl' is not accessible (pending or deleted) and could not be verified for PR#$PullRequestNumber."
                            Write-ActionWarning -Message "$warningMessage (fail-closed is disabled, continuing)"
                            $evaluationWarnings.Add($warningMessage)
                        }
                    }
                    else {
                        Invoke-EvaluationError -Message "Error reading review comment '$reviewCommentUrl' for alert $($alert.number). (StatusCode:$(Get-ErrorStatusCode -ErrorRecord $_) Message:$($_.Exception.Message)"
                    }
                }
            }
        }

        if ($matchFound) {
            $locationMatches += $location
        }
    }

    #if there are any matches, then add alert to the global list of alerts/locations that match the PR
    if ($locationMatches.Count -gt 0) {
        $null = $alert | Add-Member -MemberType NoteProperty -Name 'locations' -Value $locationMatches -PassThru
        $alertsInitiatedFromPr += $alert
    }

    #output progress
    $alertCount++
    $progress = [math]::Round(($alertCount / $alerts.count) * 100, 0)
    Write-Progress -Activity "Secret Scanning Alert Search" -Status "Progress: $progress%" -PercentComplete $progress
}

#Clear progress bar and finish
Write-Progress -Activity "Secret Scanning Alert Search" -Completed

#Build output for each alert that was found
#   * an Error/Warning Actions annotation
#   * add a step summary markdown table row of the alert details
$numSecretsAlertsDetected = 0
$numSecretsAlertLocationsDetected = 0
$shouldFailAction = $false
$markdownSummaryTableRows = $null

foreach ($alert in $alertsInitiatedFromPr) {
    $numSecretsAlertsDetected++

    # Fetch dismissal request for this alert (may return null if feature is not enabled or no request exists)
    $dismissalRequest = Get-DismissalRequestForAlert -owner $OrganizationName -repo $RepositoryName -alertNumber $alert.number -apiBaseUrl $ApiBaseUrl
    $dismissalState = Get-AlertDismissalState -alert $alert -dismissalRequest $dismissalRequest
    $dismissalStatus = $dismissalState.dismissalStatus
    $alert | Add-Member -MemberType NoteProperty -Name 'dismissal_request_status' -Value $dismissalStatus -Force

    $stateValue = $dismissalState.stateValue
    if ($dismissalState.warning) {
        Write-ActionWarning $dismissalState.warning
    }

    foreach ($location in $alert.locations) {
        $numSecretsAlertLocationsDetected++
        $alertType = $location.type
        $alertLocation = Get-AlertLocationType -location $location
        $message = "A $($alert.state -eq 'resolved' ? "Closed as '$($alert.resolution)'" : 'New') Secret Detected in Pull Request #$PullRequestNumber. '$($alert.secret_type_display_name)' Secret: $($alert.html_url) Location: $alertLocation"
        $shouldBypass = ($alert.state -eq 'resolved') -and $FailOnAlertExcludeClosed

        if ($FailOnAlert -and !$shouldBypass) {
            Write-AlertAnnotation -Level 'Error' -Message $message -Location $location -AlertType $alertType
            $shouldFailAction = $true
            $passFail = '[🔴](# "Error")'
        }
        else {
            Write-AlertAnnotation -Level 'Warning' -Message $message -Location $location -AlertType $alertType
            $passFail = '[🟡](# "Warning")'
        }

        # Build location value for the markdown table
        $locationValue = Get-AlertLocationWithLink -location $location -prHtmlUrl $pr.html_url -pullRequestNumber $PullRequestNumber -expectedApiBaseUrl $ApiBaseUrl

        # Format validity with checked date as hover tooltip
        $validityValue = $null -eq $alert.validity ? '❌' : $alert.validity
        if ($alert.validity_checked_at) {
            $validityValue = "[$validityValue](# `"$($alert.validity_checked_at)`")"
        }

        $markdownSummaryTableRows += "| $passFail | :key: [$($alert.number)]($($alert.html_url)) | $($alert.secret_type_display_name) | $stateValue | $($null -eq $alert.resolution ? '❌' : $alert.resolution) | $($alert.push_protection_bypassed) | $validityValue | $locationValue | `n"
    }
}

# One line summary of alerts found
$summary = "$($numSecretsAlertsDetected -gt 0 ? '🚨' : '👍') Found [$numSecretsAlertsDetected] secret scanning alert$($numSecretsAlertsDetected -eq 1 ? '' : 's') across [$numSecretsAlertLocationsDetected] location$($numSecretsAlertLocationsDetected -eq 1 ? '' : 's') that originated from PR#$PullRequestNumber"

#Actions Markdown Summary - https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary
#flashy! - https://github.blog/2022-05-09-supercharging-github-actions-with-job-summaries/
$markdownSummary = "# :unlock: [PR#$PullRequestNumber]($($pr.html_url)) SECRET SCANNING REVIEW SUMMARY :unlock: `n $summary `n"

#build a markdown table of any alerts
if ($alertsInitiatedFromPr.Count -gt 0) {

    $markdownSummary += @"
| Status 🚦 | Secret Alert 🚨 | Secret Type 𝌎 | State :question: | Resolution :checkered_flag: | Push Bypass 👋 | Validity :white_check_mark: | Location #️⃣ |
| --- | --- | --- | --- | --- | --- | --- | --- |`n
"@

    $markdownSummary += $markdownSummaryTableRows
}

# PR Comment Summary, unless disabled:
#   - alerts were found: create the comment, or update the one from an earlier run
#   - no alerts were found: only update a comment from an earlier run, so it no longer reports alerts that are gone.
#     No comment is created, and an incomplete review (errors reported as warnings) leaves the earlier comment unchanged.
if ($DisablePRComment) {
    Write-ActionDebug "Skipping PR comment update - DisablePRComment is set to $DisablePRComment"
}
elseif ($alertsInitiatedFromPr.Count -eq 0 -and $evaluationWarnings.Count -gt 0) {
    Write-ActionDebug "Skipping PR comment update - no alerts were found, but the review could not be fully completed"
}
else {
    <# API: LIST, UPDATE, or CREATE PR COMMENTS
    - docs: https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#list-issue-comments
    - docs: https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#update-an-issue-comment
    - docs: https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#create-an-issue-comment
    - format: /repos/{owner}/{repo}/issues/{pull_number}/comments
    #>
    try {
        $commentResponse = Publish-PullRequestComment -owner $OrganizationName -repo $RepositoryName -pullNumber $PullRequestNumber -markdownSummary ($markdownSummary + (Get-EvaluationWarningMarkdown -Warnings $evaluationWarnings)) -createIfMissing ($alertsInitiatedFromPr.Count -gt 0) -apiBaseUrl $ApiBaseUrl
        if ($null -ne $commentResponse) {
            Write-ActionInfo "Updated PR Comment: $($commentResponse.html_url)"
        }
        else {
            Write-ActionDebug "Skipping PR comment update - no alerts were found and there is no PR comment from an earlier run to update"
        }
    }
    catch {
        Invoke-EvaluationError -Message $_.Exception.Message
    }
}

# Include any errors that were reported as warnings (FailClosed disabled)
$markdownSummary += Get-EvaluationWarningMarkdown -Warnings $evaluationWarnings

# Output Step Summary - To the GITHUB_STEP_SUMMARY environment file. GITHUB_STEP_SUMMARY is unique for each step in a job
if ($DisableWorkflowSummary) {
    Write-ActionDebug "Skipping workflow summary - DisableWorkflowSummary is set to $DisableWorkflowSummary"
}
else {
    $markdownSummary > $env:GITHUB_STEP_SUMMARY
    Write-ActionDebug "Markdown Summary from env var GITHUB_STEP_SUMMARY: '$env:GITHUB_STEP_SUMMARY' "
    Write-ActionDebug $(Get-Content $env:GITHUB_STEP_SUMMARY)
}

# Create step output JSON with alert metadata: always a JSON array ('[]' when no alerts were found)
$stepOutputJson = ConvertTo-AlertStepOutputJson -alerts $alertsInitiatedFromPr

# Write step output to GITHUB_OUTPUT environment file
if ($env:GITHUB_OUTPUT) {
    try {
        Add-Content -Path $env:GITHUB_OUTPUT -Value "alerts=$stepOutputJson"
        Write-ActionDebug "Step output written to GITHUB_OUTPUT: $stepOutputJson"
    }
    catch {
        Write-ActionWarning "Failed to write step output to GITHUB_OUTPUT: $($_.Exception.Message)"
    }
}

#Output Message Summary and set exit code
# -  any error alerts were found in FailOnAlert mode (observing FailOnAlertExcludeClosed), exit with error code 1
# -  otherwise, return 0
if ($alertsInitiatedFromPr.Count -gt 0 -and $shouldFailAction) {
    Set-ActionFailed -Message $summary
}
else {
    Write-ActionInfo $summary
    exit 0
}
