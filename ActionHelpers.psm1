<#
.SYNOPSIS
Helper functions for the secret scanning review action.

.DESCRIPTION
This module contains helper functions that can be tested independently.
Functions that call external APIs (Invoke-GHRestMethod) can be tested with mocks.
#>

<#
.SYNOPSIS
Extracts the last segment (ID) from a URL path.

.DESCRIPTION
Takes a URL and returns the last path segment, which is typically an ID.
Trailing slashes are ignored. Returns null if the URL is empty or invalid.

.PARAMETER url
The URL string to extract the ID from.

.EXAMPLE
Get-IdFromUrl -url 'https://api.github.com/repos/owner/repo/pulls/comments/12345'
Returns: '12345'
#>
function Get-IdFromUrl {
    param(
        [string]$url
    )

    if (-not $url) {
        return $null
    }

    $uri = [uri]$url
    return ($uri.AbsolutePath.TrimEnd('/') -split '/')[-1]
}

<#
.SYNOPSIS
Gets a human-readable description of an alert location type.

.DESCRIPTION
Converts the location type from the GitHub API into a user-friendly description.

.PARAMETER location
The location object containing a 'type' field and associated details.

.EXAMPLE
Get-AlertLocationType -location @{ type = 'commit'; details = @{ commit_sha = 'abc123' } }
Returns: 'Commit SHA abc123'
#>
function Get-AlertLocationType {
    param($location)

    if (-not $location.type) {
        throw "Alert location does not have a 'type' field."
    }

    switch ($location.type) {
        'commit' {
            return "Commit SHA $($location.details.commit_sha)"
        }
        'pull_request_title' {
            return "Pull request title"
        }
        'pull_request_body' {
            return "Pull request body"
        }
        'pull_request_comment' {
            return "Pull request comment"
        }
        'pull_request_review' {
            return "Pull request review"
        }
        'pull_request_review_comment' {
            return "Pull request review comment"
        }
        default {
            return $null
        }
    }
}

<#
.SYNOPSIS
Retrieves the html_url for a GitHub API resource.

.DESCRIPTION
Makes an API call to get the html_url for a pull request related resource.
Returns null if the API call fails (e.g., 404 for deleted comments).
Validates that the URL host matches the expected API base URL to prevent SSRF.

.PARAMETER apiUrl
The GitHub API URL to query.

.PARAMETER expectedApiBaseUrl
The expected GitHub API base URL (e.g., https://api.github.com). Used to validate
the apiUrl host before sending authenticated requests.

.EXAMPLE
Get-PullRequestHtmlUrl -apiUrl 'https://api.github.com/repos/owner/repo/pulls/42' -expectedApiBaseUrl 'https://api.github.com'
Returns: 'https://github.com/owner/repo/pull/42'
#>
function Get-PullRequestHtmlUrl {
    param(
        [string]$apiUrl,
        [string]$expectedApiBaseUrl
    )

    if (-not $apiUrl) {
        return $null
    }

    # Validate URL host matches expected API host to prevent SSRF token exfiltration
    try {
        $parsedUrl = [uri]$apiUrl
        $parsedExpected = [uri]$expectedApiBaseUrl
        if ($parsedUrl.Scheme -ne 'https') {
            Write-ActionWarning "Refusing to send credentials to non-HTTPS URL: $apiUrl"
            return $null
        }
        if ($parsedUrl.Host -ne $parsedExpected.Host) {
            Write-ActionWarning "URL host '$($parsedUrl.Host)' does not match expected API host '$($parsedExpected.Host)'"
            return $null
        }
    }
    catch {
        Write-ActionWarning "Invalid URL: $apiUrl"
        return $null
    }

    try {
        # Pass the absolute URI through to Invoke-GHRestMethod so the request goes to the host
        # provided by the API (api.github.com, api.<tenant>.ghe.com, etc.) rather than relying on
        # PowerShellForGitHub's ApiHostName configuration, which only supports github.com and GHES.
        $uri = [uri]$apiUrl
        $response = Invoke-GHRestMethod -Method GET -Uri $uri.AbsoluteUri
        return $response.html_url
    }
    catch {
        # Silently return null for pending/deleted review comments (404 expected)
        return $null
    }
}

<#
.SYNOPSIS
Generates a markdown hyperlink for an alert location.

.DESCRIPTION
Creates a markdown link to the specific location where a secret was detected.
Handles various location types including commits, PR titles, comments, and reviews.

.PARAMETER location
The location object containing type and details of where the secret was found.

.PARAMETER prHtmlUrl
The HTML URL of the pull request.

.PARAMETER pullRequestNumber
The pull request number.

.EXAMPLE
Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://github.com/owner/repo/pull/42' -pullRequestNumber 42
Returns: '[abc123d](https://github.com/owner/repo/pull/42/commits/abc123def456789)'
#>
function Get-AlertLocationWithLink {
    param(
        $location,
        $prHtmlUrl,
        $pullRequestNumber,
        [string]$expectedApiBaseUrl
    )

    if (-not $location.type) {
        throw "Alert location does not have a 'type' field."
    }

    $locationType = Get-AlertLocationType -location $location

    switch ($location.type) {
        'commit' {
            $commitSha = $location.details.commit_sha.SubString(0, 7)
            return "[$commitSha]($prHtmlUrl/commits/$($location.details.commit_sha))"
        }
        'pull_request_title' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_title_url -expectedApiBaseUrl $expectedApiBaseUrl
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_body' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_body_url -expectedApiBaseUrl $expectedApiBaseUrl
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_comment' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_comment_url -expectedApiBaseUrl $expectedApiBaseUrl
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_review' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_review_url -expectedApiBaseUrl $expectedApiBaseUrl
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_review_comment' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_review_comment_url -expectedApiBaseUrl $expectedApiBaseUrl
            if ($htmlUrl) {
                # API call succeeded - use the html_url from the response
                return "[$locationType]($htmlUrl)"
            }

            # If we reach here, $htmlUrl is null (API call failed, likely 404 for pending/deleted review comment)
            # Fallback: manually construct the GitHub URL from the comment ID
            if ($location.details.pull_request_review_comment_url) {
                $commentId = Get-IdFromUrl -url $location.details.pull_request_review_comment_url
                $uri = [uri]$location.details.pull_request_review_comment_url
                $pathSegments = $uri.AbsolutePath -split '/'
                # Extract repo path: /repos/owner/repo/pulls/comments/12345 -> owner/repo
                $owner = $pathSegments[2]
                $repo = $pathSegments[3]
                $constructedUrl = "https://github.com/$owner/$repo/pull/$pullRequestNumber#discussion_r$commentId"
                return "[$locationType]($constructedUrl)"
            }

            return $locationType
        }
        default {
            return $locationType
        }
    }
}

<#
.SYNOPSIS
Retrieves all comments for a pull request.

.DESCRIPTION
Fetches all comments from a pull request using pagination.
Errors are propagated to the caller so it can decide (via the fail-closed setting)
whether a failed lookup should fail the review or be reported as a warning.
Comments read before the error are attached to the exception as
$_.Exception.Data['PartialResult'] so the caller can still review them.
.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER pullNumber
The pull request number.

.PARAMETER apiBaseUrl
The GitHub API base URL (e.g., https://api.github.com or https://api.<tenant>.ghe.com).
Defaults to https://api.github.com for backwards compatibility.

.EXAMPLE
Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42
Returns an array of comment objects.
#>
function Get-PullRequestComment {
    param(
        [string]$owner,
        [string]$repo,
        [int]$pullNumber,
        [string]$apiBaseUrl = 'https://api.github.com'
    )

    $allComments = @()
    $perPage = 100
    $page = 1
    $baseUrl = $apiBaseUrl.TrimEnd('/')
    $commentUrl = "$baseUrl/repos/$owner/$repo/issues/$pullNumber/comments?per_page=$perPage&page=$page"

    while ($true) {
        try {
            $comments = @(Invoke-GHRestMethod -Method GET -Uri $commentUrl)
        }
        catch {
            $_.Exception.Data['PartialResult'] = $allComments
            throw
        }
        $allComments += $comments

        if ($comments.Count -lt $perPage) {
            break
        }
        $page++
        $commentUrl = "$baseUrl/repos/$owner/$repo/issues/$pullNumber/comments?per_page=$perPage&page=$page"
    }
    return $allComments
}

<#
.SYNOPSIS
Gets the HTTP status code from an API error record.

.DESCRIPTION
Returns the HTTP status code of the response attached to the exception in an
ErrorRecord (as thrown by Invoke-GHRestMethod), or null if none is available
(for example, network failures or non-HTTP errors).

.PARAMETER ErrorRecord
The ErrorRecord captured in a catch block ($_).

.EXAMPLE
try { Invoke-GHRestMethod -Method GET -Uri $url } catch { $statusCode = Get-ErrorStatusCode -ErrorRecord $_ }
#>
function Get-ErrorStatusCode {
    param(
        $ErrorRecord
    )

    try {
        $statusCode = $ErrorRecord.Exception.Response.StatusCode
        if ($null -ne $statusCode) {
            return [int]$statusCode
        }
    }
    catch {
        Write-ActionDebug "Unable to read HTTP status code from error: $($_.Exception.Message)" | Out-Host
    }
    return $null
}

<#
.SYNOPSIS
Retrieves a pull request review comment.

.DESCRIPTION
Fetches a pull request review comment from its API URL so the caller can verify which
pull request it belongs to (via pull_request_url). Validates that the URL uses HTTPS and
targets the expected API host before sending an authenticated request.
Errors (including 404 for pending or deleted review comments) are propagated to the caller.

.PARAMETER url
The pull request review comment API URL (location.details.pull_request_review_comment_url).

.PARAMETER expectedApiBaseUrl
The expected GitHub API base URL (e.g., https://api.github.com).

.EXAMPLE
Get-PullRequestReviewComment -url 'https://api.github.com/repos/owner/repo/pulls/comments/123' -expectedApiBaseUrl 'https://api.github.com'
Returns the review comment object, including pull_request_url.
#>
function Get-PullRequestReviewComment {
    param(
        [string]$url,
        [string]$expectedApiBaseUrl = 'https://api.github.com'
    )

    $parsedUrl = [uri]$url
    $parsedExpected = [uri]$expectedApiBaseUrl
    if ($parsedUrl.Scheme -ne 'https') {
        throw "Refusing to send credentials to non-HTTPS URL: $url"
    }
    if ($parsedUrl.Host -ne $parsedExpected.Host) {
        throw "URL host '$($parsedUrl.Host)' does not match expected API host '$($parsedExpected.Host)'"
    }

    return Invoke-GHRestMethod -Method GET -Uri $parsedUrl.AbsoluteUri
}

<#
.SYNOPSIS
Retrieves the commit SHAs for a pull request.

.DESCRIPTION
Lists all commits on a pull request, following pagination. The list commits on a pull request
endpoint returns at most 250 commits, so when the pull request reports more commits than were
returned, the commits are re-read from the compare endpoint (base branch...head SHA), which
paginates past that limit. The caller should compare the returned count against the pull
request's commit count to detect an incomplete list. Errors are propagated to the caller.

.PARAMETER pullRequest
The pull request object (from GET /repos/{owner}/{repo}/pulls/{pull_number}).

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER pullNumber
The pull request number.

.PARAMETER apiBaseUrl
The GitHub API base URL. Defaults to https://api.github.com.

.EXAMPLE
$shas = @(Get-PullRequestCommitSha -pullRequest $pr -owner 'owner' -repo 'repo' -pullNumber 42 -apiBaseUrl $ApiBaseUrl)
#>
function Get-PullRequestCommitSha {
    param(
        $pullRequest,
        [string]$owner,
        [string]$repo,
        [int]$pullNumber,
        [string]$apiBaseUrl = 'https://api.github.com'
    )

    $baseUrl = $apiBaseUrl.TrimEnd('/')
    $commitShas = [System.Collections.Generic.List[string]]::new()
    $url = "$baseUrl/repos/$owner/$repo/pulls/$pullNumber/commits?per_page=100"
    while ($url) {
        $response = Invoke-GHRestMethod -Method GET -Uri $url -ExtendedResult $true
        foreach ($commit in @($response.result)) {
            if ($commit.sha) { $commitShas.Add($commit.sha) }
        }
        $url = $response.nextLink
    }

    $expectedCount = [int]$pullRequest.commits
    if ($commitShas.Count -lt $expectedCount -and $pullRequest.base.ref -and $pullRequest.head.sha) {
        # Send-ActionCommand returns the workflow command string, so route it to the host to keep it out of the returned SHAs
        Write-ActionDebug "PR#$pullNumber reports $expectedCount commits but only $($commitShas.Count) were listed. Reading commits from the compare endpoint." | Out-Host
        $compareShas = [System.Collections.Generic.List[string]]::new()
        $url = "$baseUrl/repos/$owner/$repo/compare/$([uri]::EscapeDataString($pullRequest.base.ref))...$($pullRequest.head.sha)?per_page=100"
        while ($url) {
            $response = Invoke-GHRestMethod -Method GET -Uri $url -ExtendedResult $true
            foreach ($commit in @($response.result.commits)) {
                if ($commit.sha) { $compareShas.Add($commit.sha) }
            }
            $url = $response.nextLink
        }
        if ($compareShas.Count -gt $commitShas.Count) {
            $commitShas = $compareShas
        }
    }

    return $commitShas.ToArray()
}

<#
.SYNOPSIS
Builds the markdown section listing errors that were tolerated because fail-closed is disabled.

.DESCRIPTION
Returns a markdown warning block listing each error message, or an empty string when there are none.

.PARAMETER Warnings
The list of error messages that were reported as warnings.

.EXAMPLE
Get-EvaluationWarningMarkdown -Warnings @('Error getting generic secret scanning alerts')
#>
function Get-EvaluationWarningMarkdown {
    param(
        [string[]]$Warnings
    )

    if (-not $Warnings -or $Warnings.Count -eq 0) {
        return ''
    }

    $markdown = "`n> [!WARNING]`n> The secret scanning review could not be fully completed. ``fail-closed`` is disabled, so these errors did not fail the workflow:`n"
    foreach ($warning in $Warnings) {
        $markdown += "> - $(($warning -replace '\r?\n', ' ').Trim())`n"
    }
    return $markdown
}

<#
.SYNOPSIS
Writes an alert annotation for commit-type locations.

.DESCRIPTION
Creates a GitHub Actions annotation (warning or error) associated with a specific file,
line, and column. Only processes annotations for commit-type locations.

.PARAMETER Level
The severity level of the annotation ('Error' or 'Warning').

.PARAMETER Message
The annotation message to display.

.PARAMETER Location
The location object containing file path and position details.

.PARAMETER AlertType
The type of alert location (only 'commit' type will generate annotations).

.EXAMPLE
Write-AlertAnnotation -Level 'Error' -Message 'Secret found' -Location $location -AlertType 'commit'

.LINK
https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message
https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-a-warning-message
#>
function Write-AlertAnnotation {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Error', 'Warning')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        $Location,

        [Parameter(Mandatory = $true)]
        [string]$AlertType
    )

    # Only write annotations for commit type locations
    if ($AlertType -ne 'commit') {
        return
    }

    if ($Level -eq 'Error') {
        Write-ActionError -Message $Message -File $Location.details.path -Line $Location.details.start_line -Col $Location.details.start_column
    }
    else {
        Write-ActionWarning -Message $Message -File $Location.details.path -Line $Location.details.start_line -Col $Location.details.start_column
    }
}

<#
.SYNOPSIS
Gets the dismissal request for a secret scanning alert.

.DESCRIPTION
Fetches the dismissal request status for a secret scanning alert using the
secret scanning alert dismissal requests API. Returns null if no dismissal
request exists or the API call fails (e.g., feature not enabled).

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER alertNumber
The secret scanning alert number.

.PARAMETER apiBaseUrl
The GitHub API base URL (e.g., https://api.github.com or https://api.<tenant>.ghe.com).
Defaults to https://api.github.com for backwards compatibility.

.EXAMPLE
Get-DismissalRequestForAlert -owner 'owner' -repo 'repo' -alertNumber 42
Returns the dismissal request object or null.
#>
function Get-DismissalRequestForAlert {
    param(
        [string]$owner,
        [string]$repo,
        [int]$alertNumber,
        [string]$apiBaseUrl = 'https://api.github.com'
    )

    # NOTE: Invoke-GHRestMethod does not throw on HTTP errors (e.g. 403/404).
    # It returns the error response body as a PSObject with a 'message' property.
    # See: https://github.com/microsoft/PowerShellForGitHub/wiki/Invoke-GHRestMethod
    # Use -ExtendedResult if you need to inspect the HTTP status code directly.
    try {
        $url = "$($apiBaseUrl.TrimEnd('/'))/repos/$owner/$repo/dismissal-requests/secret-scanning/$alertNumber"
        $response = Invoke-GHRestMethod -Method GET -Uri $url
        if ($response.message) {
            return $null
        }
        return $response
    }
    catch {
        Write-ActionDebug "Unable to retrieve dismissal request for alert $alertNumber in $owner/${repo}: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
Formats the state column value with dismissal request information.

.DESCRIPTION
Returns a formatted state string based on the dismissal request status. If a dismissal
request was fetched successfully, appends a hover tooltip link. If the alert has
closure_request fields but the dismissal API returned null (404), appends plain
'(dismissal)' text indicating the token likely lacks 'contents: read' permission.

.PARAMETER alert
The secret scanning alert object from the API.

.PARAMETER dismissalRequest
The dismissal request object, or null if the API call failed/returned 404.

.EXAMPLE
Get-AlertDismissalState -alert $alert -dismissalRequest $response
Returns @{ stateValue = 'open ([dismissal](# "Dismissal request: pending"))'; warning = $null }

.EXAMPLE
Get-AlertDismissalState -alert $alertWithClosureFields -dismissalRequest $null
Returns @{ stateValue = 'open (dismissal)'; warning = 'Alert #2 has a dismissal...' }
#>
function Get-AlertDismissalState {
    param(
        [PSObject]$alert,
        $dismissalRequest
    )

    # Error responses are already filtered out by Get-DismissalRequestForAlert (checks $response.message),
    # so any non-null dismissalRequest here has a valid status from the API.
    $dismissalStatus = if ($null -ne $dismissalRequest -and $dismissalRequest.status) { $dismissalRequest.status } else { $null }
    $hasDismissalFields = ($null -ne $alert.closure_request_comment) -or ($null -ne $alert.closure_request_reviewer_comment) -or ($null -ne $alert.closure_request_reviewer)

    $stateValue = $alert.state
    $warning = $null

    if ($dismissalStatus) {
        $stateValue = "$($alert.state) ([dismissal](# `"Dismissal request: $dismissalStatus`"))"
    }
    elseif ($hasDismissalFields -and -not $dismissalStatus) {
        $stateValue = "$($alert.state) (dismissal)"
        $warning = "Alert #$($alert.number) has a dismissal request but the dismissal request status could not be retrieved. Ensure your token has 'contents: read' permission for dismissal request details."
    }

    return @{
        stateValue      = $stateValue
        dismissalStatus = $dismissalStatus
        warning         = $warning
    }
}

Export-ModuleMember -Function Get-IdFromUrl, Get-AlertLocationType, Get-PullRequestHtmlUrl, Get-AlertLocationWithLink, Get-PullRequestComment, Get-ErrorStatusCode, Get-PullRequestReviewComment, Get-PullRequestCommitSha, Get-EvaluationWarningMarkdown, Write-AlertAnnotation, Get-DismissalRequestForAlert, Get-AlertDismissalState
