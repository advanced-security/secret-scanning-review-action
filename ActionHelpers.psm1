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
Returns null if the URL is empty or invalid.

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
    return ($uri.AbsolutePath -split '/')[-1]
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

.PARAMETER apiUrl
The GitHub API URL to query.

.EXAMPLE
Get-PullRequestHtmlUrl -apiUrl 'https://api.github.com/repos/owner/repo/pulls/42'
Returns: 'https://github.com/owner/repo/pull/42'
#>
function Get-PullRequestHtmlUrl {
    param(
        [string]$apiUrl
    )

    if (-not $apiUrl) {
        return $null
    }

    try {
        $uri = [uri]$apiUrl
        $response = Invoke-GHRestMethod -Method GET -Uri $uri.AbsolutePath
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
        $pullRequestNumber
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
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_title_url
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_body' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_body_url
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_comment' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_comment_url
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_review' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_review_url
            if ($htmlUrl) {
                return "[$locationType]($htmlUrl)"
            }
            return $locationType
        }
        'pull_request_review_comment' {
            $htmlUrl = Get-PullRequestHtmlUrl -apiUrl $location.details.pull_request_review_comment_url
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
Returns an empty array if the API call fails.

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER pullNumber
The pull request number.

.EXAMPLE
Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42
Returns an array of comment objects.
#>
function Get-PullRequestComment {
    param(
        [string]$owner,
        [string]$repo,
        [int]$pullNumber
    )

    $allComments = @()
    $perPage = 100
    $page = 1
    $commentUrl = "/repos/$owner/$repo/issues/$pullNumber/comments?per_page=$perPage&page=$page"

    try {
        while ($true) {
            $comments = Invoke-GHRestMethod -Method GET -Uri $commentUrl
            $allComments += $comments

            if ($comments.Count -lt $perPage) {
                break
            }
            $page++
            $commentUrl = "/repos/$owner/$repo/issues/$pullNumber/comments?per_page=$perPage&page=$page"
        }
        return $allComments
    }
    catch {
        Write-ActionDebug "Error getting PR comments: $($_.Exception.Message)"
        return @()
    }
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

.EXAMPLE
Get-DismissalRequestForAlert -owner 'owner' -repo 'repo' -alertNumber 42
Returns the dismissal request object or null.
#>
function Get-DismissalRequestForAlert {
    param(
        [string]$owner,
        [string]$repo,
        [int]$alertNumber
    )

    try {
        $url = "/repos/$owner/$repo/dismissal-requests/secret-scanning/$alertNumber"
        Write-ActionDebug "Fetching dismissal request for alert #$alertNumber from $url"
        $response = Invoke-GHRestMethod -Method GET -Uri $url
        Write-ActionDebug "Dismissal request for alert #$alertNumber returned status: $($response.status)"
        return $response
    }
    catch {
        Write-ActionDebug "Dismissal request for alert #$alertNumber failed: $($_.Exception.Message)"
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

    $dismissalStatus = if ($null -ne $dismissalRequest -and $dismissalRequest.status) { $dismissalRequest.status } else { $null }
    $hasDismissalFields = ($null -ne $alert.closure_request_comment) -or ($null -ne $alert.closure_request_reviewer_comment) -or ($null -ne $alert.closure_request_reviewer)

    $stateValue = $alert.state
    $warning = $null

    if ($dismissalStatus) {
        $stateValue = "$($alert.state) ([dismissal](# `"Dismissal request: $dismissalStatus`"))"
    }
    elseif ($hasDismissalFields -and $null -eq $dismissalRequest) {
        $stateValue = "$($alert.state) (dismissal)"
        $warning = "Alert #$($alert.number) has a dismissal request but the dismissal request API returned 404. Add 'contents: read' permission to your fine-grained token to see dismissal request details."
    }

    return @{
        stateValue      = $stateValue
        dismissalStatus = $dismissalStatus
        warning         = $warning
    }
}

Export-ModuleMember -Function Get-IdFromUrl, Get-AlertLocationType, Get-PullRequestHtmlUrl, Get-AlertLocationWithLink, Get-PullRequestComment, Write-AlertAnnotation, Get-DismissalRequestForAlert, Get-AlertDismissalState
