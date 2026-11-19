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
Pull request review comments link to the location's html_url, without an API call. When html_url is missing
(for example, on older GitHub Enterprise Server versions), the link is built on the GitHub instance the workflow
runs on (GITHUB_SERVER_URL, defaulting to https://github.com).

.PARAMETER location
The location object containing type and details of where the secret was found.

.PARAMETER prHtmlUrl
The HTML URL of the pull request.

.PARAMETER pullRequestNumber
The pull request number.

.PARAMETER expectedApiBaseUrl
The expected GitHub API base URL (e.g., https://api.github.com), used to validate the location API URLs
before sending an authenticated request for their html_url.

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
            # Prefer the location's html_url: it needs no API call and is also provided for pending or deleted review comments
            if ($location.details.html_url) {
                return "[$locationType]($($location.details.html_url))"
            }

            # Without html_url, build the link on the GitHub instance the workflow runs on from the review comment API URL:
            # <API base URL>/repos/{owner}/{repo}/pulls/comments/{id} -> <server URL>/{owner}/{repo}/pull/{pull number}#discussion_r{id}
            if ($location.details.pull_request_review_comment_url -match '/repos/(?<owner>[^/]+)/(?<repo>[^/]+)/pulls/comments/(?<id>[0-9]+)/?$') {
                $serverUrl = if ([String]::IsNullOrWhiteSpace($env:GITHUB_SERVER_URL)) { 'https://github.com' } else { $env:GITHUB_SERVER_URL.TrimEnd('/') }
                return "[$locationType]($serverUrl/$($matches.owner)/$($matches.repo)/pull/$pullRequestNumber#discussion_r$($matches.id))"
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
            # Invoke-GHRestMethod returns $null for an empty page, so skip $null entries
            $comments = @(Invoke-GHRestMethod -Method GET -Uri $commentUrl | Where-Object { $null -ne $_ })
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
Creates or updates the action's summary comment on a pull request.

.DESCRIPTION
Lists the pull request comments (see Get-PullRequestComment) and updates the first comment that contains the
action's watermark with the markdown summary. When there is no such comment, a new comment is created, unless
createIfMissing is $false. The caller passes $false when no alerts were found, so a summary comment from an
earlier run is corrected, but no new comment is added.
Returns the created or updated comment, or $null when no comment was written.
Errors are thrown with a message that describes the failed request, so the caller can decide (via the
fail-closed setting) whether the error fails the review or is reported as a warning.

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER pullNumber
The pull request number.

.PARAMETER markdownSummary
The markdown summary to write. The watermark and a timestamp are added to the comment.

.PARAMETER createIfMissing
Whether to create a comment when the pull request has no summary comment yet. Defaults to $true.

.PARAMETER apiBaseUrl
The GitHub API base URL (e.g., https://api.github.com or https://api.<tenant>.ghe.com).
Defaults to https://api.github.com.

.EXAMPLE
Publish-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42 -markdownSummary $markdownSummary -createIfMissing $false
Updates the summary comment on pull request #42 from an earlier run, and returns $null when there is none.
#>
function Publish-PullRequestComment {
    param(
        [string]$owner,
        [string]$repo,
        [int]$pullNumber,
        [string]$markdownSummary,
        [bool]$createIfMissing = $true,
        [string]$apiBaseUrl = 'https://api.github.com'
    )

    try {
        $comments = @(Get-PullRequestComment -owner $owner -repo $repo -pullNumber $pullNumber -apiBaseUrl $apiBaseUrl)
    }
    catch {
        throw "Error reading comments from '$owner/$repo' Pull Request#$pullNumber, skipping PR comment.  Ensure GITHUB_TOKEN has ``pull_requests:read`` repo permissions. (StatusCode:$(Get-ErrorStatusCode -ErrorRecord $_) Message:$($_.Exception.Message))"
    }

    $prCommentWatermark = '<!-- secret-scanning-review-pr-comment-watermark -->'
    $existingComment = $comments | Where-Object { $_.body -match $prCommentWatermark } | Select-Object -First 1
    if ($null -eq $existingComment -and -not $createIfMissing) {
        return $null
    }

    $comment = @{
        body = "{0}`n{1}`n<!-- {2} -->" -f $prCommentWatermark, $markdownSummary, (Get-Date).ToUniversalTime().ToString('o')
    }
    try {
        if ($null -ne $existingComment) {
            return Invoke-GHRestMethod -Method PATCH -Uri $existingComment.url -Body ($comment | ConvertTo-Json)
        }
        return Invoke-GHRestMethod -Method POST -Uri "$($apiBaseUrl.TrimEnd('/'))/repos/$owner/$repo/issues/$pullNumber/comments" -Body ($comment | ConvertTo-Json)
    }
    catch {
        throw "Error adding comment to '$owner/$repo' Pull Request#$pullNumber.  Ensure GITHUB_TOKEN has ``pull_requests:write`` repo permissions. (StatusCode:$(Get-ErrorStatusCode -ErrorRecord $_) Message:$($_.Exception.Message))"
    }
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
Extracts the pull request number from a review comment html_url.

.DESCRIPTION
Returns the pull request number from a review comment html_url in the format
https://<host>/<owner>/<repo>/pull/<number>#discussion_r<id>, as provided in the html_url of a
pull_request_review_comment secret scanning alert location. The owner and repository must match
the given repository (case-insensitive).
Returns $null when the URL is missing, is not in that format, or belongs to another repository.

.PARAMETER htmlUrl
The review comment html_url (location.details.html_url).

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.EXAMPLE
Get-PullRequestNumberFromReviewCommentHtmlUrl -htmlUrl 'https://github.com/owner/repo/pull/42#discussion_r12345' -owner 'owner' -repo 'repo'
Returns: 42
#>
function Get-PullRequestNumberFromReviewCommentHtmlUrl {
    param(
        [string]$htmlUrl,
        [string]$owner,
        [string]$repo
    )

    if ($htmlUrl -cmatch '^https?://[^/?#\s]+/(?<owner>[^/?#\s]+)/(?<repo>[^/?#\s]+)/pull/(?<number>[0-9]+)#discussion_r[0-9]+\z' -and
        $matches.owner -ieq $owner -and $matches.repo -ieq $repo) {
        return $matches.number -as [long]
    }
    return $null
}

<#
.SYNOPSIS
Tests whether a pull request review comment alert location belongs to a pull request.

.DESCRIPTION
Compares the pull request number in the location's html_url (see
Get-PullRequestNumberFromReviewCommentHtmlUrl) with the given pull request number, without an API
call. This also works for pending or deleted review comments, which the API cannot return (404).
Only when html_url is missing or not in that format is the review comment read from
pull_request_review_comment_url (see Get-PullRequestReviewComment) and its pull_request_url
compared with the pull request API URL. Errors from that lookup (including 404 for pending or
deleted review comments) are propagated to the caller.
Returns $false when the location has neither URL.

.PARAMETER location
The pull_request_review_comment secret scanning alert location.

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER pullNumber
The pull request number.

.PARAMETER pullRequestApiUrl
The pull request API URL (e.g., https://api.github.com/repos/owner/repo/pulls/42).

.PARAMETER expectedApiBaseUrl
The expected GitHub API base URL (e.g., https://api.github.com), used to validate
pull_request_review_comment_url before sending an authenticated request.

.EXAMPLE
Test-ReviewCommentInPullRequest -location $location -owner 'owner' -repo 'repo' -pullNumber 42 -pullRequestApiUrl 'https://api.github.com/repos/owner/repo/pulls/42' -expectedApiBaseUrl 'https://api.github.com'
Returns $true when the review comment is on pull request #42, otherwise $false.
#>
function Test-ReviewCommentInPullRequest {
    param(
        $location,
        [string]$owner,
        [string]$repo,
        [int]$pullNumber,
        [string]$pullRequestApiUrl,
        [string]$expectedApiBaseUrl = 'https://api.github.com'
    )

    $htmlUrlPullNumber = Get-PullRequestNumberFromReviewCommentHtmlUrl -htmlUrl $location.details.html_url -owner $owner -repo $repo
    if ($null -ne $htmlUrlPullNumber) {
        return $htmlUrlPullNumber -eq $pullNumber
    }

    $reviewCommentUrl = $location.details.pull_request_review_comment_url
    if (-not $reviewCommentUrl) {
        return $false
    }

    $reviewComment = Get-PullRequestReviewComment -url $reviewCommentUrl -expectedApiBaseUrl $expectedApiBaseUrl
    return $reviewComment.pull_request_url -eq $pullRequestApiUrl
}

<#
.SYNOPSIS
Extracts the pull request number from a pull request comment html_url.

.DESCRIPTION
Returns the pull request number from a pull request comment html_url in the format
https://<host>/<owner>/<repo>/pull/<number>#issuecomment-<id>, as provided in the html_url of a
pull_request_comment secret scanning alert location. The owner and repository must match
the given repository (case-insensitive).
Returns $null when the URL is missing, is not in that format, or belongs to another repository.

.PARAMETER htmlUrl
The pull request comment html_url (location.details.html_url).

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.EXAMPLE
Get-PullRequestNumberFromPullRequestCommentHtmlUrl -htmlUrl 'https://github.com/owner/repo/pull/42#issuecomment-12345' -owner 'owner' -repo 'repo'
Returns: 42
#>
function Get-PullRequestNumberFromPullRequestCommentHtmlUrl {
    param(
        [string]$htmlUrl,
        [string]$owner,
        [string]$repo
    )

    if ($htmlUrl -cmatch '^https?://[^/?#\s]+/(?<owner>[^/?#\s]+)/(?<repo>[^/?#\s]+)/pull/(?<number>[0-9]+)#issuecomment-[0-9]+\z' -and
        $matches.owner -ieq $owner -and $matches.repo -ieq $repo) {
        return $matches.number -as [long]
    }
    return $null
}

<#
.SYNOPSIS
Tests whether a pull request comment alert location belongs to a pull request.

.DESCRIPTION
Compares the pull request number in the location's html_url (see
Get-PullRequestNumberFromPullRequestCommentHtmlUrl) with the given pull request number, without an API
call. This also works for comments deleted after the secret was detected, which are no longer listed on
the pull request.
Only when html_url is missing or not in that format is the comment ID from pull_request_comment_url
looked up in the comments returned by listPullRequestComments, which is only invoked then.
Returns $false when the location has neither URL.

.PARAMETER location
The pull_request_comment secret scanning alert location.

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER pullNumber
The pull request number.

.PARAMETER listPullRequestComments
A script block that returns the pull request comments (for example, with Get-PullRequestComment).
It is only invoked when html_url cannot be used, so the caller can list the comments once, on first use.
Its success-stream output is used as the comment list, so it must send any other output (such as workflow
commands written by GitHubActions' Write-Action* functions) to the host.

.EXAMPLE
Test-PullRequestCommentInPullRequest -location $location -owner 'owner' -repo 'repo' -pullNumber 42 -listPullRequestComments { Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42 }
Returns $true when the comment is on pull request #42, otherwise $false.
#>
function Test-PullRequestCommentInPullRequest {
    param(
        $location,
        [string]$owner,
        [string]$repo,
        [int]$pullNumber,
        [scriptblock]$listPullRequestComments
    )

    $htmlUrlPullNumber = Get-PullRequestNumberFromPullRequestCommentHtmlUrl -htmlUrl $location.details.html_url -owner $owner -repo $repo
    if ($null -ne $htmlUrlPullNumber) {
        return $htmlUrlPullNumber -eq $pullNumber
    }

    $commentId = Get-IdFromUrl -url $location.details.pull_request_comment_url
    if (-not $commentId) {
        return $false
    }

    foreach ($comment in @(& $listPullRequestComments)) {
        if ($null -ne $comment -and $comment.id -eq $commentId) {
            return $true
        }
    }
    return $false
}

<#
.SYNOPSIS
Retrieves all items from a paginated GitHub API list endpoint.

.DESCRIPTION
Requests the list URL and follows the nextLink of each page. Invoke-GHRestMethod returns $null for an empty
page and a single object (not an array) for a page with one item, so each page is unrolled and $null entries
are skipped: only the listed items are returned.
Errors are propagated to the caller. Items read before the error are attached to the exception as
$_.Exception.Data['PartialResult'] so the caller can still review them.

.PARAMETER url
The list URL, including any query parameters.

.EXAMPLE
$alerts = @(Get-PagedResult -url 'https://api.github.com/repos/owner/repo/secret-scanning/alerts?per_page=100')
Returns all secret scanning alerts for the repository.
#>
function Get-PagedResult {
    param(
        [string]$url
    )

    $items = [System.Collections.Generic.List[object]]::new()
    try {
        while ($url) {
            $response = Invoke-GHRestMethod -Method GET -Uri $url -ExtendedResult $true
            foreach ($item in @($response.result)) {
                if ($null -ne $item) {
                    $items.Add($item)
                }
            }
            $url = $response.nextLink
        }
    }
    catch {
        $_.Exception.Data['PartialResult'] = $items.ToArray()
        throw
    }
    return $items.ToArray()
}

<#
.SYNOPSIS
Gets the API URL of a secret scanning alert's locations.

.DESCRIPTION
Returns the alert's locations_url. When it is missing, the URL is built from the alert number
(<API base URL>/repos/{owner}/{repo}/secret-scanning/alerts/{number}/locations), as the Python runtime does,
so the alert is still reviewed. Returns $null when the alert has neither.

.PARAMETER alert
The secret scanning alert.

.PARAMETER owner
The repository owner.

.PARAMETER repo
The repository name.

.PARAMETER apiBaseUrl
The GitHub API base URL (e.g., https://api.github.com or https://<hostname>/api/v3).
Defaults to https://api.github.com.

.EXAMPLE
Get-AlertLocationsUrl -alert @{ number = 42 } -owner 'owner' -repo 'repo' -apiBaseUrl 'https://api.github.com'
Returns: 'https://api.github.com/repos/owner/repo/secret-scanning/alerts/42/locations'
#>
function Get-AlertLocationsUrl {
    param(
        $alert,
        [string]$owner,
        [string]$repo,
        [string]$apiBaseUrl = 'https://api.github.com'
    )

    if (-not [String]::IsNullOrWhiteSpace($alert.locations_url)) {
        return $alert.locations_url
    }
    if ($null -ne $alert.number) {
        return "$($apiBaseUrl.TrimEnd('/'))/repos/$owner/$repo/secret-scanning/alerts/$($alert.number)/locations"
    }
    return $null
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
Builds the JSON for the alerts step output.

.DESCRIPTION
Returns a compressed JSON array with the metadata of each alert: number, secret_type, push_protection_bypassed,
push_protection_bypassed_by, state, resolution, validity, validity_checked_at, html_url and dismissal_request_status.
The result is always a JSON array, as documented in the README and written by the Python runtime: '[]' when there
are no alerts, and a one-item array when there is one alert.

.PARAMETER alerts
The secret scanning alerts that originated from the pull request.

.EXAMPLE
ConvertTo-AlertStepOutputJson -alerts @()
Returns: '[]'

.EXAMPLE
Add-Content -Path $env:GITHUB_OUTPUT -Value "alerts=$(ConvertTo-AlertStepOutputJson -alerts $alertsInitiatedFromPr)"
#>
function ConvertTo-AlertStepOutputJson {
    param(
        [object[]]$alerts
    )

    $stepOutput = [System.Collections.Generic.List[object]]::new()
    foreach ($alert in $alerts) {
        $stepOutput.Add(@{
            number                      = $alert.number
            secret_type                 = $alert.secret_type
            push_protection_bypassed    = $alert.push_protection_bypassed
            push_protection_bypassed_by = $alert.push_protection_bypassed_by
            state                       = $alert.state
            resolution                  = $alert.resolution
            validity                    = $alert.validity
            validity_checked_at         = $alert.validity_checked_at
            html_url                    = $alert.html_url
            dismissal_request_status    = $alert.dismissal_request_status
        })
    }

    # Pass the list with -InputObject: piping it unrolls the list, so 0 alerts would write nothing and 1 alert a bare object.
    # Depth 3 keeps the nested push_protection_bypassed_by user object (array > alert > user > user fields).
    return ConvertTo-Json -InputObject $stepOutput.ToArray() -Compress -Depth 3
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

<#
.SYNOPSIS
Extracts the pull request number from the GITHUB_REF environment variable.

.DESCRIPTION
Supports both the standard `pull_request` event ref format (refs/pull/:prNumber/merge)
and the `merge_group` event ref format used by GitHub merge queues
(refs/heads/gh-readonly-queue/:baseBranch/pr-:prNumber-:sha).
Both formats are matched from the start of the ref and are case-sensitive, as in the Python runtime, so a
base branch name that contains 'refs/pull/<n>' does not change the result. The base branch name can contain
slashes: the pull request number is read from the last '/pr-<n>-' segment.
Returns $null if the ref does not match either format.

.PARAMETER githubRef
The value of the GITHUB_REF environment variable.

.EXAMPLE
Get-PullRequestNumberFromRef -githubRef 'refs/pull/120/merge'
Returns: '120'

.EXAMPLE
Get-PullRequestNumberFromRef -githubRef 'refs/heads/gh-readonly-queue/main/pr-120-abcdef1234567890abcdef1234567890abcdef12'
Returns: '120'
#>
function Get-PullRequestNumberFromRef {
    param(
        [string]$githubRef
    )

    if ($githubRef -cmatch '^refs/pull/([0-9]+)') {
        return $matches[1]
    }

    if ($githubRef -cmatch '^refs/heads/gh-readonly-queue/.+/pr-([0-9]+)-') {
        return $matches[1]
    }

    return $null
}

Export-ModuleMember -Function Get-IdFromUrl, Get-AlertLocationType, Get-PullRequestHtmlUrl, Get-AlertLocationWithLink, Get-PullRequestComment, Publish-PullRequestComment, Get-ErrorStatusCode, Get-PullRequestReviewComment, Get-PullRequestNumberFromReviewCommentHtmlUrl, Test-ReviewCommentInPullRequest, Get-PullRequestNumberFromPullRequestCommentHtmlUrl, Test-PullRequestCommentInPullRequest, Get-PagedResult, Get-AlertLocationsUrl, Get-PullRequestCommitSha, Get-EvaluationWarningMarkdown, ConvertTo-AlertStepOutputJson, Write-AlertAnnotation, Get-DismissalRequestForAlert, Get-AlertDismissalState, Get-PullRequestNumberFromRef
