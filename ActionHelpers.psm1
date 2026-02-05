<# 
.SYNOPSIS
Helper functions for the secret scanning review action.

.DESCRIPTION
This module contains helper functions that can be tested independently.
Functions that call external APIs (Invoke-GHRestMethod) can be tested with mocks.
#>

# Helper function to extract ID from URL path
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

# Helper function to get alert location type description
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

# Helper function to get html_url for PR-related locations
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

# Helper function to get alert location with hyperlink
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

# Helper function to get PR comments
function Get-PullRequestComments {
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

# Helper function to write alert annotations for commit type locations
# Writes an Action Warning/Error to the message log and creates an annotation associated with the file and line/col number (only for commit type locations)
function Write-AlertAnnotation {
    param(
        # Error docs: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message
        # Warning docs: https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-a-warning-message
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

Export-ModuleMember -Function Get-IdFromUrl, Get-AlertLocationType, Get-PullRequestHtmlUrl, Get-AlertLocationWithLink, Get-PullRequestComments, Write-AlertAnnotation
