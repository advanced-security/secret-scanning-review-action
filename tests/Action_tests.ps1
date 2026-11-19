# Tests for action.ps1 helper functions

Import-Module Pester

BeforeAll {
    Set-StrictMode -Version Latest

    # Import the ActionHelpers module from the repo root
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'ActionHelpers.psm1') -Force

    # Define mock functions for external dependencies
    function global:Invoke-GHRestMethod {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            $Method,
            $Uri,
            $ExtendedResult,
            $Body
        )
    }
    function global:Write-ActionError {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            $Message,
            $File,
            $Line,
            $Col
        )
    }
    function global:Write-ActionWarning {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            $Message,
            $File,
            $Line,
            $Col
        )
    }
    function global:Write-ActionDebug {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            $Message
        )
    }
}

Describe 'Get-IdFromUrl' {
    It 'Returns null for empty url' {
        Get-IdFromUrl -url '' | Should -BeNullOrEmpty
        Get-IdFromUrl -url $null | Should -BeNullOrEmpty
    }

    It 'Extracts ID from simple API URL' {
        Get-IdFromUrl -url 'https://api.github.com/repos/owner/repo/pulls/comments/12345' | Should -Be '12345'
    }

    It 'Extracts ID from pull request URL' {
        Get-IdFromUrl -url 'https://api.github.com/repos/owner/repo/pulls/42' | Should -Be '42'
    }

    It 'Extracts ID from issue comment URL' {
        Get-IdFromUrl -url 'https://api.github.com/repos/owner/repo/issues/comments/98765' | Should -Be '98765'
    }

    It 'Extracts ID from review URL' {
        Get-IdFromUrl -url 'https://api.github.com/repos/owner/repo/pulls/10/reviews/5555' | Should -Be '5555'
    }

    It 'Extracts ID from URL with trailing slash' {
        # Trailing slash should be ignored; ID remains valid
        Get-IdFromUrl -url 'https://api.github.com/repos/owner/repo/pulls/123/' | Should -Be '123'
    }
}

Describe 'Get-AlertLocationType' {
    It 'Throws when location has no type field' {
        $location = @{ details = @{ commit_sha = 'abc123' } }
        # In strict mode, accessing non-existent property throws PropertyNotFoundException
        { Get-AlertLocationType -location $location } | Should -Throw
    }

    It 'Returns commit SHA description for commit type' {
        $location = @{
            type = 'commit'
            details = @{ commit_sha = 'abc123def456' }
        }
        Get-AlertLocationType -location $location | Should -Be 'Commit SHA abc123def456'
    }

    It 'Returns pull request title for pull_request_title type' {
        $location = @{
            type = 'pull_request_title'
            details = @{ pull_request_title_url = 'https://api.github.com/repos/owner/repo/pulls/42' }
        }
        Get-AlertLocationType -location $location | Should -Be 'Pull request title'
    }

    It 'Returns pull request body for pull_request_body type' {
        $location = @{
            type = 'pull_request_body'
            details = @{ pull_request_body_url = 'https://api.github.com/repos/owner/repo/pulls/42' }
        }
        Get-AlertLocationType -location $location | Should -Be 'Pull request body'
    }

    It 'Returns pull request comment for pull_request_comment type' {
        $location = @{
            type = 'pull_request_comment'
            details = @{ pull_request_comment_url = 'https://api.github.com/repos/owner/repo/issues/comments/12345' }
        }
        Get-AlertLocationType -location $location | Should -Be 'Pull request comment'
    }

    It 'Returns pull request review for pull_request_review type' {
        $location = @{
            type = 'pull_request_review'
            details = @{ pull_request_review_url = 'https://api.github.com/repos/owner/repo/pulls/42/reviews/5555' }
        }
        Get-AlertLocationType -location $location | Should -Be 'Pull request review'
    }

    It 'Returns pull request review comment for pull_request_review_comment type' {
        $location = @{
            type = 'pull_request_review_comment'
            details = @{ pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/12345' }
        }
        Get-AlertLocationType -location $location | Should -Be 'Pull request review comment'
    }

    It 'Returns null for unknown location type' {
        $location = @{
            type = 'unknown_type'
            details = @{}
        }
        Get-AlertLocationType -location $location | Should -BeNullOrEmpty
    }
}

Describe 'Get-PullRequestHtmlUrl' {
    It 'Returns null for empty apiUrl' {
        Get-PullRequestHtmlUrl -apiUrl '' | Should -BeNullOrEmpty
        Get-PullRequestHtmlUrl -apiUrl $null | Should -BeNullOrEmpty
    }

    It 'Returns html_url from API response' {
        Mock Invoke-GHRestMethod { return @{ html_url = 'https://github.com/owner/repo/pull/42' } } -ModuleName ActionHelpers

        $result = Get-PullRequestHtmlUrl -apiUrl 'https://api.github.com/repos/owner/repo/pulls/42' -expectedApiBaseUrl 'https://api.github.com'
        $result | Should -Be 'https://github.com/owner/repo/pull/42'
    }

    It 'Returns null when API call fails (404)' {
        Mock Invoke-GHRestMethod { throw "Not Found" } -ModuleName ActionHelpers

        $result = Get-PullRequestHtmlUrl -apiUrl 'https://api.github.com/repos/owner/repo/pulls/999' -expectedApiBaseUrl 'https://api.github.com'
        $result | Should -BeNullOrEmpty
    }

    It 'Returns null for non-HTTPS URL' {
        $result = Get-PullRequestHtmlUrl -apiUrl 'http://evil.com/repos/owner/repo/pulls/42' -expectedApiBaseUrl 'https://api.github.com'
        $result | Should -BeNullOrEmpty
    }

    It 'Returns null when host does not match expected API host' {
        $result = Get-PullRequestHtmlUrl -apiUrl 'https://evil.com/repos/owner/repo/pulls/42' -expectedApiBaseUrl 'https://api.github.com'
        $result | Should -BeNullOrEmpty
    }
}

Describe 'Get-AlertLocationWithLink' {
    BeforeEach {
        # Default mock - return null to test fallback paths
        Mock Get-PullRequestHtmlUrl { return $null } -ModuleName ActionHelpers
        $script:originalServerUrl = $env:GITHUB_SERVER_URL
        $env:GITHUB_SERVER_URL = $null
    }

    AfterEach {
        $env:GITHUB_SERVER_URL = $script:originalServerUrl
    }

    It 'Throws when location has no type field' {
        $location = @{ details = @{} }
        { Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://github.com/owner/repo/pull/42' -pullRequestNumber 42 } | Should -Throw
    }

    It 'Returns commit link for commit type' {
        $location = @{
            type = 'commit'
            details = @{ commit_sha = 'abc123def456789' }
        }
        $result = Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://github.com/owner/repo/pull/42' -pullRequestNumber 42
        $result | Should -Be '[abc123d](https://github.com/owner/repo/pull/42/commits/abc123def456789)'
    }

    It 'Returns linked pull_request_title when API succeeds' {
        Mock Get-PullRequestHtmlUrl { return 'https://github.com/owner/repo/pull/42' } -ModuleName ActionHelpers

        $location = @{
            type = 'pull_request_title'
            details = @{ pull_request_title_url = 'https://api.github.com/repos/owner/repo/pulls/42' }
        }
        $result = Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://github.com/owner/repo/pull/42' -pullRequestNumber 42
        $result | Should -Be '[Pull request title](https://github.com/owner/repo/pull/42)'
    }

    It 'Returns plain text pull_request_title when API fails' {
        Mock Get-PullRequestHtmlUrl { return $null } -ModuleName ActionHelpers

        $location = @{
            type = 'pull_request_title'
            details = @{ pull_request_title_url = 'https://api.github.com/repos/owner/repo/pulls/42' }
        }
        $result = Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://github.com/owner/repo/pull/42' -pullRequestNumber 42
        $result | Should -Be 'Pull request title'
    }

    It 'Uses the location html_url for pull_request_review_comment without an API call' {
        $location = @{
            type = 'pull_request_review_comment'
            details = @{
                pull_request_review_comment_url = 'https://api.tenant.ghe.com/repos/owner/repo/pulls/comments/12345'
                html_url                        = 'https://tenant.ghe.com/owner/repo/pull/42#discussion_r12345'
            }
        }
        $result = Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://tenant.ghe.com/owner/repo/pull/42' -pullRequestNumber 42
        $result | Should -Be '[Pull request review comment](https://tenant.ghe.com/owner/repo/pull/42#discussion_r12345)'
        Should -Invoke Get-PullRequestHtmlUrl -Times 0 -Exactly -ModuleName ActionHelpers
    }

    It 'Builds the pull_request_review_comment link on GITHUB_SERVER_URL when html_url is missing (<case>)' -TestCases @(
        @{ case = 'GHE.com'; serverUrl = 'https://tenant.ghe.com'; apiUrl = 'https://api.tenant.ghe.com/repos/owner/repo/pulls/comments/12345'; expected = 'https://tenant.ghe.com/owner/repo/pull/42#discussion_r12345' }
        @{ case = 'GHES'; serverUrl = 'https://ghes.example.com/'; apiUrl = 'https://ghes.example.com/api/v3/repos/owner/repo/pulls/comments/12345'; expected = 'https://ghes.example.com/owner/repo/pull/42#discussion_r12345' }
    ) {
        param($serverUrl, $apiUrl, $expected)
        $env:GITHUB_SERVER_URL = $serverUrl
        $location = @{
            type = 'pull_request_review_comment'
            details = @{ pull_request_review_comment_url = $apiUrl }
        }
        $result = Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://example.com/owner/repo/pull/42' -pullRequestNumber 42
        $result | Should -Be "[Pull request review comment]($expected)"
    }

    It 'Builds the pull_request_review_comment link on https://github.com when html_url and GITHUB_SERVER_URL are missing' {
        $location = @{
            type = 'pull_request_review_comment'
            details = @{ pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/12345' }
        }
        $result = Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://github.com/owner/repo/pull/42' -pullRequestNumber 42
        $result | Should -Be '[Pull request review comment](https://github.com/owner/repo/pull/42#discussion_r12345)'
        Should -Invoke Get-PullRequestHtmlUrl -Times 0 -Exactly -ModuleName ActionHelpers
    }
}

Describe 'Get-PullRequestComment' {
    It 'Returns no comments for a pull request without comments' {
        # Invoke-GHRestMethod returns $null for an empty page
        Mock Invoke-GHRestMethod { return $null } -ModuleName ActionHelpers

        @(Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42).Count | Should -Be 0
    }
    It 'Propagates API errors to the caller' {
        Mock Invoke-GHRestMethod { throw "API Error" } -ModuleName ActionHelpers

        { Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42 } | Should -Throw '*API Error*'
    }

    It 'Attaches comments read before an error to the exception' {
        Mock Invoke-GHRestMethod {
            if ($Uri -like '*page=1') { return @(1..100 | ForEach-Object { @{ id = $_ } }) }
            throw "API Error"
        } -ModuleName ActionHelpers

        $caught = $null
        try { Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42 } catch { $caught = $_ }

        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -BeLike '*API Error*'
        @($caught.Exception.Data['PartialResult']).Count | Should -Be 100
    }

    It 'Follows pagination when a page is full' {
        Mock Invoke-GHRestMethod {
            if ($Uri -like '*page=1') { return @(1..100 | ForEach-Object { @{ id = $_ } }) }
            return @( @{ id = 101 } )
        } -ModuleName ActionHelpers

        $result = Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42
        $result.Count | Should -Be 101
        Should -Invoke Invoke-GHRestMethod -Times 2 -ModuleName ActionHelpers
    }

    It 'Returns comments from single page' {
        $mockComments = @(
            @{ id = 1; body = 'Comment 1' },
            @{ id = 2; body = 'Comment 2' }
        )
        Mock Invoke-GHRestMethod { return $mockComments } -ModuleName ActionHelpers

        $result = Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42
        $result.Count | Should -Be 2
    }

    It 'Defaults to api.github.com when no apiBaseUrl is provided' {
        $mockComments = @( @{ id = 1; body = 'Comment 1' } )
        Mock Invoke-GHRestMethod { return $mockComments } -ModuleName ActionHelpers

        Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42

        Should -Invoke Invoke-GHRestMethod -Times 1 -ModuleName ActionHelpers -ParameterFilter {
            $Uri -like 'https://api.github.com/repos/owner/repo/issues/42/comments*' -and $Method -eq 'GET'
        }
    }

    It 'Uses the provided apiBaseUrl (ghe.com support)' {
        $mockComments = @( @{ id = 1; body = 'Comment 1' } )
        Mock Invoke-GHRestMethod { return $mockComments } -ModuleName ActionHelpers

        Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42 -apiBaseUrl 'https://api.tenant.ghe.com'

        Should -Invoke Invoke-GHRestMethod -Times 1 -ModuleName ActionHelpers -ParameterFilter {
            $Uri -like 'https://api.tenant.ghe.com/repos/owner/repo/issues/42/comments*' -and $Method -eq 'GET'
        }
    }
}

Describe 'Publish-PullRequestComment' {
    BeforeAll {
        $script:commentArgs = @{ owner = 'owner'; repo = 'repo'; pullNumber = 42 }
    }

    It 'Updates the summary comment from an earlier run (createIfMissing: <createIfMissing>)' -TestCases @(
        @{ createIfMissing = $true }
        @{ createIfMissing = $false }
    ) {
        param($createIfMissing)
        Mock Get-PullRequestComment {
            @(
                @{ body = 'Looks good'; url = 'https://api.github.com/repos/owner/repo/issues/comments/1' }
                @{ body = "<!-- secret-scanning-review-pr-comment-watermark -->`nFound [1] secret scanning alert"; url = 'https://api.github.com/repos/owner/repo/issues/comments/2' }
            )
        } -ModuleName ActionHelpers
        Mock Invoke-GHRestMethod { @{ html_url = 'https://github.com/owner/repo/pull/42#issuecomment-2' } } -ModuleName ActionHelpers

        $result = Publish-PullRequestComment @script:commentArgs -markdownSummary 'Found [0] secret scanning alerts' -createIfMissing $createIfMissing
        $result.html_url | Should -Be 'https://github.com/owner/repo/pull/42#issuecomment-2'
        Should -Invoke Invoke-GHRestMethod -Times 1 -Exactly -ModuleName ActionHelpers
        Should -Invoke Invoke-GHRestMethod -Times 1 -Exactly -ModuleName ActionHelpers -ParameterFilter {
            $Method -eq 'PATCH' -and $Uri -eq 'https://api.github.com/repos/owner/repo/issues/comments/2' -and
            ($Body | ConvertFrom-Json).body.StartsWith("<!-- secret-scanning-review-pr-comment-watermark -->`nFound [0] secret scanning alerts`n<!-- ")
        }
    }

    It 'Creates a comment when there is none and createIfMissing is true' {
        Mock Get-PullRequestComment { @(@{ body = 'Looks good'; url = 'https://api.tenant.ghe.com/repos/owner/repo/issues/comments/1' }) } -ModuleName ActionHelpers
        Mock Invoke-GHRestMethod { @{ html_url = 'https://tenant.ghe.com/owner/repo/pull/42#issuecomment-3' } } -ModuleName ActionHelpers

        Publish-PullRequestComment @script:commentArgs -markdownSummary 'Found [1] secret scanning alert' -apiBaseUrl 'https://api.tenant.ghe.com' | Should -Not -BeNullOrEmpty
        Should -Invoke Invoke-GHRestMethod -Times 1 -Exactly -ModuleName ActionHelpers -ParameterFilter {
            $Method -eq 'POST' -and $Uri -eq 'https://api.tenant.ghe.com/repos/owner/repo/issues/42/comments'
        }
    }

    It 'Does not create a comment when there is none and createIfMissing is false' {
        Mock Get-PullRequestComment { @(@{ body = 'Looks good'; url = 'https://api.github.com/repos/owner/repo/issues/comments/1' }) } -ModuleName ActionHelpers
        Mock Invoke-GHRestMethod { } -ModuleName ActionHelpers

        Publish-PullRequestComment @script:commentArgs -markdownSummary 'Found [0] secret scanning alerts' -createIfMissing $false | Should -BeNullOrEmpty
        Should -Invoke Invoke-GHRestMethod -Times 0 -Exactly -ModuleName ActionHelpers
    }

    It 'Throws an error naming the failed request when the comments cannot be read' {
        Mock Get-PullRequestComment { throw 'Server Error' } -ModuleName ActionHelpers
        { Publish-PullRequestComment @script:commentArgs -markdownSummary 'summary' } | Should -Throw "Error reading comments from 'owner/repo' Pull Request#42*Server Error*"
    }

    It 'Throws an error naming the failed request when the comment cannot be written' {
        Mock Get-PullRequestComment { } -ModuleName ActionHelpers
        Mock Invoke-GHRestMethod { throw 'Forbidden' } -ModuleName ActionHelpers
        { Publish-PullRequestComment @script:commentArgs -markdownSummary 'summary' } | Should -Throw "Error adding comment to 'owner/repo' Pull Request#42*Forbidden*"
    }
}

Describe 'Get-ErrorStatusCode' {
    It 'Returns the HTTP status code from the error response' {
        $errorRecord = [pscustomobject]@{ Exception = [pscustomobject]@{ Response = [pscustomobject]@{ StatusCode = [System.Net.HttpStatusCode]::NotFound } } }
        Get-ErrorStatusCode -ErrorRecord $errorRecord | Should -Be 404
    }

    It 'Returns null when the error has no response' {
        try { throw 'network failure' } catch { $result = Get-ErrorStatusCode -ErrorRecord $_ }
        $result | Should -BeNullOrEmpty
    }
}

Describe 'Get-PullRequestReviewComment' {
    It 'Refuses non-HTTPS URLs' {
        Mock Invoke-GHRestMethod { } -ModuleName ActionHelpers
        { Get-PullRequestReviewComment -url 'http://api.github.com/repos/o/r/pulls/comments/1' -expectedApiBaseUrl 'https://api.github.com' } | Should -Throw '*non-HTTPS*'
        Should -Invoke Invoke-GHRestMethod -Times 0 -ModuleName ActionHelpers
    }

    It 'Refuses URLs for a different host' {
        Mock Invoke-GHRestMethod { } -ModuleName ActionHelpers
        { Get-PullRequestReviewComment -url 'https://evil.example.com/repos/o/r/pulls/comments/1' -expectedApiBaseUrl 'https://api.github.com' } | Should -Throw '*does not match*'
        Should -Invoke Invoke-GHRestMethod -Times 0 -ModuleName ActionHelpers
    }

    It 'Returns the review comment for the expected host' {
        Mock Invoke-GHRestMethod { return @{ pull_request_url = 'https://api.github.com/repos/o/r/pulls/1' } } -ModuleName ActionHelpers
        $result = Get-PullRequestReviewComment -url 'https://api.github.com/repos/o/r/pulls/comments/1' -expectedApiBaseUrl 'https://api.github.com'
        $result.pull_request_url | Should -Be 'https://api.github.com/repos/o/r/pulls/1'
    }

    It 'Propagates API errors to the caller' {
        Mock Invoke-GHRestMethod { throw 'Not Found' } -ModuleName ActionHelpers
        { Get-PullRequestReviewComment -url 'https://api.github.com/repos/o/r/pulls/comments/1' -expectedApiBaseUrl 'https://api.github.com' } | Should -Throw '*Not Found*'
    }
}

Describe 'Get-PullRequestNumberFromReviewCommentHtmlUrl' {
    It 'Returns the pull request number from <htmlUrl>' -TestCases @(
        @{ htmlUrl = 'https://github.com/owner/repo/pull/4#discussion_r4606065507'; expected = 4 }
        @{ htmlUrl = 'https://github.com/Owner/REPO/pull/12#discussion_r1'; expected = 12 }
        @{ htmlUrl = 'https://tenant.ghe.com/owner/repo/pull/7#discussion_r2'; expected = 7 }
    ) {
        param($htmlUrl, $expected)
        Get-PullRequestNumberFromReviewCommentHtmlUrl -htmlUrl $htmlUrl -owner 'owner' -repo 'repo' | Should -Be $expected
    }

    It 'Returns null when html_url is <case>' -TestCases @(
        @{ case = 'missing'; htmlUrl = $null }
        @{ case = 'empty'; htmlUrl = '' }
        @{ case = 'for another owner'; htmlUrl = 'https://github.com/other/repo/pull/4#discussion_r1' }
        @{ case = 'for another repository'; htmlUrl = 'https://github.com/owner/other/pull/4#discussion_r1' }
        @{ case = 'without a fragment'; htmlUrl = 'https://github.com/owner/repo/pull/4' }
        @{ case = 'an issue comment fragment'; htmlUrl = 'https://github.com/owner/repo/pull/4#issuecomment-1' }
        @{ case = 'a pulls path'; htmlUrl = 'https://github.com/owner/repo/pulls/4#discussion_r1' }
        @{ case = 'a path with extra segments'; htmlUrl = 'https://github.com/owner/repo/pull/4/files#discussion_r1' }
        @{ case = 'a non-numeric pull request number'; htmlUrl = 'https://github.com/owner/repo/pull/abc#discussion_r1' }
        @{ case = 'followed by a newline'; htmlUrl = "https://github.com/owner/repo/pull/4#discussion_r1`n" }
        @{ case = 'relative'; htmlUrl = '/owner/repo/pull/4#discussion_r1' }
    ) {
        param($htmlUrl)
        Get-PullRequestNumberFromReviewCommentHtmlUrl -htmlUrl $htmlUrl -owner 'owner' -repo 'repo' | Should -BeNullOrEmpty
    }
}

Describe 'Test-ReviewCommentInPullRequest' {
    BeforeAll {
        # Pull request #1 in owner/repo
        $script:pullRequestArgs = @{
            owner              = 'owner'
            repo               = 'repo'
            pullNumber         = 1
            pullRequestApiUrl  = 'https://api.github.com/repos/owner/repo/pulls/1'
            expectedApiBaseUrl = 'https://api.github.com'
        }
    }

    It 'Matches an html_url for this pull request without an API call' {
        # A pending or deleted review comment returns 404 from the API
        Mock Invoke-GHRestMethod { throw 'Not Found' } -ModuleName ActionHelpers
        $location = @{ type = 'pull_request_review_comment'; details = @{
                pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/99'
                html_url                        = 'https://github.com/owner/repo/pull/1#discussion_r99'
            }
        }

        Test-ReviewCommentInPullRequest -location $location @script:pullRequestArgs | Should -BeTrue
        Should -Invoke Invoke-GHRestMethod -Times 0 -Exactly -ModuleName ActionHelpers
    }

    It 'Does not match an html_url for another pull request and makes no API call' {
        Mock Invoke-GHRestMethod { throw 'Not Found' } -ModuleName ActionHelpers
        $location = @{ type = 'pull_request_review_comment'; details = @{
                pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/99'
                html_url                        = 'https://github.com/owner/repo/pull/4#discussion_r99'
            }
        }

        Test-ReviewCommentInPullRequest -location $location @script:pullRequestArgs | Should -BeFalse
        Should -Invoke Invoke-GHRestMethod -Times 0 -Exactly -ModuleName ActionHelpers
    }

    It 'Falls back to the review comment API when html_url is <case>' -TestCases @(
        @{ case = 'missing'; details = @{ pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/99' } }
        @{ case = 'malformed'; details = @{ pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/99'; html_url = 'https://github.com/owner/repo/pull/1' } }
    ) {
        param($details)
        Mock Invoke-GHRestMethod { return @{ pull_request_url = 'https://api.github.com/repos/owner/repo/pulls/1' } } -ModuleName ActionHelpers
        $location = @{ type = 'pull_request_review_comment'; details = $details }

        Test-ReviewCommentInPullRequest -location $location @script:pullRequestArgs | Should -BeTrue
        Should -Invoke Invoke-GHRestMethod -Times 1 -Exactly -ModuleName ActionHelpers -ParameterFilter {
            $Uri -eq 'https://api.github.com/repos/owner/repo/pulls/comments/99'
        }
    }

    It 'Propagates a fallback lookup error (such as 404) so the caller applies fail-closed' {
        Mock Invoke-GHRestMethod { throw 'Not Found' } -ModuleName ActionHelpers
        $location = @{ type = 'pull_request_review_comment'; details = @{
                pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/99'
            }
        }

        { Test-ReviewCommentInPullRequest -location $location @script:pullRequestArgs } | Should -Throw '*Not Found*'
    }
}

Describe 'Get-PullRequestNumberFromPullRequestCommentHtmlUrl' {
    It 'Returns the pull request number from <htmlUrl>' -TestCases @(
        @{ htmlUrl = 'https://github.com/owner/repo/pull/4#issuecomment-1081119451'; expected = 4 }
        @{ htmlUrl = 'https://github.com/Owner/REPO/pull/12#issuecomment-1'; expected = 12 }
        @{ htmlUrl = 'https://tenant.ghe.com/owner/repo/pull/7#issuecomment-2'; expected = 7 }
    ) {
        param($htmlUrl, $expected)
        Get-PullRequestNumberFromPullRequestCommentHtmlUrl -htmlUrl $htmlUrl -owner 'owner' -repo 'repo' | Should -Be $expected
    }

    It 'Returns null when html_url is <case>' -TestCases @(
        @{ case = 'missing'; htmlUrl = $null }
        @{ case = 'empty'; htmlUrl = '' }
        @{ case = 'for another owner'; htmlUrl = 'https://github.com/other/repo/pull/4#issuecomment-1' }
        @{ case = 'for another repository'; htmlUrl = 'https://github.com/owner/other/pull/4#issuecomment-1' }
        @{ case = 'without a fragment'; htmlUrl = 'https://github.com/owner/repo/pull/4' }
        @{ case = 'a review comment fragment'; htmlUrl = 'https://github.com/owner/repo/pull/4#discussion_r1' }
        @{ case = 'an issue path'; htmlUrl = 'https://github.com/owner/repo/issues/4#issuecomment-1' }
        @{ case = 'a pulls path'; htmlUrl = 'https://github.com/owner/repo/pulls/4#issuecomment-1' }
        @{ case = 'a path with extra segments'; htmlUrl = 'https://github.com/owner/repo/pull/4/files#issuecomment-1' }
        @{ case = 'a non-numeric pull request number'; htmlUrl = 'https://github.com/owner/repo/pull/abc#issuecomment-1' }
        @{ case = 'followed by a newline'; htmlUrl = "https://github.com/owner/repo/pull/4#issuecomment-1`n" }
        @{ case = 'relative'; htmlUrl = '/owner/repo/pull/4#issuecomment-1' }
    ) {
        param($htmlUrl)
        Get-PullRequestNumberFromPullRequestCommentHtmlUrl -htmlUrl $htmlUrl -owner 'owner' -repo 'repo' | Should -BeNullOrEmpty
    }
}

Describe 'Test-PullRequestCommentInPullRequest' {
    BeforeAll {
        # Pull request #1 in owner/repo
        $script:pullRequestArgs = @{
            owner      = 'owner'
            repo       = 'repo'
            pullNumber = 1
        }
    }

    It 'Matches an html_url for this pull request without listing comments' {
        # A comment deleted after detection is no longer listed on the pull request
        $listCount = [System.Collections.Generic.List[int]]::new()
        $location = @{ type = 'pull_request_comment'; details = @{
                pull_request_comment_url = 'https://api.github.com/repos/owner/repo/issues/comments/99'
                html_url                 = 'https://github.com/owner/repo/pull/1#issuecomment-99'
            }
        }

        Test-PullRequestCommentInPullRequest -location $location @script:pullRequestArgs -listPullRequestComments { $listCount.Add(1); @() } | Should -BeTrue
        $listCount.Count | Should -Be 0
    }

    It 'Does not match an html_url for another pull request and does not list comments' {
        $listCount = [System.Collections.Generic.List[int]]::new()
        $location = @{ type = 'pull_request_comment'; details = @{
                pull_request_comment_url = 'https://api.github.com/repos/owner/repo/issues/comments/99'
                html_url                 = 'https://github.com/owner/repo/pull/4#issuecomment-99'
            }
        }

        Test-PullRequestCommentInPullRequest -location $location @script:pullRequestArgs -listPullRequestComments { $listCount.Add(1); @() } | Should -BeFalse
        $listCount.Count | Should -Be 0
    }

    It 'Falls back to the listed comments when html_url is <case>' -TestCases @(
        @{ case = 'missing'; details = @{ pull_request_comment_url = 'https://api.github.com/repos/owner/repo/issues/comments/99' } }
        @{ case = 'malformed'; details = @{ pull_request_comment_url = 'https://api.github.com/repos/owner/repo/issues/comments/99'; html_url = 'https://github.com/owner/repo/pull/1' } }
    ) {
        param($details)
        $location = @{ type = 'pull_request_comment'; details = $details }

        Test-PullRequestCommentInPullRequest -location $location @script:pullRequestArgs -listPullRequestComments { @(@{ id = 98 }, @{ id = 99 }) } | Should -BeTrue
        Test-PullRequestCommentInPullRequest -location $location @script:pullRequestArgs -listPullRequestComments { @(@{ id = 98 }) } | Should -BeFalse
    }
}

Describe 'Get-PagedResult' {
    It 'Returns no items for an empty list' {
        # Invoke-GHRestMethod returns a $null result for an empty page
        Mock Invoke-GHRestMethod { return @{ result = $null; nextLink = $null } } -ModuleName ActionHelpers

        @(Get-PagedResult -url 'https://api.github.com/repos/o/r/secret-scanning/alerts?per_page=100').Count | Should -Be 0
    }

    It 'Follows nextLink, including a page with a single item' {
        # Invoke-GHRestMethod returns a single object (not an array) for a page with one item
        Mock Invoke-GHRestMethod {
            if ($Uri -like '*page=2') { return @{ result = [pscustomobject]@{ number = 3 }; nextLink = $null } }
            return @{ result = @([pscustomobject]@{ number = 1 }, [pscustomobject]@{ number = 2 }); nextLink = 'https://api.github.com/repos/o/r/secret-scanning/alerts?per_page=100&page=2' }
        } -ModuleName ActionHelpers

        $result = @(Get-PagedResult -url 'https://api.github.com/repos/o/r/secret-scanning/alerts?per_page=100')
        $result.number | Should -Be @(1, 2, 3)
        Should -Invoke Invoke-GHRestMethod -Times 2 -Exactly -ModuleName ActionHelpers
    }

    It 'Attaches items read before an error to the exception' {
        Mock Invoke-GHRestMethod {
            if ($Uri -like '*page=2') { throw 'Bad Gateway' }
            return @{ result = [pscustomobject]@{ number = 1 }; nextLink = 'https://api.github.com/repos/o/r/secret-scanning/alerts?per_page=100&page=2' }
        } -ModuleName ActionHelpers

        $caught = $null
        try { Get-PagedResult -url 'https://api.github.com/repos/o/r/secret-scanning/alerts?per_page=100' } catch { $caught = $_ }

        $caught.Exception.Message | Should -BeLike '*Bad Gateway*'
        @($caught.Exception.Data['PartialResult']).number | Should -Be @(1)
    }
}

Describe 'Get-AlertLocationsUrl' {
    It 'Returns the alert locations_url' {
        $alert = @{ number = 42; locations_url = 'https://api.tenant.ghe.com/repos/owner/repo/secret-scanning/alerts/42/locations' }
        Get-AlertLocationsUrl -alert $alert -owner 'owner' -repo 'repo' -apiBaseUrl 'https://api.tenant.ghe.com' | Should -Be 'https://api.tenant.ghe.com/repos/owner/repo/secret-scanning/alerts/42/locations'
    }

    It 'Builds the URL from the alert number when locations_url is <case>' -TestCases @(
        @{ case = 'missing'; alert = @{ number = 42 } }
        @{ case = 'blank'; alert = @{ number = 42; locations_url = ' ' } }
    ) {
        param($alert)
        Get-AlertLocationsUrl -alert $alert -owner 'owner' -repo 'repo' -apiBaseUrl 'https://ghes.example.com/api/v3/' | Should -Be 'https://ghes.example.com/api/v3/repos/owner/repo/secret-scanning/alerts/42/locations'
    }

    It 'Returns null when the alert has neither a number nor a locations_url' {
        Get-AlertLocationsUrl -alert @{ secret_type = 'password' } -owner 'owner' -repo 'repo' | Should -BeNullOrEmpty
    }
}

Describe 'Get-PullRequestCommitSha' {
    It 'Follows nextLink pagination on the pull request commits endpoint' {
        Mock Invoke-GHRestMethod {
            if ($Uri -like '*page=2') { return @{ result = @(@{ sha = 'b' }); nextLink = $null } }
            return @{ result = @(@{ sha = 'a' }); nextLink = 'https://api.github.com/repos/o/r/pulls/1/commits?per_page=100&page=2' }
        } -ModuleName ActionHelpers
        $pr = @{ commits = 2; base = @{ ref = 'main' }; head = @{ sha = 'head' } }

        $result = @(Get-PullRequestCommitSha -pullRequest $pr -owner 'o' -repo 'r' -pullNumber 1)
        $result | Should -Be @('a', 'b')
        Should -Invoke Invoke-GHRestMethod -Times 0 -ModuleName ActionHelpers -ParameterFilter { $Uri -like '*/compare/*' }
    }

    It 'Falls back to the compare endpoint when the commit list is truncated' {
        Mock Invoke-GHRestMethod {
            if ($Uri -like '*/compare/*') { return @{ result = @{ commits = @(1..300 | ForEach-Object { @{ sha = "s$_" } }) }; nextLink = $null } }
            return @{ result = @(1..250 | ForEach-Object { @{ sha = "s$_" } }); nextLink = $null }
        } -ModuleName ActionHelpers
        $pr = @{ commits = 300; base = @{ ref = 'releases/v1' }; head = @{ sha = 'head' } }

        $result = @(Get-PullRequestCommitSha -pullRequest $pr -owner 'o' -repo 'r' -pullNumber 1)
        $result.Count | Should -Be 300
        Should -Invoke Invoke-GHRestMethod -Times 1 -ModuleName ActionHelpers -ParameterFilter { $Uri -like 'https://api.github.com/repos/o/r/compare/releases%2Fv1...head*' }
    }

    It 'Returns only commit SHAs when debug output is written (compare returns fewer than expected)' {
        # GitHubActions' Write-ActionDebug returns the workflow command string on the success stream
        Mock Write-ActionDebug { "::debug::$Message" } -ModuleName ActionHelpers
        Mock Invoke-GHRestMethod {
            if ($Uri -like '*/compare/*') { return @{ result = @{ commits = @(1..299 | ForEach-Object { @{ sha = "s$_" } }) }; nextLink = $null } }
            return @{ result = @(1..250 | ForEach-Object { @{ sha = "s$_" } }); nextLink = $null }
        } -ModuleName ActionHelpers
        $pr = @{ commits = 300; base = @{ ref = 'main' }; head = @{ sha = 'head' } }

        $result = @(Get-PullRequestCommitSha -pullRequest $pr -owner 'o' -repo 'r' -pullNumber 1)
        $result.Count | Should -Be 299
        $result | Where-Object { $_ -like '::debug::*' } | Should -BeNullOrEmpty
    }

    It 'Propagates API errors to the caller' {
        Mock Invoke-GHRestMethod { throw 'Server Error' } -ModuleName ActionHelpers
        $pr = @{ commits = 1; base = @{ ref = 'main' }; head = @{ sha = 'head' } }
        { Get-PullRequestCommitSha -pullRequest $pr -owner 'o' -repo 'r' -pullNumber 1 } | Should -Throw '*Server Error*'
    }
}

Describe 'Get-EvaluationWarningMarkdown' {
    It 'Returns an empty string when there are no warnings' {
        Get-EvaluationWarningMarkdown -Warnings @() | Should -Be ''
    }

    It 'Lists each warning on a single line' {
        $result = Get-EvaluationWarningMarkdown -Warnings @("first`r`nerror", 'second')
        $result | Should -BeLike '*> `[!WARNING`]*'
        $result | Should -BeLike "*> - first error`n*"
        $result | Should -BeLike "*> - second`n*"
    }
}

Describe 'ConvertTo-AlertStepOutputJson' {
    BeforeAll {
        function Get-FakeAlert {
            param(
                [int]$number,
                $bypassedBy = $null
            )
            [PSCustomObject]@{
                number                      = $number
                secret_type                 = 'github_personal_access_token'
                push_protection_bypassed    = $null -ne $bypassedBy
                push_protection_bypassed_by = $bypassedBy
                state                       = 'open'
                resolution                  = $null
                validity                    = 'active'
                validity_checked_at         = $null
                html_url                    = "https://github.com/owner/repo/security/secret-scanning/$number"
                dismissal_request_status    = $null
            }
        }
    }

    It 'Returns a JSON array with one item per alert (<alertCount> alerts)' -ForEach @(
        @{ alertCount = 0 }
        @{ alertCount = 1 }
        @{ alertCount = 2 }
    ) {
        $alerts = @(1, 2 | Select-Object -First $alertCount | ForEach-Object { Get-FakeAlert -number $_ })

        $json = ConvertTo-AlertStepOutputJson -alerts $alerts

        $json | Should -Match '^\[.*\]$'
        (ConvertFrom-Json -InputObject $json -NoEnumerate).Count | Should -Be $alertCount
    }

    It 'Keeps the nested push_protection_bypassed_by user object' {
        $user = '{"login":"octocat","id":1,"type":"User","site_admin":false}' | ConvertFrom-Json

        $json = ConvertTo-AlertStepOutputJson -alerts @(Get-FakeAlert -number 7 -bypassedBy $user)

        $alert = (ConvertFrom-Json -InputObject $json -NoEnumerate)[0]
        $alert.number | Should -Be 7
        $alert.push_protection_bypassed | Should -BeTrue
        $alert.push_protection_bypassed_by.login | Should -Be 'octocat'
        $alert.push_protection_bypassed_by.id | Should -Be 1
    }
}

Describe 'Write-AlertAnnotation' {
    It 'Does nothing for non-commit alert types' {
        Mock Write-ActionError { } -ModuleName ActionHelpers
        Mock Write-ActionWarning { } -ModuleName ActionHelpers

        $location = @{ type = 'pull_request_title'; details = @{} }
        Write-AlertAnnotation -Level 'Error' -Message 'Test' -Location $location -AlertType 'pull_request_title'

        Should -Invoke Write-ActionError -Times 0 -ModuleName ActionHelpers
        Should -Invoke Write-ActionWarning -Times 0 -ModuleName ActionHelpers
    }

    It 'Writes error annotation for commit type with Error level' {
        Mock Write-ActionError { } -ModuleName ActionHelpers

        $location = @{
            type = 'commit'
            details = @{ path = 'src/file.ps1'; start_line = 10; start_column = 5 }
        }
        Write-AlertAnnotation -Level 'Error' -Message 'Secret found' -Location $location -AlertType 'commit'

        Should -Invoke Write-ActionError -Times 1 -ModuleName ActionHelpers -ParameterFilter {
            $Message -eq 'Secret found' -and $File -eq 'src/file.ps1' -and $Line -eq 10 -and $Col -eq 5
        }
    }

    It 'Writes warning annotation for commit type with Warning level' {
        Mock Write-ActionWarning { } -ModuleName ActionHelpers

        $location = @{
            type = 'commit'
            details = @{ path = 'src/file.ps1'; start_line = 20; start_column = 1 }
        }
        Write-AlertAnnotation -Level 'Warning' -Message 'Secret found' -Location $location -AlertType 'commit'

        Should -Invoke Write-ActionWarning -Times 1 -ModuleName ActionHelpers -ParameterFilter {
            $Message -eq 'Secret found' -and $File -eq 'src/file.ps1' -and $Line -eq 20 -and $Col -eq 1
        }
    }
}

Describe 'Get-DismissalRequestForAlert' {
    It 'Returns null when API call fails (no dismissal request)' {
        Mock Invoke-GHRestMethod { throw "Not Found" } -ModuleName ActionHelpers

        $result = Get-DismissalRequestForAlert -owner 'owner' -repo 'repo' -alertNumber 42
        $result | Should -BeNullOrEmpty
    }

    It 'Returns dismissal request object when API succeeds' {
        $mockResponse = @{
            id = 21
            status = 'denied'
            requester_comment = 'Test token used in readme'
        }
        Mock Invoke-GHRestMethod { return $mockResponse } -ModuleName ActionHelpers

        $result = Get-DismissalRequestForAlert -owner 'owner' -repo 'repo' -alertNumber 42
        $result | Should -Not -BeNullOrEmpty
        $result.status | Should -Be 'denied'
        $result.id | Should -Be 21
    }

    It 'Returns dismissal request with pending status' {
        $mockResponse = @{
            id = 30
            status = 'pending'
        }
        Mock Invoke-GHRestMethod { return $mockResponse } -ModuleName ActionHelpers

        $result = Get-DismissalRequestForAlert -owner 'owner' -repo 'repo' -alertNumber 17
        $result.status | Should -Be 'pending'
    }

    It 'Calls correct API URL' {
        Mock Invoke-GHRestMethod { return @{ status = 'approved' } } -ModuleName ActionHelpers

        Get-DismissalRequestForAlert -owner 'myorg' -repo 'myrepo' -alertNumber 99

        Should -Invoke Invoke-GHRestMethod -Times 1 -ModuleName ActionHelpers -ParameterFilter {
            $Uri -eq 'https://api.github.com/repos/myorg/myrepo/dismissal-requests/secret-scanning/99' -and $Method -eq 'GET'
        }
    }

    It 'Uses the provided apiBaseUrl (ghe.com support)' {
        Mock Invoke-GHRestMethod { return @{ status = 'approved' } } -ModuleName ActionHelpers

        Get-DismissalRequestForAlert -owner 'myorg' -repo 'myrepo' -alertNumber 99 -apiBaseUrl 'https://api.tenant.ghe.com'

        Should -Invoke Invoke-GHRestMethod -Times 1 -ModuleName ActionHelpers -ParameterFilter {
            $Uri -eq 'https://api.tenant.ghe.com/repos/myorg/myrepo/dismissal-requests/secret-scanning/99' -and $Method -eq 'GET'
        }
    }

    It 'Returns null when API returns error response body instead of throwing' {
        # Invoke-GHRestMethod does not throw on HTTP errors; it returns the error body as a PSObject
        $errorResponse = @{ message = 'Resource not accessible by personal access token'; documentation_url = 'https://docs.github.com'; status = '403' }
        Mock Invoke-GHRestMethod { return $errorResponse } -ModuleName ActionHelpers

        $result = Get-DismissalRequestForAlert -owner 'owner' -repo 'repo' -alertNumber 42
        $result | Should -BeNullOrEmpty
    }
}

Describe 'Get-AlertDismissalState' {
    It 'Returns plain state when no dismissal request and no closure fields' {
        $alert = [PSCustomObject]@{
            number = 1
            state = 'open'
            closure_request_comment = $null
            closure_request_reviewer_comment = $null
            closure_request_reviewer = $null
        }

        $result = Get-AlertDismissalState -alert $alert -dismissalRequest $null
        $result.stateValue | Should -Be 'open'
        $result.dismissalStatus | Should -BeNullOrEmpty
        $result.warning | Should -BeNullOrEmpty
    }

    It 'Returns hover tooltip when dismissal request has status' {
        $alert = [PSCustomObject]@{
            number = 2
            state = 'open'
            closure_request_comment = 'Test key'
            closure_request_reviewer_comment = $null
            closure_request_reviewer = $null
        }
        $dismissalRequest = @{ status = 'pending' }

        $result = Get-AlertDismissalState -alert $alert -dismissalRequest $dismissalRequest
        $result.stateValue | Should -Match 'open \(\[dismissal\].*Dismissal request: pending'
        $result.dismissalStatus | Should -Be 'pending'
        $result.warning | Should -BeNullOrEmpty
    }

    It 'Returns plain dismissal text and warning when closure fields present but API returned null' {
        $alert = [PSCustomObject]@{
            number = 42
            state = 'open'
            closure_request_comment = 'This is a test key'
            closure_request_reviewer_comment = $null
            closure_request_reviewer = $null
        }

        $result = Get-AlertDismissalState -alert $alert -dismissalRequest $null
        $result.stateValue | Should -Be 'open (dismissal)'
        $result.dismissalStatus | Should -BeNullOrEmpty
        $result.warning | Should -BeLike '*Alert #42*contents: read*'
    }

    It 'Returns plain dismissal text when closure_request_reviewer is present but API returned null' {
        $alert = [PSCustomObject]@{
            number = 7
            state = 'resolved'
            closure_request_comment = $null
            closure_request_reviewer_comment = $null
            closure_request_reviewer = @{ login = 'reviewer1' }
        }

        $result = Get-AlertDismissalState -alert $alert -dismissalRequest $null
        $result.stateValue | Should -Be 'resolved (dismissal)'
        $result.warning | Should -BeLike '*Alert #7*'
    }

    It 'Returns plain dismissal text when closure_request_reviewer_comment is present but API returned null' {
        $alert = [PSCustomObject]@{
            number = 8
            state = 'open'
            closure_request_comment = $null
            closure_request_reviewer_comment = 'Denied - rotate the secret'
            closure_request_reviewer = $null
        }

        $result = Get-AlertDismissalState -alert $alert -dismissalRequest $null
        $result.stateValue | Should -Be 'open (dismissal)'
        $result.warning | Should -BeLike '*Alert #8*'
    }

    It 'Returns approved status with hover tooltip' {
        $alert = [PSCustomObject]@{
            number = 3
            state = 'resolved'
            closure_request_comment = 'False positive'
            closure_request_reviewer_comment = 'Confirmed false positive'
            closure_request_reviewer = @{ login = 'admin' }
        }
        $dismissalRequest = @{ status = 'approved' }

        $result = Get-AlertDismissalState -alert $alert -dismissalRequest $dismissalRequest
        $result.stateValue | Should -Match 'resolved \(\[dismissal\].*Dismissal request: approved'
        $result.dismissalStatus | Should -Be 'approved'
        $result.warning | Should -BeNullOrEmpty
    }

}

Describe 'Get-PullRequestNumberFromRef' {
    # Same cases as TestGetPullRequestNumberFromRef in tests/test_action.py, so both runtimes read the same number
    It 'Parses ''<githubRef>''' -TestCases @(
        @{ githubRef = 'refs/pull/120/merge'; expected = '120' }
        @{ githubRef = 'refs/heads/gh-readonly-queue/main/pr-120-abcdef1234567890abcdef1234567890abcdef12'; expected = '120' }
        @{ githubRef = 'refs/heads/gh-readonly-queue/releases/1.0/pr-42-abcdef1234567890abcdef1234567890abcdef12'; expected = '42' }
        @{ githubRef = 'refs/heads/gh-readonly-queue/release/refs/pull/7/pr-120-abcdef1234567890abcdef1234567890abcdef12'; expected = '120' }
        @{ githubRef = 'refs/heads/release/refs/pull/7/merge'; expected = $null }
        @{ githubRef = 'REFS/PULL/120/MERGE'; expected = $null }
        @{ githubRef = 'refs/heads/main'; expected = $null }
        @{ githubRef = ''; expected = $null }
    ) {
        param($githubRef, $expected)
        Should -ActualValue (Get-PullRequestNumberFromRef -githubRef $githubRef) -Be $expected
    }
}
