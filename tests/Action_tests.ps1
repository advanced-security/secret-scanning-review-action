# Tests for action.ps1 helper functions

Import-Module Pester

BeforeAll {
    # Import the ActionHelpers module from the repo root
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'ActionHelpers.psm1') -Force

    # Define mock functions for external dependencies
    function global:Invoke-GHRestMethod { 
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
        param(
            $Method, 
            $Uri
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

    It 'Handles URLs with trailing slash' {
        # Last segment after split would be empty string
        Get-IdFromUrl -url 'https://api.github.com/repos/owner/repo/pulls/123/' | Should -BeNullOrEmpty
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

        $result = Get-PullRequestHtmlUrl -apiUrl 'https://api.github.com/repos/owner/repo/pulls/42'
        $result | Should -Be 'https://github.com/owner/repo/pull/42'
    }

    It 'Returns null when API call fails (404)' {
        Mock Invoke-GHRestMethod { throw "Not Found" } -ModuleName ActionHelpers

        $result = Get-PullRequestHtmlUrl -apiUrl 'https://api.github.com/repos/owner/repo/pulls/999'
        $result | Should -BeNullOrEmpty
    }
}

Describe 'Get-AlertLocationWithLink' {
    BeforeEach {
        # Default mock - return null to test fallback paths
        Mock Get-PullRequestHtmlUrl { return $null } -ModuleName ActionHelpers
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

    It 'Returns fallback URL for pull_request_review_comment when API fails' {
        Mock Get-PullRequestHtmlUrl { return $null } -ModuleName ActionHelpers

        $location = @{
            type = 'pull_request_review_comment'
            details = @{ pull_request_review_comment_url = 'https://api.github.com/repos/owner/repo/pulls/comments/12345' }
        }
        $result = Get-AlertLocationWithLink -location $location -prHtmlUrl 'https://github.com/owner/repo/pull/42' -pullRequestNumber 42
        $result | Should -Be '[Pull request review comment](https://github.com/owner/repo/pull/42#discussion_r12345)'
    }
}

Describe 'Get-PullRequestComment' {
    It 'Returns empty array when API call fails' {
        Mock Invoke-GHRestMethod { throw "API Error" } -ModuleName ActionHelpers
        Mock Write-ActionDebug { } -ModuleName ActionHelpers

        $result = Get-PullRequestComment -owner 'owner' -repo 'repo' -pullNumber 42
        $result | Should -BeNullOrEmpty
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
            $Uri -eq '/repos/myorg/myrepo/dismissal-requests/secret-scanning/99' -and $Method -eq 'GET'
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