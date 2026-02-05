# Tests for action.ps1 functions

Import-Module Pester

BeforeAll {
    # Define the functions from action.ps1 for testing
    # We extract these to avoid running the full script which has side effects (module installation, auth setup, etc.)

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
