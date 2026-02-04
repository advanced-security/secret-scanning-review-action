# Import the Pester module
Import-Module Pester

# Define the tests
Describe "Require a token" {
    BeforeAll {
        # Set up any variables or conditions needed before running the tests
        #$env:GITHUB_TOKEN = 'test_token'

        # Run the script and capture the exit code
        $output = ./../action.ps1
    }

    It "action.ps1 should fail and require a token" {
        $errorMessageFound = $output | Where-Object { $_ -match "::error::GitHubToken is not set" }
        $errorMessageFound | Should -Not -BeNullOrEmpty
        $LASTEXITCODE | Should -Be 1
    }
}

Describe "Install Dependencies" {
    BeforeAll {
        # Set up any variables or conditions needed before running the tests
        $env:GITHUB_REPOSITORY = 'octodemo/demo-vulnerabilities-ghas'
        $env:GITHUB_REF = 'refs/pull/120/merge'
        $env:GITHUB_STEP_SUMMARY = $(New-Item -Name /_temp/_runner_file_commands/step_summary_a01d8a3b-1412-4059-9cf1-f7c4b54cff76 -ItemType File -Force).FullName
        $env:SSR_FAIL_ON_ALERT = "true"
        $env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED = "true"

        # Delete all environment variables
        # $env:GITHUB_TOKEN = $null
        # $env:GITHUB_REPOSITORY = $null
        # $env:GITHUB_REF = $null
        # $env:GITHUB_STEP_SUMMARY = $null
        # $env:SSR_FAIL_ON_ALERT = $null
        # $env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED = $null


        # Run the script and capture the exit code
        $output = ./../action.ps1
    }


    It "GitHubActions module is installed" {
        $module = Get-Module -ListAvailable -Name GitHubActions -ErrorAction SilentlyContinue
        $module | Should -Not -BeNullOrEmpty
    }

    It "PowerShellForGitHub module is installed" {
        $module = Get-Module -ListAvailable -Name PowerShellForGitHub -ErrorAction SilentlyContinue
        $module | Should -Not -BeNullOrEmpty
    }


}

# Import the module that contains the function to test
#Import-Module GitHubActions

# Define the tests
Describe "Mocked Tests" {
    # Mock the Get-GitHubPullRequest function to return a predefined object
    # Get-GitHubPullRequest -ModuleName GitHubActions {
    # Mock Get-GitHubPullRequest{
    #     return @{
    #         Title = 'Test PR'
    #         commits = 1
    #     }
    # }

    # BeforeAll {
    #     # Set up any variables or conditions needed before running the tests
    #     $env:GITHUB_REPOSITORY = 'octodemo/demo-vulnerabilities-ghas'
    #     $env:GITHUB_REF = 'refs/pull/120/merge'
    #     $env:GITHUB_STEP_SUMMARY = $(New-Item -Name /_temp/_runner_file_commands/step_summary_a01d8a3b-1412-4059-9cf1-f7c4b54cff76 -ItemType File -Force).FullName
    #     $env:SSR_FAIL_ON_ALERT = "true"
    #     $env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED = "true"
    # }


    # Context "context"{
    #     function Get-GitHubPullRequest {
    #         "placeholder function"
    #     }

    #     Mock Get-GitHubPullRequest{
    #         return @{
    #             Title = 'Test PR'
    #             commits = 1
    #         }
    #     }

    #     It "GitHubActions module is installed" {
    #         # Run the script and capture the exit code
    #         $output = & ./../action.ps1 -GitHubToken 'test_token'


    #         Write-Host $output
    #         Assert-MockCalled Get-GitHubPullRequest -Times 1 -ModuleName 'GitHubActions'


    #     }

    # }

}