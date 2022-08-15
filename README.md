# secret-scanning-review-action
Action to detect if a Secret Scanning alert is initially detected in a PR commit

# Architecture
* PowerShell based script wrapped in a GitHub NodeJS action

## Dependencies
* GitHub Dependencies
    * GitHub REST APIs
    * `pwsh-github-action-base` ([Repo](https://github.com/ebekker/pwsh-github-action-base)) PowerShell Actions Wrapper Template
        * by [@ebekker](https://github.com/ebekker/)
   
* External Dependencies
    * `PowerShellForGitHub` ([Gallery](https://www.powershellgallery.com/packages/PowerShellForGitHub/0.16.1) / [Repo](https://github.com/Microsoft/PowerShellForGitHub)) - PowerShell wrapper for GitHub API
        * by [@microsoft](https://github.com/microsoft)
    * GitHubActions ([Gallery](https://www.powershellgallery.com/packages/GitHubActions/1.0.0.3) / [Repo](https://github.com/ebekker/pwsh-github-action-tools)) - PowerShell wrapper of the Github `@actions/core` [toolkit](https://github.com/actions/toolkit/tree/master/packages/core)
        * by [@ebekker](https://github.com/ebekker/)


## REST APIs
* Pulls
   * https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#get-a-pull-request
   * https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#list-commits-on-a-pull-request
* Secret Scanning
   * https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
   * https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-locations-for-a-secret-scanning-alert

# FAQ

## Why Powershell
A few reasons
1. I was challanged by a coworker during a Python v PowerShell discussion
2. To demonstrate actions flexibility
3. Find current pitfalls and work with platform team to improve!