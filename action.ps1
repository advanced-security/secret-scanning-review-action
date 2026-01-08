<#
.SYNOPSIS
Action to detect if a Secret Scanning alert is initially detected in a PR commit

.DESCRIPTION
Features:
- optional to fail via parameter (even if alert is resolved)

Requirements:
- GITHUB_TOKEN with repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.

.EXAMPLE
PS>gh auth login --scopes repo # <-- Easy to grab a local auth token to test with from here!6
PS>Write-Host "initializing local run! Ensure you provide a valid GITHUB_TOKEN otherwise you will get a 401!!! "
$VerbosePreference = 'SilentlyContinue'
$env:GITHUB_TOKEN = gh auth token
$env:GITHUB_REPOSITORY = 'octodemo/demo-vulnerabilities-ghas'
$env:GITHUB_REF = 'refs/pull/120/merge'
$env:GITHUB_STEP_SUMMARY = $(New-Item -Name /_temp/_runner_file_commands/step_summary_a01d8a3b-1412-4059-9cf1-f7c4b54cff76 -ItemType File -Force).FullName
$env:SSR_FAIL_ON_ALERT = "true"
$env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED = "true"
PS> action.ps1

A simple example execution of the internal pwsh script against an Owner/Repo and Pull Request outside of GitHub Action context

.PARAMETER GitHubToken
        GitHub Token with repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.
        NOTE: This is not required if the GITHUB_TOKEN environment variable is set.

.PARAMETER FailOnAlert
        If provided, will fail the action workflow via non-zero exit code if a matching secret scanning alert is found.
        Additionaly, annotations will show as errors (vs default warnings).
        Default is false.
        NOTE: Currently only works with GitHub Actions as an environment variable SSR_FAIL_ON_ALERT: true

.PARAMETER FailOnAlertExcludeClosed
        If provided, will handle failure exit code / annotations as warnings if the alert is found and the alert is marked as closed (state: 'resolved').
        Default is false.
        NOTE: Currently only works with GitHub Actions as an environment variable SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED: true

.PARAMETER DisablePRComment
        If provided, will disable the PR comment feature.
        Default is false.

.NOTES
Features
    - Actions compatible
        - GitHubActions module ( https://github.com/ebekker/pwsh-github-action-base)
        - options: https://github.com/ebekker/pwsh-github-action-tools/blob/master/docs/GitHubActions/README.md
    - PR File Annotations - https://github.com/actions/toolkit/tree/main/packages/core#annotations
        - warning message - https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-a-warning-message

ToDo List
   - filter out alerts that are before the first commit of the PR
   - graphQL instead of iterating over rest api / or parallel api calls
   - param vs env var (js script enhancement) ... ex's : https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token

Future Enhancements
    - add summary comment to PR if alert is found (1 comment per PR even if multiple runs?)
    - further options for FailOnAlert workflow bool
        - whitelist of resolution types (false_positive, wont_fix, revoked, pattern_edited, pattern_deleted or used_in_tests) - via https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
        - whitelist of secret types (https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets-for-advanced-security)

.LINK
https://github.com/advanced-security/secret-scanning-review-action
#>

param(
    [string]$GitHubToken,
    [bool]$FailOnAlert,
    [bool]$FailOnAlertExcludeClosed,
    [bool]$DisablePRComment
)

# List of supported generic secret types as per:
# https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns
# Includes non-provider patterns and copilot patterns
Set-Variable -Name GENERIC_SECRET_TYPES -Value "password,ec_private_key,generic_private_key,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key" -Option ReadOnly -Scope Script

# Handle `Untrusted repository` prompt
Set-PSRepository PSGallery -InstallationPolicy Trusted

#check if GitHubActions module is installed
if (Get-Module -ListAvailable -Name GitHubActions -ErrorAction SilentlyContinue) {
    Write-ActionDebug "GitHubActions module is installed"
}
else {
    #directly to output here before module loaded to support Write-ActionInfo
    Write-Output "GitHubActions module is not installed.  Installing from Gallery..."
    Install-Module -Name GitHubActions
}

#check if PowerShellForGitHub module is installed
if (Get-Module -ListAvailable -Name PowerShellForGitHub -ErrorAction SilentlyContinue) {
    Write-ActionDebug "PowerShellForGitHub module is installed"
}
else {
    Write-ActionInfo "PowerShellForGitHub module is not installed.  Installing from Gallery..."
    Install-Module -Name PowerShellForGitHub

    #Disable Telemetry since we are accessing sensitive apis - https://github.com/microsoft/PowerShellForGitHub/blob/master/USAGE.md#telemetry
    Set-GitHubConfiguration -DisableTelemetry -SessionOnly
}

#check if GITHUB_TOKEN is set
Write-ActionDebug "GitHubToken parameter is $([String]::IsNullOrWhiteSpace($GitHubToken) ? "NOT SET" : "SET" ). $($null -ne $env:GITHUB_TOKEN ? "Overridden by environment variable GITHUB_TOKEN" : $null)"
if ($null -ne $env:GITHUB_TOKEN) {
    $GitHubToken = $env:GITHUB_TOKEN
    Write-ActionDebug "GitHubToken is now set from GITHUB_TOKEN environment variable"
}

if ([String]::IsNullOrWhiteSpace($GitHubToken)) {
    Set-ActionFailed -Message "GitHubToken is not set"
}

#configure github module with authentication token ... sample code taken from example 2 for GitHub Action!
#Get-Help Set-GitHubAuthentication -Examples

# Allows you to specify your access token as a plain-text string ("<Your Access Token>")
# which will be securely stored on the machine for use in all future PowerShell sessions.
$secureString = ($GitHubToken | ConvertTo-SecureString -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential "username is ignored", $secureString
Set-GitHubAuthentication -Credential $cred
$GitHubToken = $secureString = $cred = $null # clear this out now that it's no longer needed

#Init Owner/Repo/PR variables+
$actionRepo = Get-ActionRepo
$OrganizationName = $actionRepo.Owner
$RepositoryName = $actionRepo.Repo

#get the pull request number from the GITHUB_REF environment variable
if ($env:GITHUB_REF -match 'refs/pull/([0-9]+)') {
    $PullRequestNumber = $matches[1]
}
else {
    #https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request
    Set-ActionFailed -Message "Action workflow must be run on 'pull_request'.  GITHUB_REF is not set to a pull request number"
}

#Default Org / Repo for all GH api calls
Set-GitHubConfiguration -DefaultOwnerName $OrganizationName -DefaultRepositoryName $RepositoryName

<# API: GET PR
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#get-a-pull-request
    - format: /repos/{owner}/{repo}/pulls/{pull_number}
#>
try {
    $pr = Get-GitHubPullRequest -PullRequest $PullRequestNumber
}
catch {
    Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' PR#$PullRequestNumber info.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}
Write-ActionInfo "PR#$PullRequestNumber '$($pr.Title)' has $($pr.commits) commit$($pr.commits -eq 1 ? '' : 's')"

<# API: GET PR Commits
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#list-commits-on-a-pull-request
    - format: /repos/{owner}/{repo}/pulls/{pull_number}/commits
#>
$prCommitsUrl = [uri]$pr.commits_url
try {
    $commits = Invoke-GHRestMethod -Method GET -Uri $prCommitsUrl.AbsolutePath
}
catch {
    Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' PR#$PullRequestNumber commits.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}

#for each PR commit add the commit sha to the list
$prCommitShaList = @()
foreach ($commit in $commits) {
    #     ex commit:
    #     sha          : d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d
    $prCommitShaList += $commit.sha
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
$repoAlertsUrl = "/repos/$OrganizationName/$RepositoryName/secret-scanning/alerts?per_page=$perPage"
try {
    $alertsResponse = Invoke-GHRestMethod -Method GET -Uri $repoAlertsUrl -ExtendedResult $true
    $alerts = [System.Collections.ArrayList]@($alertsResponse.result)
    # Get the next page of secret scanning alerts if there is one
    while ($alertsResponse.nextLink) {
        $alertsResponse = Invoke-GHRestMethod -Method GET -Uri $alertsResponse.nextLink -ExtendedResult $true
        $alerts.AddRange($alertsResponse.result)
    }
    Write-ActionInfo "Found $($alerts.Count) default secret scanning alert$($alerts.Count -eq 1 ? '' : 's') for '$OrganizationName/$RepositoryName'"
}
catch {
    Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' secret scanning alerts.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}

# Second call: Get generic secret scanning alerts (non-provider patterns and copilot patterns)
$genericAlertsUrl = "/repos/$OrganizationName/$RepositoryName/secret-scanning/alerts?per_page=$perPage&secret_type=$GENERIC_SECRET_TYPES"
try {
    $genericAlertsResponse = Invoke-GHRestMethod -Method GET -Uri $genericAlertsUrl -ExtendedResult $true
    $genericAlerts = [System.Collections.ArrayList]@($genericAlertsResponse.result)
    # Get the next page of generic secret scanning alerts if there is one
    while ($genericAlertsResponse.nextLink) {
        $genericAlertsResponse = Invoke-GHRestMethod -Method GET -Uri $genericAlertsResponse.nextLink -ExtendedResult $true
        $genericAlerts.AddRange($genericAlertsResponse.result)
    }
    Write-ActionInfo "Found $($genericAlerts.Count) generic secret scanning alert$($genericAlerts.Count -eq 1 ? '' : 's') for '$OrganizationName/$RepositoryName'"

    # Merge alerts and deduplicate by alert number
    $alertNumbers = @{}
    foreach ($alert in $alerts) {
        $alertNumbers[$alert.number] = $true
    }
    foreach ($genericAlert in $genericAlerts) {
        if (-not $alertNumbers.ContainsKey($genericAlert.number)) {
            [void]$alerts.Add($genericAlert)
            $alertNumbers[$genericAlert.number] = $true
        }
    }
    Write-ActionInfo "Found $($alerts.Count) total secret scanning alert$($alerts.Count -eq 1 ? '' : 's') after merging and deduplication"
}
catch {
    Write-ActionWarning -Message "Error getting generic secret scanning alerts for '$OrganizationName/$RepositoryName'. This may be expected if generic secrets are not enabled. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}

#for each secret scanning alert, find the initial location of the secret and theh list
$alertCount = 0
$alertsInitiatedFromPr = @()
foreach ($alert in $alerts) {
    <# API: GET Secret Scanning Alert List Locations
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
    - format: /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations
    - returns: 1 "location" object per file where secret detected
    - note: details.commit_sha - SHA of the commit where the secret was detected
    #>
    $repoAlertLocationUrl = [uri]"$($alert.locations_url)?per_page=$perPage"
    try {
        $locationsResult = Invoke-GHRestMethod -Method GET -Uri "$($repoAlertLocationUrl.AbsolutePath)$($repoAlertLocationUrl.Query)" -ExtendedResult $true
        $locations = $locationsResult.result
        # Get the next page of secret scanning alert locations if there is one
        while ($locationsResult.nextLink) {
            $locationsResult = Invoke-GHRestMethod -Method GET -Uri $locationsResult.nextLink -ExtendedResult $true
            $locations += $locationsResult.result
        }
        Write-ActionDebug "Found $($locations.Count) secret scanning alert locations for alert #$($alert.number)"
    }
    catch {
        Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' secret scanning alert locations.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
    }

    $locationMatches = @()
    foreach ($location in $locations) {
        $alertInitialCommitSha = $location.details.commit_sha

        #if alertInitialCommitSha in list of commit shas, then add location to list to further add to the alert list
        if ($alertInitialCommitSha -in $prCommitShaList) {
            Write-ActionDebug "YES! Found a repo secret scanning alert (# $($alert.number)) on initial commit sha: $alertInitialCommitSha that originated from a PR#$PullRequestNumber commit"
            $locationMatches += $location
        }
        else {
            Write-ActionDebug "NO! Did not find a repo secret scanning alert (# $($alert.number)) on initial commit sha: $alertInitialCommitSha that originated from a PR#$PullRequestNumber commit"
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
#   * an Errror/Warning Actions annotation
#   * add a step summary markdown table row of the alert details
$numSecretsAlertsDetected = 0
$numSecretsAlertLocationsDetected = 0
$shouldFailAction = $false
$markdownSummaryTableRows = $null

foreach ($alert in $alertsInitiatedFromPr) {
    $numSecretsAlertsDetected++
    foreach ($location in $alert.locations) {
        $numSecretsAlertLocationsDetected++
        $message = "A $($alert.state -eq 'resolved' ? "Closed as '$($alert.resolution)'" : 'New') Secret Detected in Pull Request #$PullRequestNumber Commit SHA:$($location.details.commit_sha.SubString(0,7)). '$($alert.secret_type_display_name)' Secret: $($alert.html_url) Commit: $($pr.html_url)/commits/$($location.details.commit_sha)"
        $shouldBypass = ($alert.state -eq 'resolved') -and $FailOnAlertExcludeClosed

        if ($FailOnAlert -and !$shouldBypass) {
            # Writes an Action Error to the message log and creates an annotation associated with the file and line/col number. (# TODO - no support for ?Title? .. send PR to maintainer!)
            #   -docs: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message
            Write-ActionError -Message $message -File $location.details.path -Line $location.details.start_line -Col $location.details.start_column
            $shouldFailAction = $true
            $passFail = '[🔴](# "Error")'
        }
        else {
            # Writes an Action Warning to the message log and creates an annotation associated with the file and line/col number. (# TODO - no support for ?Title? .. send PR to maintainer!)
            #   -docs: https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-a-warning-message
            Write-ActionWarning -Message $message -File $location.details.path -Line $location.details.start_line -Col $location.details.start_column
            $passFail = '[🟡](# "Warning")'
        }

        $markdownSummaryTableRows += "| $passFail | :key: [$($alert.number)]($($alert.html_url)) | $($alert.secret_type_display_name) | $($alert.state) | $($null -eq $alert.resolution ? '❌' : $alert.resolution) | $($alert.push_protection_bypassed) | [$($location.details.commit_sha.SubString(0,7))]($($pr.html_url)/commits/$($location.details.commit_sha)) | `n"
    }
}

# One line summary of alerts found
$summary = "$($numSecretsAlertsDetected -gt 0 ? '🚨' : '👍') Found [$numSecretsAlertsDetected] secret scanning alert$($numSecretsAlertsDetected -eq 1 ? '' : 's') across [$numSecretsAlertLocationsDetected] location$($numSecretsAlertLocationsDetected -eq 1 ? '' : 's') that originated from a PR#$PullRequestNumber commit"

#Actions Markdown Summary - https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary
#flashy! - https://github.blog/2022-05-09-supercharging-github-actions-with-job-summaries/
$markdownSummary = "# :unlock: [PR#$PullRequestNumber]($($pr.html_url)) SECRET SCANNING REVIEW SUMMARY :unlock: `n $summary `n"

#build a markdown table of any alerts
if ($alertsInitiatedFromPr.Count -gt 0) {

    $markdownSummary += @"
| Status 🚦 | Secret Alert 🚨 | Secret Type 𝌎 | State :question: | Resolution :checkered_flag: | Push Bypass 👋 | Commit #️⃣ |
| --- | --- | --- | --- | --- | --- | --- |`n
"@

    $markdownSummary += $markdownSummaryTableRows
}

# PR Comment Summary only if not disabled and alerts were found
if (!$DisablePRComment -and $alertsInitiatedFromPr.Count -gt 0) {
    <# API: GET PR COMMENTS
    - docs: https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#get-an-issue-comment
    - format: /repos/{owner}/{repo}/issues/{pull_number}/comments
    #>
    $commentUrl = "/repos/$OrganizationName/$RepositoryName/issues/$PullRequestNumber/comments?per_page=100"
    try {
        $comments = Invoke-GHRestMethod -Method GET -Uri $commentUrl
    }
    catch {
        Set-ActionFailed -Message "Error reading comment from '$OrganizationName/$RepositoryName' Pull Request#$PullRequestNumber.  Ensure GITHUB_TOKEN has `pull_requests:read` repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
    }

    $prCommentWatermark = "<!-- secret-scanning-review-pr-comment-watermark -->"
    $existingComment = $comments | Where-Object { $_.body -match $prCommentWatermark } | Select-Object -First 1
    $comment = @{
        body = "{0}`n{1}`n<!-- {2} -->" -f $prCommentWatermark, $markdownSummary, (Get-Date).ToUniversalTime().ToString("o")
    }
    try {
        if ($null -ne $existingComment) {
            $commentResponse = Invoke-GHRestMethod -Method PATCH -Uri $existingComment.url -Body $($comment | ConvertTo-Json)
        }
        else {
            $commentResponse = Invoke-GHRestMethod -Method POST -Uri $commentUrl -Body $($comment | ConvertTo-Json)
        }
        Write-ActionInfo "Updated PR Comment: $($commentResponse.html_url)"
    }
    catch {
        Set-ActionFailed -Message "Error adding comment to '$OrganizationName/$RepositoryName' Pull Request#$PullRequestNumber.  Ensure GITHUB_TOKEN has `pull_requests:write` repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
    }
}
else {
    Write-ActionDebug "Skipping PR comment update - DisablePRComment is set to $DisablePRComment and alertsInitiatedFromPr is $($alertsInitiatedFromPr.Count)"
}

#Output Step Summary - To the GITHUB_STEP_SUMMARY environment file. GITHUB_STEP_SUMMARY is unique for each step in a job
$markdownSummary > $env:GITHUB_STEP_SUMMARY
#Get-Item -Path $env:GITHUB_STEP_SUMMARY | Show-Markdown
Write-ActionDebug "Markdown Summary from env var GITHUB_STEP_SUMMARY: '$env:GITHUB_STEP_SUMMARY' "
Write-ActionDebug $(Get-Content $env:GITHUB_STEP_SUMMARY)

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
