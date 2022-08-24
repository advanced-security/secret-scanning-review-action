<#
.SYNOPSIS
Action to detect if a Secret Scanning alert is initially detected in a PR commit

.DESCRIPTION
Features:
- optional to fail via parameter (even if alert is resolved)

Requirements:
- GITHUB_TOKEN with repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.

.EXAMPLE
PS>Write-Host "initializing local run! Ensure you provide a valid GITHUB_TOKEN otherwise you will get a 401!!! "
$VerbosePreference = 'SilentlyContinue'
$env:GITHUB_TOKEN = "<get a token from github>"
$env:GITHUB_REPOSITORY = 'octodemo/demo-vulnerabilities-ghas'
$env:GITHUB_REF = 'refs/pull/120/merge'
$env:SSR_FAIL_ON_ALERT = "true"
$env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED = "true"
PS> action.ps1

A simple example execution of the internal pwsh script against an Owner/Repo and Pull Request outside of GitHub Action context

.PARAMETER FailOnAlert
        If provided, will fail the action workflow via non-zero exit code if a matching secret scanning alert is found.  
        Additionaly, annotations will show as errors (vs default warnings).
        Default is false. 
        NOTE: Currently only works with GitHub Actions as an environment variable SSR_FAIL_ON_ALERT: true

.PARAMETER FailOnAlertExcludeClosed
        If provided, will handle failure exit code / annotations as warnings if the alert is found and the alert is marked as closed (state: 'resolved').        
        Default is false. 
        NOTE: Currently only works with GitHub Actions as an environment variable SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED: true

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
    - further options for FailOnAlert workflow switch
        - whitelist of resolution types (false_positive, wont_fix, revoked, pattern_edited, pattern_deleted or used_in_tests) - via https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
        - whitelist of secret types (https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets-for-advanced-security)

.LINK
https://github.com/felickz/secret-scanning-review-action
#>

param(
    [Switch]$FailOnAlert,
    [Switch]$FailOnAlertExcludeClosed
)

# Handle `Untrusted repository` prompt
Set-PSRepository PSGallery -InstallationPolicy Trusted

#check if GitHubActions module is installed
if (Get-Module -ListAvailable -Name GitHubActions -ErrorAction SilentlyContinue)
{
    Write-ActionDebug "GitHubActions module is installed"
}
else
{
    #directly to output here before module loaded to support Write-ActionInfo
    Write-Output "GitHubActions module is not installed.  Installing from Gallery..."
    Install-Module -Name GitHubActions
}

#check if PowerShellForGitHub module is installed
if (Get-Module -ListAvailable -Name PowerShellForGitHub -ErrorAction SilentlyContinue)
{
    Write-ActionDebug "PowerShellForGitHub module is installed"
}
else
{
    Write-ActionInfo "PowerShellForGitHub module is not installed.  Installing from Gallery..."
    Install-Module -Name PowerShellForGitHub

    #Disable Telemetry since we are accessing sensitive apis - https://github.com/microsoft/PowerShellForGitHub/blob/master/USAGE.md#telemetry
    Set-GitHubConfiguration -DisableTelemetry -SessionOnly
}

#check if GITHUB_TOKEN is set
if ($null -eq $env:GITHUB_TOKEN)
{
    Set-ActionFailed -Message "GITHUB_TOKEN is not set"    
}
else
{
    Write-ActionDebug "GITHUB_TOKEN is set"
}

#configure github module with authentication token ... sample code taken from example 2 for GitHub Action!
#Get-Help Set-GitHubAuthentication -Examples

# Allows you to specify your access token as a plain-text string ("<Your Access Token>")
# which will be securely stored on the machine for use in all future PowerShell sessions.
$secureString = ($env:GITHUB_TOKEN | ConvertTo-SecureString -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential "username is ignored", $secureString
Set-GitHubAuthentication -Credential $cred
$secureString = $null # clear this out now that it's no longer needed
$cred = $null # clear this out now that it's no longer needed

#Init Owner/Repo/PR variables+
$actionRepo = Get-ActionRepo
$OrganizationName = $actionRepo.Owner
$RepositoryName = $actionRepo.Repo

# Init FailOnAlert switch
# workaround - read $FailOnAlert from the environment variable
Write-ActionDebug "FailOnAlert is set to '$FailOnAlert'. $($null -ne $env:SSR_FAIL_ON_ALERT ? "Overridden by environment variable SSR_FAIL_ON_ALERT: '$env:SSR_FAIL_ON_ALERT'" : $null)" 
if($null -ne $env:SSR_FAIL_ON_ALERT)
{
    try {
        $FailOnAlert = [System.Convert]::ToBoolean($env:SSR_FAIL_ON_ALERT) 
     } catch [FormatException] {
        $FailOnAlert = $false
    }
}

# Init FailOnAlertExcludeClosed switch
# workaround - read $FailOnAlertExcludeClosed from the environment variable
Write-ActionDebug "FailOnAlertExcludeClosed is set to '$FailOnAlertExcludeClosed'. $($null -ne $env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED ? "Overridden by environment variable SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED: '$env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED'" : $null)" 
if($null -ne $env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED)
{
    try {
        $FailOnAlertExcludeClosed = [System.Convert]::ToBoolean($env:SSR_FAIL_ON_ALERT_EXCLUDE_CLOSED) 
     } catch [FormatException] {
        $FailOnAlertExcludeClosed = $false
    }
}

#get the pull request number from the GITHUB_REF environment variable
if ($env:GITHUB_REF -match 'refs/pull/([0-9]+)')
{
    $PullRequestNumber = $matches[1]
}
else
{
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
} catch {
    Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' PR#$PullRequestNumber info.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}
Write-ActionInfo "PR#$PullRequestNumber '$($pr.Title)' has $($pr.commits) commits"

<# API: GET PR Commits  
    - docs: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#list-commits-on-a-pull-request
    - format: /repos/{owner}/{repo}/pulls/{pull_number}/commits
#>
$prCommitsUrl = [uri]$pr.commits_url
try {
    $commits = Invoke-GHRestMethod -Method GET -Uri $prCommitsUrl.AbsolutePath
} catch {
    Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' PR#$PullRequestNumber commits.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
}

#for each PR commit add the commit sha to the list
$prCommitShaList = @()
foreach ($commit in $commits){
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
#>
$repoAlertsUrl = "/repos/$OrganizationName/$RepositoryName/secret-scanning/alerts"
try {
$alerts = Invoke-GHRestMethod -Method GET -Uri $repoAlertsUrl
} catch {
    Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' secret scanning alerts.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
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
    $repoAlertLocationUrl = [uri]$alert.locations_url
    try {
        $locations = Invoke-GHRestMethod -Method GET -Uri $repoAlertLocationUrl.AbsolutePath
    } catch {
        Set-ActionFailed -Message "Error getting '$OrganizationName/$RepositoryName' secret scanning alert locations.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
    }

    $locationMatches = @()
    foreach ($location in $locations) {        
        $alertInitialCommitSha = $location.details.commit_sha

        #if alertInitialCommitSha in list of commit shas, then add location to list to further add to the alert list
        if ($alertInitialCommitSha -in $prCommitShaList) {
            Write-ActionDebug "YES! Found a secret scanning alert (# $($alert.number)) on initial commit sha: $alertInitialCommitSha that originated from a PR#$PullRequestNumber commit"
            $locationMatches += $location
        }
        else {
            Write-ActionDebug "NO! Did not find a secret scanning alert (# $($alert.number)) on initial commit sha: $alertInitialCommitSha that originated from a PR#$PullRequestNumber commit"
        }
    }

    #if there are any matches, then add alert to the global list of alerts/locations that match the PR
    if($locationMatches.Count -gt 0) {
        $null = $alert | Add-Member -MemberType NoteProperty -Name 'locations' -Value $locationMatches -PassThru
        $alertsInitiatedFromPr += $alert
    }
   
    #output progress
    $alertCount++
    $progress = [math]::Round(($alertCount/$alerts.count)*100, 0)
    Write-Progress -Activity "Secret Scanning Alert Search" -Status "Progress: $progress%" -PercentComplete $progress
}

#Clear progress bar and finish
Write-Progress -Activity "Secret Scanning Alert Search" -Completed


#Output an Errror/Warning Actions Annotation for each alert that was found
$numSecretsAlertsDetected = 0
$numSecretsAlertLocationsDetected = 0
$shouldFailAction = $false

foreach ($alert in $alertsInitiatedFromPr) {
    $numSecretsAlertsDetected++
    foreach($location in $alert.locations) {                
        $numSecretsAlertLocationsDetected++
        $message = "$($alert.state -eq 'resolved' ? "Closed as '$($alert.resolution)'" : 'New') Secret Detected in Pull Request #$PullRequestNumber Commit SHA:$($location.details.commit_sha.SubString(0,7)).  Secret:$($alert.html_url) Commit:$($pr.html_url)/commits/$($location.details.commit_sha)"        
        $shouldBypass = ($alert.state -eq 'resolved') -and $FailOnAlertExcludeClosed

        if($FailOnAlert -and !$shouldBypass) {
            # Writes an Action Error to the message log and creates an annotation associated with the file and line/col number. (# TODO - no support for ?Title? .. send PR to maintainer!)
            #   -docs: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message
            Write-ActionError -Message $message -File $location.details.path -Line $location.details.start_line -Col $location.details.start_column
            $shouldFailAction = $true
        }
        else {
            # Writes an Action Warning to the message log and creates an annotation associated with the file and line/col number. (# TODO - no support for ?Title? .. send PR to maintainer!)
            #   -docs: https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-a-warning-message
            Write-ActionWarning -Message $message -File $location.details.path -Line $location.details.start_line -Col $location.details.start_column
        }
    }  
}

#TODO - consider outputing this summary to a comment on the PR
# #Add 1 time comment to PR with summary of alerts found
# $comment = @{
#     body = "Found $numSecretsAlertsDetected secret scanning alerts in this Pull Request.  $numSecretsAlertLocationsDetected of those alerts were detected in this Pull Request."
# }
# $commentUrl = "/repos/$OrganizationName/$RepositoryName/pulls/$PullRequestNumber/comments"
# try {
#     $comment = Invoke-GHRestMethod -Method POST -Uri $commentUrl -Body $comment
# } catch {
#     Set-ActionFailed -Message "Error adding comment to '$OrganizationName/$RepositoryName' Pull Request#$PullRequestNumber.  Ensure GITHUB_TOKEN has proper repo permissions. (StatusCode:$($_.Exception.Response.StatusCode.Value__) Message:$($_.Exception.Message)"
# }


#Output Summary and Return exit code 
# -  any error alerts were found in FailOnAlert mode (observing FailOnAlertExcludeClosed), exit with error code 1
# -  otherwise, return 0
$summary = "SECRET SCANNING REVIEW SUMMARY: Found [$numSecretsAlertsDetected] alert$($numSecretsAlertsDetected -eq 1 ? '' : 's') across [$numSecretsAlertLocationsDetected] location$($numSecretsAlertLocationsDetected -eq 1 ? '' : 's') that originated from a PR#$PullRequestNumber commit"

if($alertsInitiatedFromPr.Count -gt 0 -and $shouldFailAction) {
    Set-ActionFailed -Message $summary
}
else {
    Write-ActionInfo $summary    
    exit 0
}