<#
.SYNOPSIS
Action to detect if a Secret Scanning alert is initially detected in a PR commit

.DESCRIPTION
Features:
- optional to fail via parameter (even if alert is resolved)

Requirements:
- GITHUB_TOKEN with repo scope or security_events scope. For public repositories, you may instead use the public_repo scope.

.EXAMPLE
PS>$VerbosePreference = 'Continue'
PS>$env:GITHUB_TOKEN = "<get a token from github>"    
PS>$env:GITHUB_REPOSITORY = 'octodemo/demo-vulnerabilities-ghas'
PS>$env:GITHUB_REF = 'refs/pull/120/merge'
PS> action.ps1

A simple example execution of the internal pwsh script against an Owner/Repo and Pull Request outside of GitHub Action context

.PARAMETER FailOnAlert
        If provided, will fail the action workflow via non-zero exit code if a matching secret scanning alert is found.

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
    - options for FailOnAlert workflow switch
        - if offending alert is in bypassed state, then it is not a failure
        - whitelist of secret types (https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets-for-advanced-security)


.LINK
https://github.com/felickz/secret-scanning-review-action
#>

param(
    [Switch]$FailOnAlert
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
####@{url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/119; id=1022143435; node_id=PR_kwDOD0gIsM487KvL; html_url=https://github.com/octodemo/demo-vulnerabilities-ghas/pull/119; diff_url=https://github.com/octodemo/demo-vulnerabilities-ghas/pull/119.diff; patch_url=https://github.com/octodemo/demo-vulnerabilities-ghas/pull/119.patch; issue_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/119; number=119; state=open; locked=False; title=test adding GCP API key; user=; body=; created_at=08/10/2022 02:23:05; updated_at=08/10/2022 19:49:58; closed_at=; merged_at=; merge_commit_sha=02b4b03dee89cb4d65112ab8f7f32756e4a1f684; assignee=; assignees=System.Object[]; requested_reviewers=System.Object[]; requested_teams=System.Object[]; labels=System.Object[]; milestone=; draft=False; commits_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/119/commits; review_comments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/119/comments; review_comment_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/comments{/number}; comments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/119/comments; statuses_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/statuses/d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d; head=; base=; _links=; author_association=COLLABORATOR; auto_merge=; active_lock_reason=; merged=False; mergeable=True; rebaseable=True; mergeable_state=blocked; merged_by=; comments=0; review_comments=0; maintainer_can_modify=True; commits=2; additions=3; deletions=0; changed_files=1}

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
foreach ($commit in $commits)
{
    #     ex commit:
    #     sha          : d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d
    $prCommitShaList += $commit.sha
}

Write-ActionInfo "PR#$PullRequestNumber Commit SHA list: $($prCommitShaList -join ",")"

####@{id=256379056; node_id=MDEwOlJlcG9zaXRvcnkyNTYzNzkwNTY=; name=demo-vulnerabilities-ghas; full_name=octodemo/demo-vulnerabilities-ghas; private=True; owner=; html_url=https://github.com/octodemo/demo-vulnerabilities-ghas; description=This repo contains examples of all security feature available for GitHub Enterprise and GHAS. Use it for demo purposes only.; fork=False; url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas; forks_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/forks; keys_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/keys{/key_id}; collaborators_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/collaborators{/collaborator}; teams_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/teams; hooks_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/hooks; issue_events_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/events{/number}; events_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/events; assignees_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/assignees{/user}; branches_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/branches{/branch}; tags_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/tags; blobs_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/blobs{/sha}; git_tags_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/tags{/sha}; git_refs_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/refs{/sha}; trees_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/trees{/sha}; statuses_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/statuses/{sha}; languages_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/languages; stargazers_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/stargazers; contributors_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/contributors; subscribers_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/subscribers; subscription_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/subscription; commits_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/commits{/sha}; git_commits_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/commits{/sha}; comments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/comments{/number}; issue_comment_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/comments{/number}; contents_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/contents/{+path}; compare_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/compare/{base}...{head}; merges_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/merges; archive_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/{archive_format}{/ref}; downloads_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/downloads; issues_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues{/number}; pulls_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls{/number}; milestones_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/milestones{/number}; notifications_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/notifications{?since,all,participating}; labels_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/labels{/name}; releases_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/releases{/id}; deployments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/deployments; created_at=04/17/2020 02:17:12; updated_at=05/17/2022 21:03:00; pushed_at=08/10/2022 19:47:32; git_url=git://github.com/octodemo/demo-vulnerabilities-ghas.git; ssh_url=org-38940897@github.com:octodemo/demo-vulnerabilities-ghas.git; clone_url=https://github.com/octodemo/demo-vulnerabilities-ghas.git; svn_url=https://github.com/octodemo/demo-vulnerabilities-ghas; homepage=; size=24244; stargazers_count=8; watchers_count=8; language=JavaScript; has_issues=True; has_projects=True; has_downloads=True; has_wiki=True; has_pages=False; forks_count=8; mirror_url=; archived=False; disabled=False; open_issues_count=71; license=; allow_forking=True; is_template=False; web_commit_signoff_required=False; topics=System.Object[]; visibility=internal; forks=8; open_issues=71; watchers=8; default_branch=main; permissions=; temp_clone_token=AANNZW2QMTIDF37VXPAAASLC6YJFM; allow_squash_merge=True; allow_merge_commit=True; allow_rebase_merge=True; allow_auto_merge=False; delete_branch_on_merge=False; allow_update_branch=False; use_squash_pr_title_as_default=False; squash_merge_commit_message=COMMIT_MESSAGES; squash_merge_commit_title=COMMIT_OR_PR_TITLE; merge_commit_message=PR_TITLE; merge_commit_title=MERGE_MESSAGE; organization=; security_and_analysis=; network_count=8; subscribers_count=0}
####$repo = Get-GitHubRepository -OwnerName $OrganizationName -RepositoryName $RepositoryName

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
        #@{path=secrets.yml; start_line=1; end_line=1; start_column=11; end_column=32; blob_sha=d233fb964b86e09d4a99bba85c6006dcc4c9258f; blob_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/blobs/d233fb964b86e09d4a99bba85c6006dcc4c9258f; commit_sha=44d3503204f61baffcad1f2293ab9dd41db4820a; commit_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/commits/44d3503204f61baffcad1f2293ab9dd41db4820a}
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

$numSecretsAlertsDetected = 0
$numSecretsAlertLocationsDetected = 0
#output the alert url for each alert that was found
foreach ($alert in $alertsInitiatedFromPr) {
    $numSecretsAlertsDetected++
    foreach($location in $alert.locations) {        
        # TODO - no support for ?Title? .. send PR to maintainer!
        $numSecretsAlertLocationsDetected++
        # Writes an Action Warning to the message log and creates an annotation associated with the file and line/col number.
        #   -docs: https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-a-warning-message
        Write-ActionWarning -Message "$($alert.push_protection_bypassed?'Bypassed':'New') Secret Detected in Pull Request #$PullRequestNumber Commit SHA:$($location.details.commit_sha.SubString(0,7)).  Secret:$($alert.html_url) Commit:$($pr.html_url)/commits/$($location.details.commit_sha)" -File $location.details.path -Line $location.details.start_line -Col $location.details.start_column
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

$summary = "SECRET SCANNING REVIEW SUMMARY: Found [$numSecretsAlertsDetected] alert$($numSecretsAlertsDetected -eq 1 ? '' : 's') across [$numSecretsAlertLocationsDetected] location$($numSecretsAlertLocationsDetected -eq 1 ? '' : 's') that originated from a PR#$PullRequestNumber commit"


#if any alerts were found in FailOnAlert mode, exit with error code 1
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


if($alertsInitiatedFromPr.Count -gt 0 -and $FailOnAlert) {
    Set-ActionFailed -Message $summary
}
else {
    Write-ActionInfo $summary    
    exit 0
}