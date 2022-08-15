#DONE
#  - optional to fail via parameter
#  - progress bar

#TODO 
#- actions compatible
#  - GitHubActions module ( https://github.com/ebekker/pwsh-github-action-base)
#     - options: https://github.com/ebekker/pwsh-github-action-tools/blob/master/docs/GitHubActions/README.md
#  - Annotations - https://github.com/actions/toolkit/tree/main/packages/core#annotations
#     - warning message - https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-a-warning-message
#  - test Get-ActionRepo vs params
#- error handling for failing apis (404 when not authorized, etc)
#- output current state of alert (if it was bypassed pp)
#- filter out alerts that are before the first commit of the PR
#- graphQL instead of iterating over rest api / or parallel api calls
#- support step debug logs == verbose mode (pwsh-github-action-tools support this?)
#- ReadMe + architecture



param(
    [Switch]$ErrorOnAlert 
)

###DEBUG MODE
$VerbosePreference = 'Continue'

$env:GITHUB_REPOSITORY = 'octodemo/demo-vulnerabilities-ghas'
$env:GITHUB_REF = 'refs/pull/120/merge'
####

#check if PowerShellForGitHub module is installed
if (Get-Module -ListAvailable -Name PowerShellForGitHub -ErrorAction SilentlyContinue)
{
    Write-Verbose "PowerShellForGitHub module is installed"
}
else
{
    Write-Host "PowerShellForGitHub module is not installed"
    Install-Module -Name PowerShellForGitHub
}

#check if GitHubActions module is installed
if (Get-Module -ListAvailable -Name GitHubActions -ErrorAction SilentlyContinue)
{
    Write-Verbose "GitHubActions module is installed"
}
else
{
    Write-Host "GitHubActions module is not installed"
    Install-Module -Name GitHubActions
}


#check if GITHUB_TOKEN is set
if ($null -eq $env:GITHUB_TOKEN)
{
    Write-Host "GITHUB_TOKEN is not set"
    exit 1
}
else
{
    Write-Verbose "GITHUB_TOKEN is set"
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

#get PR info
$pr = Get-GitHubPullRequest -PullRequest $PullRequestNumber
Write-Host "PR: $($pr.Title) has $($pr.commits) commits"
####@{url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/119; id=1022143435; node_id=PR_kwDOD0gIsM487KvL; html_url=https://github.com/octodemo/demo-vulnerabilities-ghas/pull/119; diff_url=https://github.com/octodemo/demo-vulnerabilities-ghas/pull/119.diff; patch_url=https://github.com/octodemo/demo-vulnerabilities-ghas/pull/119.patch; issue_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/119; number=119; state=open; locked=False; title=test adding GCP API key; user=; body=; created_at=08/10/2022 02:23:05; updated_at=08/10/2022 19:49:58; closed_at=; merged_at=; merge_commit_sha=02b4b03dee89cb4d65112ab8f7f32756e4a1f684; assignee=; assignees=System.Object[]; requested_reviewers=System.Object[]; requested_teams=System.Object[]; labels=System.Object[]; milestone=; draft=False; commits_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/119/commits; review_comments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/119/comments; review_comment_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/comments{/number}; comments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/119/comments; statuses_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/statuses/d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d; head=; base=; _links=; author_association=COLLABORATOR; auto_merge=; active_lock_reason=; merged=False; mergeable=True; rebaseable=True; mergeable_state=blocked; merged_by=; comments=0; review_comments=0; maintainer_can_modify=True; commits=2; additions=3; deletions=0; changed_files=1}

#commits_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls/119/commits;
$prCommitsUrl = [uri]$pr.commits_url
$commits = Invoke-GHRestMethod -Method GET -Uri $prCommitsUrl.AbsolutePath

#for each commit add the sha to the list
$prCommitShaList = @()
foreach ($commit in $commits)
{
        #     ex commit:
        #     sha          : d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d
        # node_id      : C_kwDOHy75StoAKGQ1YTIyOTlkZDczMDdhNzljYTZiOGIzZmJmNWNmMTkyZTYyYTY4M2Q
        # commit       : @{author=; committer=; message=Update test.txt; tree=; url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/commits/d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d; 
        #                comment_count=0; verification=}
        # url          : https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/commits/d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d
        # html_url     : https://github.com/octodemo/demo-vulnerabilities-ghas/commit/d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d
        # comments_url : https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/commits/d5a2299dd7307a79ca6b8b3fbf5cf192e62a683d/comments
        # author       : @{login=rafskov; id=25858030; node_id=MDQ6VXNlcjI1ODU4MDMw; avatar_url=https://avatars.githubusercontent.com/u/25858030?v=4; gravatar_id=; 
        #                url=https://api.github.com/users/rafskov; html_url=https://github.com/rafskov; followers_url=https://api.github.com/users/rafskov/followers; 
        #                following_url=https://api.github.com/users/rafskov/following{/other_user}; gists_url=https://api.github.com/users/rafskov/gists{/gist_id}; 
        #                starred_url=https://api.github.com/users/rafskov/starred{/owner}{/repo}; subscriptions_url=https://api.github.com/users/rafskov/subscriptions; 
        #                organizations_url=https://api.github.com/users/rafskov/orgs; repos_url=https://api.github.com/users/rafskov/repos; 
        #                events_url=https://api.github.com/users/rafskov/events{/privacy}; received_events_url=https://api.github.com/users/rafskov/received_events; type=User; site_admin=True}
        # committer    : @{login=web-flow; id=19864447; node_id=MDQ6VXNlcjE5ODY0NDQ3; avatar_url=https://avatars.githubusercontent.com/u/19864447?v=4; gravatar_id=; 
        #                url=https://api.github.com/users/web-flow; html_url=https://github.com/web-flow; followers_url=https://api.github.com/users/web-flow/followers; 
        #                following_url=https://api.github.com/users/web-flow/following{/other_user}; gists_url=https://api.github.com/users/web-flow/gists{/gist_id}; 
        #                starred_url=https://api.github.com/users/web-flow/starred{/owner}{/repo}; subscriptions_url=https://api.github.com/users/web-flow/subscriptions; 
        #                organizations_url=https://api.github.com/users/web-flow/orgs; repos_url=https://api.github.com/users/web-flow/repos; 
        #                events_url=https://api.github.com/users/web-flow/events{/privacy}; received_events_url=https://api.github.com/users/web-flow/received_events; type=User; site_admin=False}
        # parents      : {@{sha=8d8882455c5c1c61f23f2f024cbbf3b32564efbf; url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/commits/8d8882455c5c1c61f23f2f024cbbf3b32564efbf; 
        #                html_url=https://github.com/octodemo/demo-vulnerabilities-ghas/commit/8d8882455c5c1c61f23f2f024cbbf3b32564efbf}}
    $prCommitShaList += $commit.sha
}

Write-Host "PR Commit SHA list: $prCommitShaList"

####@{id=256379056; node_id=MDEwOlJlcG9zaXRvcnkyNTYzNzkwNTY=; name=demo-vulnerabilities-ghas; full_name=octodemo/demo-vulnerabilities-ghas; private=True; owner=; html_url=https://github.com/octodemo/demo-vulnerabilities-ghas; description=This repo contains examples of all security feature available for GitHub Enterprise and GHAS. Use it for demo purposes only.; fork=False; url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas; forks_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/forks; keys_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/keys{/key_id}; collaborators_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/collaborators{/collaborator}; teams_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/teams; hooks_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/hooks; issue_events_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/events{/number}; events_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/events; assignees_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/assignees{/user}; branches_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/branches{/branch}; tags_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/tags; blobs_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/blobs{/sha}; git_tags_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/tags{/sha}; git_refs_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/refs{/sha}; trees_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/trees{/sha}; statuses_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/statuses/{sha}; languages_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/languages; stargazers_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/stargazers; contributors_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/contributors; subscribers_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/subscribers; subscription_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/subscription; commits_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/commits{/sha}; git_commits_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/commits{/sha}; comments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/comments{/number}; issue_comment_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues/comments{/number}; contents_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/contents/{+path}; compare_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/compare/{base}...{head}; merges_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/merges; archive_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/{archive_format}{/ref}; downloads_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/downloads; issues_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/issues{/number}; pulls_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/pulls{/number}; milestones_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/milestones{/number}; notifications_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/notifications{?since,all,participating}; labels_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/labels{/name}; releases_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/releases{/id}; deployments_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/deployments; created_at=04/17/2020 02:17:12; updated_at=05/17/2022 21:03:00; pushed_at=08/10/2022 19:47:32; git_url=git://github.com/octodemo/demo-vulnerabilities-ghas.git; ssh_url=org-38940897@github.com:octodemo/demo-vulnerabilities-ghas.git; clone_url=https://github.com/octodemo/demo-vulnerabilities-ghas.git; svn_url=https://github.com/octodemo/demo-vulnerabilities-ghas; homepage=; size=24244; stargazers_count=8; watchers_count=8; language=JavaScript; has_issues=True; has_projects=True; has_downloads=True; has_wiki=True; has_pages=False; forks_count=8; mirror_url=; archived=False; disabled=False; open_issues_count=71; license=; allow_forking=True; is_template=False; web_commit_signoff_required=False; topics=System.Object[]; visibility=internal; forks=8; open_issues=71; watchers=8; default_branch=main; permissions=; temp_clone_token=AANNZW2QMTIDF37VXPAAASLC6YJFM; allow_squash_merge=True; allow_merge_commit=True; allow_rebase_merge=True; allow_auto_merge=False; delete_branch_on_merge=False; allow_update_branch=False; use_squash_pr_title_as_default=False; squash_merge_commit_message=COMMIT_MESSAGES; squash_merge_commit_title=COMMIT_OR_PR_TITLE; merge_commit_message=PR_TITLE; merge_commit_title=MERGE_MESSAGE; organization=; security_and_analysis=; network_count=8; subscribers_count=0}
####$repo = Get-GitHubRepository -OwnerName $OrganizationName -RepositoryName $RepositoryName

#Query all secret scanning alerts for the repository
$repoAlertsUrl = "/repos/$OrganizationName/$RepositoryName/secret-scanning/alerts"
$alerts = Invoke-GHRestMethod -Method GET -Uri $repoAlertsUrl

#for each secret scanning alert, find the initial location of the secret and theh list
$alertCount = 0
$alertsInitiatedFromPr = @()
foreach ($alert in $alerts) {
    $repoAlertLocationUrl = [uri]$alert.locations_url

    #Secret Scanning List Locations API - https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
    # - RESPONSE: 1 "location" object per file where secret detected
    #    - details.commit_sha - SHA of the commit where the secret was detected
    $locations = Invoke-GHRestMethod -Method GET -Uri $repoAlertLocationUrl.AbsolutePath
    $locationMatches = @()
    foreach ($location in $locations) {
        #@{path=secrets.yml; start_line=1; end_line=1; start_column=11; end_column=32; blob_sha=d233fb964b86e09d4a99bba85c6006dcc4c9258f; blob_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/blobs/d233fb964b86e09d4a99bba85c6006dcc4c9258f; commit_sha=44d3503204f61baffcad1f2293ab9dd41db4820a; commit_url=https://api.github.com/repos/octodemo/demo-vulnerabilities-ghas/git/commits/44d3503204f61baffcad1f2293ab9dd41db4820a}
        $alertInitialCommitSha = $location.details.commit_sha

        #if alertInitialCommitSha in list of commit shas, then add alert to list of alerts to delete
        if ($alertInitialCommitSha -in $prCommitShaList) {
            Write-Verbose "YES! Found a secret scanning alert (# $($alert.number)) initial commit sha: $alertInitialCommitSha that originated from a PR#$PullRequestNumber commit"
            $locationMatches += $location
        }
        else {
            Write-Verbose "NO! Did not find a secret scanning alert (# $($alert.number)) initial commit sha: $alertInitialCommitSha that originated from a PR#$PullRequestNumber commit"
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

#output the alert url for each alert that was found
foreach ($alert in $alertsInitiatedFromPr) {
    foreach($location in $alert.locations) {
        Write-Host "[+] Alert: $($alert.html_url) at Path: '$($location.details.path)' (commit sha: $($location.details.commit_sha))"
        # TODO - no support for ?Title? .. send PR to maintainer!
        Write-ActionWarning -Message "[+] Alert: $($alert.html_url) (commit sha: $($location.details.commit_sha))" -File $location.details.path -Line $location.details.start_line -Col $location.details.start_column
    }  
}

#if any alerts were found in ErrorOnAlert mode, exit with error code 1
if($alertsInitiatedFromPr.Count -gt 0 -and $ErrorOnAlert) {
    Set-ActionFailed -Message "Found $($alertsInitiatedFromPr.count) secret scanning alert(s) that originated from a PR#$PullRequestNumber commit"
}
else {
    exit 0
}