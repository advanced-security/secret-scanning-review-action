![GitHub](https://img.shields.io/badge/github-%23121011.svg?logo=github&logoColor=white)
![GitHub Issues](https://img.shields.io/github/issues/advanced-security/secret-scanning-review-action)
![GitHub Issues](https://img.shields.io/github/issues-pr/advanced-security/secret-scanning-review-action)
![GitHub Issues](https://img.shields.io/github/issues-pr-closed/advanced-security/secret-scanning-review-action)
![GitHub Stars](https://img.shields.io/github/stars/advanced-security/secret-scanning-review-action)
![GitHub forks](https://img.shields.io/github/forks/advanced-security/secret-scanning-review-action)

[![Latest](https://img.shields.io/github/release/advanced-security/secret-scanning-review-action.svg)](https://github.com/advanced-security/secret-scanning-review-action/releases) 
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/advanced-security/secret-scanning-review-action/badge)](https://scorecard.dev/viewer/?uri=github.com/advanced-security/secret-scanning-review-action)
![GitHub License](https://img.shields.io/github/license/advanced-security/secret-scanning-review-action)

# Secret Scanning Review Action

## Overview

This Action adds more awareness, and optionally fails a pull request status check, when a secret scanning alert is introduced as part of a pull request. This makes it harder for peer reviewers to miss the alert and makes it easier to enforce that the alert is resolved before the pull request is merged (when combined with [repository rulesets](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)).

This Action is also helpful in increasing visibility for secrets that are detected with secret scanning, but are not yet [supported with push protection](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets-for-push-protection), or where push protection has been bypassed.

> [!NOTE]
> When running the Action with the `python` runtime, the Action will also provide a summary of the secrets introduced in the pull request title, description, comments, review, and review comments.

## Prerequisites

For private and internal repositories, you must enable [GitHub Advanced Security](https://docs.github.com/en/enterprise-cloud@latest/get-started/learning-about-github/about-github-advanced-security).

## Functionality

### Commit Annontations

The Action adds a `Warning` annotation to any file in the pull request that has introduced a secret (based on the secret scanning alert's initial commit):
<img width="854" alt="Secret Scanning Review Workflow File Annotation" src="https://user-images.githubusercontent.com/1760475/184815609-58dd4f31-dc08-445a-a692-3b5d4dacbaae.png">

Setting the workflow [FailOnAlert](#failonalert-environment-variable-ssr_fail_on_alert) configuration value to `true` will change those `Warnings` into `Errors`:
<img width="854" alt="Secret Scanning Review Workflow File Annotation" src="https://user-images.githubusercontent.com/1760475/185046387-576fb75b-8a68-4640-94bc-9966f1f3b721.png">

### Status Check Failure

By adding `Error` annotations, new secret alerts will fail the workflow's status check, which provides a "trust, but verify" approach to secret scanning:
<img width="854" alt="Secret Scanning Review Workflow Checks" src="https://user-images.githubusercontent.com/1760475/185046465-1924d71c-3e73-4269-94b9-e5bc283410f4.png">

### Pull Request Job Summary

The Action summarizes all secrets introduced in the pull request in the workflow run summary:
<img width="854" alt="Secret Scanning Review Workflow Checks" src="https://user-images.githubusercontent.com/1760475/204209697-7f13551b-5fea-4bc0-bb6e-f4757a82c946.png">

### Pull Request Comments

By default, when any secrets are found the Action will also add a comment to the pull request with a summary of the secrets introduced in the pull request:
<img width="854" alt="Secret Scanning Review Workflow Checks" src="https://github.com/advanced-security/secret-scanning-review-action/assets/1760475/5b743082-33d2-45d1-bef2-c0bb5d796932">

## Security Model Considerations
* To be clear, this Action will surface secret scanning alerts to anyone with `Read` access to a repository. This level of visibility is consistent with the access needed to see any raw secrets already commited to the repository's commit history.

* By default, only users with the repository `Admin` role, users with the organization `Security manager` role, organization owners, _and the committer of the secret_, will be able to dismiss the alert.

* If you do wish to give broader access to secret scanning alerts in the repository you might consider a [custom repository role configuration](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-peoples-access-to-your-organization-with-roles/about-custom-repository-roles#security). With a custom role you can choose to grant `View secret scanning results` or `Dismiss or reopen secret scanning results` on top of any of the base repository roles.

## Configuration Options

### `token`
**REQUIRED** A GitHub Access Token
   * Classic Tokens
      * `repo` scope. For public repositories, you may instead use the `public_repo` + `security_events` scopes.
   * Fine-grained personal access token permissions
      * Read-Only - [Secret Scanning Alerts](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-secret-scanning-alerts)
      * Write - [Pull requests](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-pull-requests).
        * (`disable-pr-comment: true`) Read-Only - [Pull requests](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-pull-requests). Not required for public repositories.

NOTE:
   * Unfortunately we cannot currently utilize the built in Actions [GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token) due to ommitted permissions on the `secret-scanning` API.  Therefore you must generate a token (PAT or GitHub App) with these permissions, add the token as a secret in your repository, and assign the secret to the workflow parameter. See Also: [Granting additional permissions](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#granting-additional-permissions)
   * It is worth noting this token will have `sensitive` data access to return a list of plain text secrets that have been detected in your organization/repository.  At this point, a detected secret also implies anyone with read repository access would provide the same level of access to the leaked secret and therefore should be considered compromised.

### `fail-on-alert`
**OPTIONAL** If provided, will fail the action workflow via non-zero exit code if a matching secret scanning alert is found. Default `'false'`.

### `fail-on-alert-exclude-closed`
**OPTIONAL** If provided, will handle failure exit code / annotations as warnings if the alert is found and the alert is marked as closed (state: 'resolved'). Default `'false'`.

### `disable-pr-comment`
**OPTIONAL** If provided, will not put a comment on the Pull Request with a summary of detected secrets. Default `'false'`.

### `runtime`
**OPTIONAL** If provided, will desingate the runtime that's used to run the action. Options are `'powershell'` or `'python'`. Default `'powershell'`.

### `python-http-proxy-url`
**OPTIONAL** If provided, will set the http proxy for the python runtime. Default `""`. Example: `"http://proxy.example.com:1234"`

### `python-https-proxy-url`
**OPTIONAL** If provided, will set the https proxy for the python runtime. Default `""`. Example: `"http://proxy.example.com:5678"`

### `python-verify-ssl`
**OPTIONAL** If provided, will set the ssl verification option for the python runtime. Default `'true'`.
> [!WARNING]
> Disabling SSL verification is NOT recommended for production environments. This option is provided for testing purposes only.

### `python-skip-closed-alerts`
**OPTIONAL** If provided, will only process open alerts. Default `'false'`.

## Example usage

> [!NOTE]
> Please keep in mind that you need a [GitHub Advanced Security](https://docs.github.com/en/enterprise-cloud@latest/get-started/learning-about-github/about-github-advanced-security) license if you're running this action on private repositories.

1. Add a new YAML workflow to your `.github/workflows` folder:

```yml
name: 'Secret Scanning Review'
on: [pull_request]

jobs:
  secret-scanning-review:
    runs-on: ubuntu-latest
    steps:
      - name: 'Secret Scanning Review Action'
        uses: advanced-security/secret-scanning-review-action@v1
        with:
          token: ${{ secrets.SECRET_SCAN_REVIEW_GITHUB_TOKEN }}
          fail-on-alert: true
          fail-on-alert-exclude-closed: true
          runtime: 'powershell' # or 'python'
```

## Architecture
* A GitHub [composite action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) wrapping a PowerShell script.

```mermaid
sequenceDiagram
    autonumber
    participant Repo as Repository
    participant PR as Pull Request
    participant Action as Action Workflow
    participant API_PR as pulls<br/><br/>REST API
    participant API_SECRET as secret-scanning<br/><br/> REST API

    Repo->>PR: Create/Update PR
    PR->>Action: invoke `pull_request` workflow
    Action->>API_PR: GET PR
    Action->>API_PR: GET PR Commits

    loop Commits
        Action->>Action: Build PR Commit SHA list
    end

    Action->>API_SECRET: GET Secret Scanning Alerts

    loop Secret Scanning Alerts
        Action->>API_SECRET: GET Secret Scanning Alert List Locations
        loop Secret Scanning Alert Locations
        Action->>Action:Build List of Alert Initial Location SHAs that are<br/>contained in the PR SHA List (Step 5)
        end
    end

    loop List of matching PR/Alerts
      loop List of Locations for matching PR/Alerts
        Action->>PR:Writes an Annotation to the message log<br/>associated with the file and line/col number.<br/>(Error/Warning based on FailOnAlert setting)
      end
    end

    Note right of PR: Annotations are visible<br/>on the PR Files changed rich diff

    Action->>PR:Writes summary to PR comment and log.<br/>Returns success/failure exit code based on FailOnAlert setting.

    Note right of PR: Fail workflow check<br/>based on FailOnAlert setting.
```

## Environment Variables
* Implicit
  * GITHUB_REPOSITORY - The owner / repository name.
  * GITHUB_REF - PR merge branch refs/pull/:prNumber/merge
* Outputs
  * GITHUB_STEP_SUMMARY - Markdown for each job so that it will be displayed on the summary page of a workflow run (unique for each step in a job)

## Dependencies
* GitHub Dependencies
    * GitHub [REST APIs](#rest-apis)
* Powershell Dependencies
    * `PowerShellForGitHub` ([Gallery](https://www.powershellgallery.com/packages/PowerShellForGitHub) / [Repo](https://github.com/Microsoft/PowerShellForGitHub)) - PowerShell wrapper for GitHub API
        * by [@microsoft](https://github.com/microsoft)
        * NOTE: [Telemetry is collected via Application Insights](https://github.com/microsoft/PowerShellForGitHub/blob/master/USAGE.md#telemetry)
    * `GitHubActions` ([Gallery](https://www.powershellgallery.com/packages/GitHubActions) / [Repo](https://github.com/ebekker/pwsh-github-action-tools)) - PowerShell wrapper of the Github `@actions/core` [toolkit](https://github.com/actions/toolkit/tree/master/packages/core)
        * by [@ebekker](https://github.com/ebekker/)

## REST APIs
* Pulls
   * https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#get-a-pull-request
   * https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#list-commits-on-a-pull-request
* Secret Scanning
   * https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
   * https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
* Comments
  * https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#get-an-issue-comment
  * https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#update-an-issue-comment
  * https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#create-an-issue-comment

## FAQ

### Why are there two runtime options and what's the difference?
The primary difference is the underlying language and the dependencies that are required to be installed on the runner.  The `powershell` runtime is the default and is the most tested.  The `python` runtime is a newer addition for those who may not have powershell installed on their self-hosted runners.

The `python` runtime also includes some additional configuration options that are not available in the `powershell` runtime, and looks beyond just the pull request commits for secrets that were introduced in the pull request title, description, comments, review, and review comments.
