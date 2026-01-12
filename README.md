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

This Action adds more awareness, and optionally fails a pull request status check, when a secret scanning alert is introduced in commits, pull request title, description, comments, reviews, or review comments as part of a pull request. This makes it harder for peer reviewers to miss the alert and makes it easier to enforce that the alert is resolved before the pull request is merged (when combined with [repository rulesets](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)).

This Action is also helpful in increasing visibility for secrets that are detected with secret scanning, but are not yet [supported with push protection](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets-for-push-protection), or where push protection has been bypassed.

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

### Step Output of Alert Metadata

The Action provides a summary of the secrets introduced in the pull request as a step output variable, `alerts`. You can access this step output in subsequent steps in your workflow for any further processing that you would like to perform.

> [!NOTE]
> The `alerts` step output does NOT include secret values.

An example of how to access this step output in your Actions workflow is shown below:

```yaml
[...]
- name: 'Secret Scanning Review Action'
  uses: advanced-security/secret-scanning-review-action@v2
  id: secret-alert-check
  with:
    token: ${{ steps.app-token.outputs.token }}
    runtime: 'python'

- name: 'Log alert metadata'
  if: always()
  run: |
    echo ${{ steps.secret-alert-check.outputs.alerts }}
```

The `alerts` variable is set to a JSON array with the following fields for each alert detected in the PR:
- `number`: The ID of the alert
- `secret_type`: The type of secret detected
- `push_protection_bypassed`: Whether the alert was introduced in a commit that bypassed push protection
- `push_protection_bypassed_by`: The user who bypassed push protection
- `state`: The state of the alert
- `resolution`: The resolution of the alert
- `html_url`: The URL to the alert in the GitHub UI

An example of the `alerts` step output variable is shown below, where two different secrets were introduced in a PR:
```json
[
    {
        "number": 68,
        "secret_type": "hardcoded_password",
        "push_protection_bypassed": false,
        "push_protection_bypassed_by": null,
        "state": "open",
        "resolution": null,
        "html_url": "https://github.com/callmegreg-demo-org/ss-demo-repo/security/secret-scanning/68"
    },
    {
        "number": 67,
        "secret_type": "hardcoded_password",
        "push_protection_bypassed": true,
        "push_protection_bypassed_by": {
            "login": "CallMeGreg",
            "id": 110078080,
            "node_id": "U_kgDOBo-ogA",
            "avatar_url": "https://avatars.githubusercontent.com/u/110078080?v=4",
            "gravatar_id": "",
            "url": "https://api.github.com/users/CallMeGreg",
            "html_url": "https://github.com/CallMeGreg",
            "followers_url": "https://api.github.com/users/CallMeGreg/followers",
            "following_url": "https://api.github.com/users/CallMeGreg/following{/other_user}",
            "gists_url": "https://api.github.com/users/CallMeGreg/gists{/gist_id}",
            "starred_url": "https://api.github.com/users/CallMeGreg/starred{/owner}{/repo}",
            "subscriptions_url": "https://api.github.com/users/CallMeGreg/subscriptions",
            "organizations_url": "https://api.github.com/users/CallMeGreg/orgs",
            "repos_url": "https://api.github.com/users/CallMeGreg/repos",
            "events_url": "https://api.github.com/users/CallMeGreg/events{/privacy}",
            "received_events_url": "https://api.github.com/users/CallMeGreg/received_events",
            "type": "User",
            "user_view_type": "public",
            "site_admin": true
        },
        "state": "resolved",
        "resolution": "false_positive",
        "html_url": "https://github.com/callmegreg-demo-org/ss-demo-repo/security/secret-scanning/67"
    }
]
```

## Security Model Considerations
* To be clear, this Action will surface secret scanning alerts to anyone with `Read` access to a repository. This level of visibility is consistent with the access needed to see any raw secrets already commited to the repository's commit history.

* By default, only users with the repository `Admin` role, users with the organization `Security manager` role, organization owners, _and the committer of the secret_, will be able to dismiss the alert.

* If you do wish to give broader access to secret scanning alerts in the repository you might consider a [custom repository role configuration](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-peoples-access-to-your-organization-with-roles/about-custom-repository-roles#security). With a custom role you can choose to grant `View secret scanning results` or `Dismiss or reopen secret scanning results` on top of any of the base repository roles.

## Configuration Options

### Inputs

| Input | Required | Description | Default |
|-------|----------|-------------|---------|
| `token` | **Yes** | GitHub Access Token with required permissions. See [token requirements](#token-requirements) below. | - |
| `fail-on-alert` | No | Fail the action workflow via non-zero exit code if a matching secret scanning alert is found. | `false` |
| `fail-on-alert-exclude-closed` | No | Handle failure exit code / annotations as warnings if the alert is found and marked as closed (state: 'resolved'). | `false` |
| `disable-pr-comment` | No | Disable the PR comment feature. | `false` |
| `runtime` | No | Runtime to use for the action. Options: `powershell` or `python`. | `powershell` |
| `skip-closed-alerts` | No | Only process open alerts. | `false` |
| `disable-workflow-summary` | No | Disable the workflow summary markdown table output. | `false` |
| `python-http-proxy-url` | No | HTTP proxy URL for the python runtime. Example: `http://proxy.example.com:1234` | `""` |
| `python-https-proxy-url` | No | HTTPS proxy URL for the python runtime. Example: `http://proxy.example.com:5678` | `""` |
| `python-verify-ssl` | No | Enable/disable SSL verification for the python runtime. ⚠️ Disabling is NOT recommended for production. | `true` |
| `python-skip-closed-alerts` | No | **DEPRECATED** - Use `skip-closed-alerts` instead. | `false` |
| `python-disable-workflow-summary` | No | **DEPRECATED** - Use `disable-workflow-summary` instead. | `false` |

### Outputs

| Output | Description |
|--------|-------------|
| `alerts` | JSON array containing details about the alerts detected in the PR. See [Step Output of Alert Metadata](#step-output-of-alert-metadata) for the JSON schema and example usage. |

### Token Requirements

The `token` input requires a GitHub Access Token with the following permissions:

**Classic Tokens:**
- `repo` scope
- For public repositories: `public_repo` + `security_events` scopes

**Fine-grained Personal Access Tokens:**
- **Read-Only**: [Secret Scanning Alerts](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-secret-scanning-alerts)
- **Write**: [Pull requests](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-pull-requests)
  - If `disable-pr-comment: true`, only **Read-Only** [Pull requests](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-pull-requests) is required (not required for public repositories)

> [!NOTE]
> The built-in Actions [GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token) cannot be used due to missing permissions on the `secret-scanning` API. You must generate a token (PAT or GitHub App) with the required permissions, add it as a secret in your repository, and assign the secret to the workflow parameter. See: [Granting additional permissions](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#granting-additional-permissions)

> [!WARNING]
> This token will have `sensitive` data access to return a list of plain text secrets detected in your organization/repository. A detected secret implies anyone with read repository access would have the same level of access to the leaked secret, which should be considered compromised.

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
        uses: advanced-security/secret-scanning-review-action@v2
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
* Python Dependencies
    * `requests` module

## REST APIs
* Pulls
   * https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#get-a-pull-request
   * https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls#list-commits-on-a-pull-request
   * https://docs.github.com/en/rest/pulls/reviews?apiVersion=2022-11-28#list-reviews-for-a-pull-request
   * https://docs.github.com/en/rest/pulls/comments?apiVersion=2022-11-28#get-a-review-comment-for-a-pull-request
* Secret Scanning
   * https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository
   * https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-locations-for-a-secret-scanning-alert
* Comments
  * https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#get-an-issue-comment
  * https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#update-an-issue-comment
  * https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#create-an-issue-comment
  * https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28#list-issue-comments

## FAQ

### Why are there two runtime options and what's the difference?
The primary difference is the underlying language and the dependencies that are required to be installed on the runner.  The `powershell` runtime is the default and is the most tested.  The `python` runtime is a newer addition for those who may not have powershell installed on their self-hosted runners.

The `python` runtime includes some additional configuration options for enterprise environments:
- **Proxy support**: Configure HTTP/HTTPS proxy settings for on-premises or corporate network environments (`python-http-proxy-url` and `python-https-proxy-url`)
- **SSL verification control**: Disable SSL verification for testing environments (`python-verify-ssl`)
