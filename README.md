# Secret Scanning Review Action

![GitHub](https://img.shields.io/badge/github-%23121011.svg?logo=github&logoColor=white)
![GitHub Issues](https://img.shields.io/github/issues/advanced-security/secret-scanning-review-action)
![GitHub Issues](https://img.shields.io/github/issues-pr/advanced-security/secret-scanning-review-action)
![GitHub Issues](https://img.shields.io/github/issues-pr-closed/advanced-security/secret-scanning-review-action)
![GitHub Stars](https://img.shields.io/github/stars/advanced-security/secret-scanning-review-action)
![GitHub forks](https://img.shields.io/github/forks/advanced-security/secret-scanning-review-action)

[![Latest](https://img.shields.io/github/release/advanced-security/secret-scanning-review-action.svg)](https://github.com/advanced-security/secret-scanning-review-action/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/advanced-security/secret-scanning-review-action/badge)](https://scorecard.dev/viewer/?uri=github.com/advanced-security/secret-scanning-review-action)
![GitHub License](https://img.shields.io/github/license/advanced-security/secret-scanning-review-action)

[![GitHub.com](https://img.shields.io/badge/Supported%20on-GitHub.com-0969da)](https://github.com)
[![GHEC with data residency](https://img.shields.io/badge/Supported%20on-GitHub%20Enterprise%20Cloud%20with%20data%20residency-0969da)](https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency)
[![GHES](https://img.shields.io/badge/Supported%20on-GitHub%20Enterprise%20Server-0969da)](https://docs.github.com/en/enterprise-server@latest)

> [!IMPORTANT]
> 🚨 September 9, 2026: [GitHub changelog entry](https://github.blog/changelog/2026-09-09-block-pull-requests-with-exposed-secrets-from-merging/)
>
> You can use repository rulesets to block pull requests from merging when the pull request introduces secret scanning alerts. Developers without bypass permissions must clear the block by resolving each alert.
> The rule checks two things before a pull request can merge:
>
> - A secret scan has completed for the head commit
> - No alerts are open for secrets introduced by the pull request's commits

## Overview

This Action adds more awareness, and optionally fails a pull request status check, when a secret scanning alert is introduced in commits, pull request title, description, comments, reviews, or review comments as part of a pull request. This makes it harder for peer reviewers to miss the alert and makes it easier to enforce that the alert is resolved before the pull request is merged (when combined with [repository rulesets](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)).

This Action is also helpful in increasing visibility for secrets that are detected with secret scanning, but are not yet [supported with push protection](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/secret-scanning-patterns#supported-secrets-for-push-protection), or where push protection has been bypassed.

## Prerequisites

1. For private and internal repositories, you must enable [GitHub Advanced Security](https://docs.github.com/en/enterprise-cloud@latest/get-started/learning-about-github/about-github-advanced-security).

2. A GitHub access token with the required permissions. See [Token Requirements](#token-requirements).

The action works on github.com, [GitHub Enterprise Cloud with data residency](https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency) (`*.ghe.com`), and GitHub Enterprise Server. The API endpoint is read from the runner-provided `GITHUB_API_URL` environment variable, so no additional configuration is required.

## Functionality

### Commit annotations

The Action adds a `Warning` annotation to any file in the pull request that has introduced a secret (based on the secret scanning alert's initial commit):
![Warning annotation on a file in the pull request](https://user-images.githubusercontent.com/1760475/184815609-58dd4f31-dc08-445a-a692-3b5d4dacbaae.png)

With [`fail-on-alert: true`](#inputs), the annotations are `Errors`:
![Error annotation on a file in the pull request](https://user-images.githubusercontent.com/1760475/185046387-576fb75b-8a68-4640-94bc-9966f1f3b721.png)

The workflow's status check then fails, which provides a "trust, but verify" approach to secret scanning:
![Failed status check on the pull request](https://user-images.githubusercontent.com/1760475/185046465-1924d71c-3e73-4269-94b9-e5bc283410f4.png)

### Pull request job summary

The workflow run summary lists each secret introduced in the pull request with its status (🟡 warning or 🔴 error), alert, secret type, state, resolution, push protection bypass, validity (`active`, `inactive`, or `unknown`), and location (commit, pull request title or body, comment, review, or review comment). Hover over the state to see the status of a [dismissal request](https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/alert-dismissal-requests), and over the validity to see when it was checked.

![Workflow summary of the secrets introduced in the pull request](https://github.com/user-attachments/assets/102b44ce-6f8d-4aa7-a57d-364673c25dc7)

### Pull request comments

By default, when any secrets are found, the Action also adds the summary as a comment to the pull request:
![Summary comment on the pull request](https://github.com/user-attachments/assets/6b08949d-8d60-425e-99a2-ee30bd6735ce)

The Action keeps a single comment and updates it on later runs, so it stops listing secrets that are no longer part of the pull request (for example, after the commit that introduced a secret was removed). It never adds a comment to a pull request where no secrets were found, and when no secrets were found but the review could not be completed (`fail-closed: false`, see [Handling API errors](#handling-api-errors)), it leaves a comment from an earlier run unchanged.

## Security Model Considerations

- This Action surfaces secret scanning alerts to anyone with `Read` access to the repository, the same access needed to see the raw secrets already committed to its history.

- By default, only users with the repository `Admin` role, users with the organization `Security manager` role, organization owners, _and the committer of the secret_ can dismiss the alert. To give broader access, use a [custom repository role](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-peoples-access-to-your-organization-with-roles/about-custom-repository-roles#security) that grants `View secret scanning results` or `Dismiss or reopen secret scanning results`.

## Configuration Options

### Inputs

| Input | Required | Description | Default |
| ----- | -------- | ----------- | ------- |
| `token` | **Yes** | GitHub access token with the required permissions. See [Token Requirements](#token-requirements). | - |
| `fail-on-alert` | No | Fail the workflow, with error annotations, if a matching secret scanning alert is found. | `false` |
| `fail-on-alert-exclude-closed` | No | With `fail-on-alert`, report alerts that are closed (state: `resolved`) as warnings instead of failing. | `false` |
| `fail-closed` | No | Fail the workflow when a GitHub API error, or a [merge queue](#does-this-action-support-merge-queues) that does not require each pull request to pass its own required checks, prevents a complete review. When `false`, these are reported as warnings. See [Handling API errors](#handling-api-errors). | `true` |
| `skip-closed-alerts` | No | Only review open alerts. | `false` |
| `disable-pr-comment` | No | Disable the PR comment. | `false` |
| `disable-workflow-summary` | No | Disable the workflow summary. | `false` |
| `runtime` | No | `powershell` or `python`. See [the runtime FAQ](#why-are-there-two-runtime-options-and-whats-the-difference). | `powershell` |
| `python-http-proxy-url` | No | HTTP proxy URL for the `python` runtime. Example: `http://proxy.example.com:1234` | - |
| `python-https-proxy-url` | No | HTTPS proxy URL for the `python` runtime. Example: `http://proxy.example.com:5678` | - |
| `python-verify-ssl` | No | SSL verification for the `python` runtime. ⚠️ Disabling it is NOT recommended. | `true` |

> [!NOTE]
> v3 removed the deprecated `python-skip-closed-alerts` and `python-disable-workflow-summary` inputs. Use `skip-closed-alerts` and `disable-workflow-summary` instead.

### Outputs

| Output   | Description |
|----------|-------------|
| `alerts` | JSON array with details about the alerts detected in the PR. See [Step Output of Alert Metadata](#step-output-of-alert-metadata). |

### Handling API errors

Both runtimes handle GitHub API errors the same way, controlled by `fail-closed`:

- **`fail-closed: true` (default)**: any API error that prevents a complete review fails the workflow, so an incomplete review never reports success. Use this when the action is a required status check.
- **`fail-closed: false`**: API errors are reported as warnings and listed in the workflow summary (and in the PR comment, when one is posted), and the review continues with the data that could be read. `fail-on-alert` still applies to the alerts that were found. If the pull request, its commits, or the secret scanning alerts cannot be read, the review ends early as incomplete, with an empty `alerts` output (`[]`) and no PR comment.

On `merge_group` events, a merge queue that does not require each pull request to pass its own required checks is handled the same way (see [merge queues](#does-this-action-support-merge-queues)). Configuration errors (a missing token, or an event other than `pull_request` or `merge_group`) always fail the workflow, and [dismissal request](https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/alert-dismissal-requests) lookups never do.

Secrets in pull request comments and review comments are matched by the pull request number in the alert location's `html_url`, without an API call, so a deleted comment (or a pending review comment) is still matched to the pull request it was posted on. When `html_url` is missing or not in the expected format (for example, on older GitHub Enterprise Server versions), the comment is looked up instead: a deleted pull request comment is then not matched, and a review comment that is not accessible (404) is counted as a match with `fail-closed: true`, and skipped with a warning with `fail-closed: false`.

### Token Requirements

The built-in [`GITHUB_TOKEN`](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token) cannot read secret scanning alerts, whatever the workflow's `permissions`. Create a token (PAT or GitHub App) with the permissions below, store it as a secret, and pass it to the `token` input (see [Granting additional permissions](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#granting-additional-permissions)).

**Classic tokens:** the `repo` scope, or `public_repo` and `security_events` for public repositories. The `security_events` scope also enables the dismissal request status.

**Fine-grained tokens and GitHub Apps** (repository permissions):

- [Secret scanning alerts](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-secret-scanning-alerts): **Read**
- [Pull requests](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-pull-requests): **Write**, or **Read** with `disable-pr-comment: true` (then not required for public repositories)
- [Contents](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-contents): **Read** (recommended). Needed for the dismissal request status, and to review pull requests with more than 250 commits, which are read from the [compare](https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#compare-two-commits) endpoint. Without it, those pull requests fail the review, or are reported as incomplete with `fail-closed: false`.

On `merge_group` events, the merge queue settings are read without additional permissions (see [merge queues](#does-this-action-support-merge-queues)).

> [!IMPORTANT]
> The workflow's `permissions` block only applies to the built-in `GITHUB_TOKEN`. If the action fails with permission errors, check the permissions of the token itself.

<!-- -->

> [!WARNING]
> This token can read the plain text of the secrets detected in the repository. Anyone with read access to the repository can also see a committed secret, so treat any detected secret as compromised.

## Example usage

Add a workflow to your `.github/workflows` folder:

```yml
name: 'Secret Scanning Review'
on: [pull_request, merge_group]

jobs:
  secret-scanning-review:
    runs-on: ubuntu-latest
    steps:
      - name: 'Secret Scanning Review Action'
        uses: advanced-security/secret-scanning-review-action@c8ac1ef693ea7d6c5f9367e82d0367dc78a12717 # v2.2.8
        with:
          token: ${{ secrets.SECRET_SCAN_REVIEW_GITHUB_TOKEN }}
          fail-on-alert: true
          fail-on-alert-exclude-closed: true
          runtime: 'powershell' # or 'python'
```

### Step Output of Alert Metadata

The `alerts` step output is a JSON array with the metadata of each alert detected in the PR, for further processing in later steps. It does NOT include secret values.

```yaml
[...]
- name: 'Secret Scanning Review Action'
  uses: advanced-security/secret-scanning-review-action@c8ac1ef693ea7d6c5f9367e82d0367dc78a12717 # v2.2.8
  id: secret-alert-check
  with:
    token: ${{ steps.app-token.outputs.token }}
    runtime: 'python'

- name: 'Log alert URLs'
  if: always()
  env:
    ALERTS: ${{ steps.secret-alert-check.outputs.alerts }}
  run: echo "$ALERTS" | jq -r '.[].html_url'
```

Each alert has the following fields:

- `number`: The ID of the alert
- `secret_type`: The type of secret detected
- `push_protection_bypassed`: Whether the alert was introduced in a commit that bypassed push protection
- `push_protection_bypassed_by`: The user who bypassed push protection (shortened in the example below)
- `state`: The state of the alert
- `resolution`: The resolution of the alert
- `validity`: The validity status of the secret (`active`, `inactive`, `unknown`, or null if not yet checked)
- `validity_checked_at`: The timestamp when the validity was last checked (may be null)
- `html_url`: The URL to the alert in the GitHub UI
- `dismissal_request_status`: The status of any dismissal request for the alert (e.g., `pending`, `approved`, `denied`, `expired`, `completed`, `cancelled`, or null if no request exists)

For example, when two different secrets were introduced in a PR:

```json
[
    {
        "number": 68,
        "secret_type": "hardcoded_password",
        "push_protection_bypassed": false,
        "push_protection_bypassed_by": null,
        "state": "open",
        "resolution": null,
        "validity": "active",
        "validity_checked_at": "2024-01-15T10:30:00Z",
        "html_url": "https://github.com/callmegreg-demo-org/ss-demo-repo/security/secret-scanning/68",
        "dismissal_request_status": null
    },
    {
        "number": 67,
        "secret_type": "hardcoded_password",
        "push_protection_bypassed": true,
        "push_protection_bypassed_by": {
            "login": "CallMeGreg",
            "id": 110078080,
            "html_url": "https://github.com/CallMeGreg",
            "type": "User"
        },
        "state": "resolved",
        "resolution": "false_positive",
        "validity": "inactive",
        "validity_checked_at": "2024-01-14T09:15:00Z",
        "html_url": "https://github.com/callmegreg-demo-org/ss-demo-repo/security/secret-scanning/67",
        "dismissal_request_status": "denied"
    }
]
```

## How it works

The Action is a [composite action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) that runs [`action.ps1`](action.ps1) (`powershell` runtime) or [`action.py`](action.py) (`python` runtime):

1. Reads the pull request number from `GITHUB_REF`: `refs/pull/:prNumber/merge`, or `refs/heads/gh-readonly-queue/:baseBranch/pr-:prNumber-:sha` on `merge_group` events, which also check the [merge queue settings](#does-this-action-support-merge-queues) of the base branch.
2. Reads the pull request and its commits, and lists the repository's secret scanning alerts (provider patterns, then generic patterns).
3. Lists the locations of each alert, and keeps the alerts with a location in the pull request: one of its commits, its title or body, or a comment, review, or review comment on it.
4. Writes an annotation for each commit location, the workflow summary, the PR comment, and the `alerts` output, then fails the workflow if `fail-on-alert` applies.

It reads the runner-provided `GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_API_URL`, `GITHUB_GRAPHQL_URL`, and `GITHUB_SERVER_URL` environment variables, and writes to `GITHUB_STEP_SUMMARY` and `GITHUB_OUTPUT`. It calls these GitHub APIs:

- REST
  - [Pulls](https://docs.github.com/en/rest/pulls?apiVersion=2022-11-28): get the pull request, list its commits, and get a review or review comment
  - [Compare two commits](https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28#compare-two-commits): pull requests with more than 250 commits
  - [Secret scanning](https://docs.github.com/en/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28): list the alerts and their locations, and get [alert dismissal requests](https://docs.github.com/en/rest/secret-scanning/alert-dismissal-requests)
  - [Issue comments](https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28): get a comment, and list, create, and update the PR comment
  - [Rules for a branch](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28#get-rules-for-a-branch): `merge_group` events
- GraphQL: [`repository.mergeQueue`](https://docs.github.com/en/graphql/reference/objects#repository): `merge_group` events, for a merge queue required by a branch protection rule

Dependencies:

- `powershell` runtime: [PowerShellForGitHub](https://github.com/microsoft/PowerShellForGitHub) (with telemetry disabled) and [GitHubActions](https://github.com/ebekker/pwsh-github-action-tools). They are vendored in [`modules/`](modules) at the versions pinned in [`requirements.psd1`](requirements.psd1), so nothing is downloaded from the PowerShell Gallery at runtime. See [CONTRIBUTING.md](CONTRIBUTING.md#updating-powershell-module-dependencies).
- `python` runtime: [`requests`](https://pypi.org/project/requests/), installed with `pip` from the hash-pinned [`requirements.txt`](requirements.txt) on each run.

## FAQ

### Does this action support merge queues?

Yes. Add the [`merge_group`](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#merge_group) event to your workflow's `on:` triggers (see [Example usage](#example-usage)). A [merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue) tests a merge group with the base branch and every pull request ahead in the queue, but the merge group ref only names the last pull request, so that is the one the action reviews. Its commits are read from the pull request, so the merge queue's merge commit does not affect the review.

The pull requests ahead of it are only covered when the merge queue requires each pull request to pass its own required checks: **Require all queue entries to pass required checks** in a ruleset, or **Only merge non-failing pull requests** in a branch protection rule (grouping strategy `ALLGREEN`). When it is off (`HEADGREEN`), a merge group merges all of its pull requests when the checks for the last one pass, so a pull request whose own merge group failed (for example, because this action found a secret) can merge together with a later pull request that passes.

> [!IMPORTANT]
> When this action is a required check in a merge queue, keep that setting turned on.

Before the review, both runtimes read the setting for the base branch:

| Setting | Result |
| ------- | ------ |
| On (`ALLGREEN`) | The pull request is reviewed as usual. |
| Off (`HEADGREEN`) | With `fail-closed: true` (default), the workflow fails with an error that explains how to turn the setting on. With `fail-closed: false`, a warning is reported and the review ends as incomplete. |
| Cannot be read with the token | A notice is written and the pull request is reviewed as usual. |
| Error reading the setting | Handled like other [API errors](#handling-api-errors). |

The setting is read without additional token permissions. For a ruleset, it is the `grouping_strategy` of the `merge_queue` rule returned by the [get rules for a branch](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28#get-rules-for-a-branch) endpoint, which only needs the [`Metadata`](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-metadata) permission that every token has. When several rulesets require a merge queue for the branch, the setting is off if any of them turns it off. For a branch protection rule, it is the `mergingStrategy` of [`repository.mergeQueue`](https://docs.github.com/en/graphql/reference/objects#repository) in the GraphQL API, which GitHub only returns when the token can read the merge queue settings (for example, a classic token of a user with write access to the repository).

### Why are there two runtime options and what's the difference?

Both runtimes review pull requests the same way. The `powershell` runtime is the default and the most tested, and it only needs `pwsh` on the runner, because its modules ship with the action. The `python` runtime is for self-hosted runners without PowerShell, and adds options for enterprise networks:

- **Proxy support**: `python-http-proxy-url` and `python-https-proxy-url`
- **SSL verification control**: `python-verify-ssl` (for testing environments only)

In the summary, the `powershell` runtime links every alert location, while the `python` runtime only links commits.
