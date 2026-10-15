# This script is intended to be a Python equivalent of action.ps1

import os
import logging
import requests
import argparse
import re
import sys
import json
import subprocess
from datetime import datetime, timezone

# List of supported generic secret types as per:
# https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns
# Includes non-provider patterns and copilot patterns
GENERIC_SECRET_TYPES = "password,ec_private_key,generic_private_key,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_url,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"

# GITHUB_API_URL is provided by the runner and points to the correct API host for the
# current GitHub instance (github.com, ghe.com data-residency tenants, or GHES).
# Fall back to public github.com for local/manual runs outside a workflow.
API_BASE_URL = os.environ.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')


class EvaluationError(Exception):
    """Raised when a GitHub API call needed for a complete review fails.

    The caller decides (via the fail-closed setting) whether the error fails the workflow
    or is reported as a warning. status_code is the HTTP status code, when available.
    """
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _status_code(err, response=None):
    """Return the HTTP status code for a failed request, or None if not available."""
    err_response = getattr(err, 'response', None)
    if err_response is not None:
        return err_response.status_code
    if response is not None:
        return getattr(response, 'status_code', None)
    return None


def escape_command_data(value):
    """Escape a workflow command message (the text after '::')."""
    return str(value).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def escape_command_property(value):
    """Escape a workflow command property value (for example file=, line=, col=)."""
    return escape_command_data(value).replace(':', '%3A').replace(',', '%2C')


def handle_evaluation_error(error, fail_closed, warnings):
    """Handle an EvaluationError according to the fail-closed setting.

    fail_closed: emit an ::error:: workflow command and exit with code 1.
    Otherwise: emit a ::warning:: workflow command, record the message in warnings, and return.
    """
    message = str(error)
    if fail_closed:
        print(f"::error::{escape_command_data(message)}")
        sys.exit(1)
    print(f"::warning::{escape_command_data(message + ' (fail-closed is disabled, continuing)')}")
    warnings.append(message)


def get_evaluation_warning_markdown(warnings):
    """Build the markdown section listing errors that were reported as warnings (fail-closed disabled)."""
    if not warnings:
        return ''
    markdown = "\n> [!WARNING]\n> The secret scanning review could not be fully completed. `fail-closed` is disabled, so these errors did not fail the workflow:\n"
    for warning in warnings:
        single_line = re.sub(r'\r?\n', ' ', warning).strip()
        markdown += f"> - {single_line}\n"
    return markdown


def complete_incomplete_review(pull_request_number, pull_request, warnings, disable_workflow_summary):
    """Write an "incomplete review" step summary and empty step output, then exit with code 0.

    Only used when fail-closed is disabled and a required lookup (pull request, commits, or alerts) failed.
    """
    html_url = pull_request.get('html_url') if pull_request else None
    pr_link = f"[PR#{pull_request_number}]({html_url})" if html_url else f"PR#{pull_request_number}"
    incomplete_summary = f"⚠️ Secret scanning review for PR#{pull_request_number} could not be completed"
    github_step_summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if disable_workflow_summary:
        print(f"Skipping workflow summary - disable-workflow-summary is set to {disable_workflow_summary}")
    elif github_step_summary:
        with open(github_step_summary, 'w') as summary_file:
            summary_file.write(
                f"# :unlock: {pr_link} SECRET SCANNING REVIEW SUMMARY :unlock: \n {incomplete_summary} \n"
                f"{get_evaluation_warning_markdown(warnings)}"
            )
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write("alerts=[]\n")
    print(f"::warning::{escape_command_data(incomplete_summary)}")
    sys.exit(0)

def get_commits_for_pr(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls?apiVersion=2022-11-28#list-commits-on-a-pull-request
    # Note: this endpoint returns at most 250 commits. See get_commit_shas_for_pr for larger PRs.
    all_commits = []
    per_page = 100
    page = 1
    while True:
        response = None
        try:
            url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/pulls/{pull_request_number}/commits?per_page={per_page}&page={page}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            }
            proxies = { "http": http_proxy_url, "https": https_proxy_url }
            response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
            response.raise_for_status()
            commits = response.json()
            all_commits.extend(commits)

            # Check if there is a next page
            if 'Link' in response.headers:
                links = response.headers['Link']
                if 'rel="next"' not in links:
                    break
            else:
                break
            page += 1
        except Exception as err:
            status_code = _status_code(err, response)
            raise EvaluationError(
                f"Error getting '{repo_owner}/{repo_name}' PR#{pull_request_number} commits. "
                f"Ensure that the access token has at least read access to pull requests. (StatusCode:{status_code} Message:{err})",
                status_code
            ) from err
    return all_commits

def get_commits_for_compare(github_token, repo_owner, repo_name, base, head, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/commits/commits?apiVersion=2022-11-28#compare-two-commits
    # Unlike the pull request commits endpoint, this endpoint paginates past 250 commits.
    from urllib.parse import quote
    all_commits = []
    per_page = 100
    page = 1
    while True:
        response = None
        try:
            url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/compare/{quote(base, safe='')}...{quote(head, safe='')}?per_page={per_page}&page={page}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            }
            proxies = { "http": http_proxy_url, "https": https_proxy_url }
            response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
            response.raise_for_status()
            all_commits.extend(response.json().get('commits', []))

            # Check if there is a next page
            if 'Link' in response.headers:
                links = response.headers['Link']
                if 'rel="next"' not in links:
                    break
            else:
                break
            page += 1
        except Exception as err:
            status_code = _status_code(err, response)
            raise EvaluationError(
                f"Error comparing '{repo_owner}/{repo_name}' commits {base}...{head}. (StatusCode:{status_code} Message:{err})",
                status_code
            ) from err
    return all_commits

def get_commit_shas_for_pr(github_token, repo_owner, repo_name, pull_request, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl):
    """Return the commit SHAs for a pull request.

    The pull request commits endpoint returns at most 250 commits, so when the pull request reports
    more commits than were listed, the commits are re-read from the compare endpoint
    (base branch...head SHA). The caller should compare the result with pull_request['commits'].
    """
    commits = get_commits_for_pr(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl)
    commit_shas = [commit['sha'] for commit in commits if commit.get('sha')]
    expected_count = int(pull_request.get('commits') or 0)
    base_ref = (pull_request.get('base') or {}).get('ref')
    head_sha = (pull_request.get('head') or {}).get('sha')
    if len(commit_shas) < expected_count and base_ref and head_sha:
        logging.debug(f"PR#{pull_request_number} reports {expected_count} commits but only {len(commit_shas)} were listed. Reading commits from the compare endpoint.")
        compare_commits = get_commits_for_compare(github_token, repo_owner, repo_name, base_ref, head_sha, http_proxy_url, https_proxy_url, verify_ssl)
        compare_shas = [commit['sha'] for commit in compare_commits if commit.get('sha')]
        if len(compare_shas) > len(commit_shas):
            commit_shas = compare_shas
    return commit_shas

def get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts, secret_type=None):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository
    all_alerts = []
    per_page = 100
    page = 1
    while True:
        response = None
        try:
            url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/secret-scanning/alerts?per_page={per_page}&page={page}"
            if skip_closed_alerts:
                url += "&state=open"
            if secret_type is not None:
                url += f"&secret_type={secret_type}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            }
            proxies = { "http": http_proxy_url, "https": https_proxy_url }
            response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
            response.raise_for_status()
            alerts = response.json()
            all_alerts.extend(alerts)

            # Check if there is a next page
            if 'Link' in response.headers:
                links = response.headers['Link']
                if 'rel="next"' not in links:
                    break
            else:
                break
            page += 1
        except Exception as err:
            status_code = _status_code(err, response)
            if status_code == 404:
                hint = "Ensure that secret scanning is enabled for the repository and that the access token has at least read access to secret scanning alerts. "
            elif status_code == 503:
                hint = "Secret scanning service unavailable, please re-run the job to try again. "
            else:
                hint = ""
            raise EvaluationError(
                f"Error getting '{repo_owner}/{repo_name}' {'generic ' if secret_type else ''}secret scanning alerts. "
                f"{hint}(StatusCode:{status_code} Message:{err})",
                status_code
            ) from err
    return all_alerts

def get_locations_for_alert(github_token, repo_owner, repo_name, alert_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-locations-for-a-secret-scanning-alert
    all_locations = []
    per_page = 100
    page = 1
    while True:
        response = None
        try:
            url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/secret-scanning/alerts/{alert_number}/locations?per_page={per_page}&page={page}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            }
            proxies = { "http": http_proxy_url, "https": https_proxy_url }
            response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
            response.raise_for_status()
            locations = response.json()
            all_locations.extend(locations)        
            
            # Check if there is a next page
            if 'Link' in response.headers:
                links = response.headers['Link']
                if 'rel="next"' not in links:
                    break
            else:
                break
            page += 1
        except Exception as err:
            status_code = _status_code(err, response)
            raise EvaluationError(
                f"Error getting '{repo_owner}/{repo_name}' secret scanning alert #{alert_number} locations. "
                f"Ensure the access token has at least read access to secret scanning alerts. (StatusCode:{status_code} Message:{err})",
                status_code
            ) from err
    return all_locations

def get_dismissal_request_for_alert(github_token, repo_owner, repo_name, alert_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/alert-dismissal-requests#get-an-alert-dismissal-request-for-secret-scanning
    try:
        url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/dismissal-requests/secret-scanning/{alert_number}"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
        }
        proxies = { "http": http_proxy_url, "https": https_proxy_url }
        response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    except Exception as err:
        logging.debug("Unable to retrieve dismissal request for alert %s in %s/%s: %s", alert_number, repo_owner, repo_name, err)
        return None

def get_pull_request(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls?apiVersion=2022-11-28#get-a-pull-request
    response = None
    try:
        url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/pulls/{pull_request_number}"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
        }
        proxies = { "http": http_proxy_url, "https": https_proxy_url }
        response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    except Exception as err:
        status_code = _status_code(err, response)
        raise EvaluationError(
            f"Error getting '{repo_owner}/{repo_name}' PR#{pull_request_number} info. "
            f"Ensure that the access token has at least read access to pull requests. (StatusCode:{status_code} Message:{err})",
            status_code
        ) from err

def update_pull_request_comment(github_token, repo_owner, repo_name, pull_request_number, markdown_summary, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/issues/comments?apiVersion=2022-11-28#get-an-issue-comment    
    comments = []
    per_page = 100
    page = 1
    url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/issues/{pull_request_number}/comments?per_page={per_page}&page={page}"
    headers = {
        'Authorization': f'Bearer {github_token}',
        'Accept': 'application/vnd.github+json'
    }
    proxies = { "http": http_proxy_url, "https": https_proxy_url }
    response = None
    try:
        while True:
            response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
            response.raise_for_status()
            page_comments = response.json()
            comments.extend(page_comments)

            # Check if there are more pages
            if len(page_comments) < 100:
                break
            page += 1
            url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/issues/{pull_request_number}/comments?per_page={per_page}&page={page}"
    except Exception as e:
        status_code = _status_code(e, response)
        raise EvaluationError(f"Error reading comments from '{repo_owner}/{repo_name}' Pull Request#{pull_request_number}, skipping PR comment. Ensure GITHUB_TOKEN has `pull_requests:read` repo permissions. (StatusCode:{status_code} Message:{e})", status_code) from e
    pr_comment_watermark = "<!-- secret-scanning-review-pr-comment-watermark -->"
    existing_comment = next((comment for comment in comments if pr_comment_watermark in comment['body']), None)
    comment = {
        'body': f"{pr_comment_watermark}\n{markdown_summary}\n<!-- {datetime.now(timezone.utc).isoformat()} -->"
    }
    try:
        if existing_comment:
            comment_response = requests.patch(existing_comment['url'], headers=headers, json=comment, proxies=proxies, verify=verify_ssl)
        else:
            comment_response = requests.post(url, headers=headers, json=comment, proxies=proxies, verify=verify_ssl)
        comment_response.raise_for_status()
        print(f"Updated PR Comment: {comment_response.json()['html_url']}")
    except Exception as e:
        status_code = _status_code(e)
        raise EvaluationError(f"Error adding comment to '{repo_owner}/{repo_name}' Pull Request#{pull_request_number}. Ensure GITHUB_TOKEN has `pull_requests:write` repo permissions. (StatusCode:{status_code} Message:{e})", status_code) from e

# Convert string input parameters to boolean
# Reference: https://stackoverflow.com/questions/15008758/parsing-boolean-values-with-argparse/43357954#43357954
def str2bool(value):
        if isinstance(value, bool):
            return value
        if value.lower() in ('true', '1'):
            return True
        elif value.lower() in ('false', '0'):
            return False
        else:
            raise ValueError(f"Invalid boolean value: {value}")

def get_pull_request_comments(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/issues/comments?apiVersion=2022-11-28#list-issue-comments
    comments = []
    per_page = 100
    page = 1
    url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/issues/{pull_request_number}/comments?per_page={per_page}&page={page}"
    headers = {
        'Authorization': f'Bearer {github_token}',
        'Accept': 'application/vnd.github+json'
    }
    proxies = { "http": http_proxy_url, "https": https_proxy_url }
    response = None
    try:
        while True:
            response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
            response.raise_for_status()
            page_comments = response.json()
            comments.extend(page_comments)

            # Check if there are more pages
            if len(page_comments) < 100:
                break
            page += 1
            url = f"{API_BASE_URL}/repos/{repo_owner}/{repo_name}/issues/{pull_request_number}/comments?per_page={per_page}&page={page}"
        return comments
    except Exception as err:
        status_code = _status_code(err, response)
        hint = "Pull request has been deleted. " if status_code == 410 else "Ensure that the access token has at least read access to pull requests. "
        raise EvaluationError(
            f"Error reading comments from '{repo_owner}/{repo_name}' PR#{pull_request_number}. "
            f"{hint}(StatusCode:{status_code} Message:{err})",
            status_code
        ) from err

def _validate_api_url(url):
    """Validate that a URL points to the expected GitHub API host to prevent SSRF token exfiltration."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    expected = urlparse(API_BASE_URL)
    if parsed.scheme != 'https':
        raise ValueError(f"Refusing to send credentials to non-HTTPS URL: {url}")
    if parsed.hostname != expected.hostname:
        raise ValueError(f"URL host '{parsed.hostname}' does not match expected API host '{expected.hostname}'")

def get_pull_request_review_comment(github_token, pr_review_comment_url, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/comments?apiVersion=2022-11-28#get-a-review-comment-for-a-pull-request
    # Errors (including 404 for pending or deleted review comments) are raised as EvaluationError.
    try:
        _validate_api_url(pr_review_comment_url)
    except ValueError as err:
        raise EvaluationError(f"Error reading review comment '{pr_review_comment_url}'. {err}") from err
    url = pr_review_comment_url
    headers = {
        'Authorization': f'Bearer {github_token}',
        'Accept': 'application/vnd.github+json'
    }
    proxies = { "http": http_proxy_url, "https": https_proxy_url }
    response = None
    try:
        response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    except Exception as err:
        status_code = _status_code(err, response)
        raise EvaluationError(
            f"Error reading review comment '{pr_review_comment_url}'. (StatusCode:{status_code} Message:{err})",
            status_code
        ) from err

def get_alert_location_type(alert_location):
    if 'type' not in alert_location:
        raise ValueError("Alert location does not have a 'type' field.")
    type = alert_location['type']
    if type == 'commit':
        return 'Commit SHA ' + alert_location['details']['commit_sha']
    elif type == 'pull_request_title':
        return 'Pull request title'
    elif type == 'pull_request_body':
        return 'Pull request body'
    elif type == 'pull_request_comment':
        return 'Pull request comment'
    elif type == 'pull_request_review':
        return 'Pull request review'
    elif type == 'pull_request_review_comment':
        return 'Pull request review comment'
    else:
        return None

def main(github_token, fail_on_alert, fail_on_alert_exclude_closed, disable_pr_comment, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts, disable_workflow_summary, fail_closed=True):
    # Check if GITHUB_TOKEN is set
    env_github_token = os.getenv('GITHUB_TOKEN', None)

    if github_token:
        logging.debug("GitHubToken parameter is SET.")
    else:
        logging.debug("GitHubToken parameter is NOT SET.")

    if env_github_token:
        github_token = env_github_token
        logging.debug("GitHubToken is now set from GITHUB_TOKEN environment variable.")
    else:
        logging.debug("GITHUB_TOKEN environment variable is not set.")

    if not github_token or github_token.isspace():
        raise ValueError("GitHubToken is not set.")
    
    # Get the repo owner and name:
    repo = os.getenv('GITHUB_REPOSITORY', None)
    if not repo:
        raise ValueError("GITHUB_REPOSITORY is not set.")
    repo_owner, repo_name = repo.split('/')
    logging.debug(f"repo_owner: {repo_owner}, repo_name: {repo_name}")

    # Get the pull request number from the GITHUB_REF environment variable
    pull_request_number = None
    github_ref = os.environ.get('GITHUB_REF', '')

    match = re.match(r'refs/pull/([0-9]+)', github_ref)
    if match:
        pull_request_number = match.group(1)
    else:
        raise Exception("Action workflow must be run on 'pull_request'. GITHUB_REF is not set to a pull request number")
    logging.debug(f"pull_request_number: {pull_request_number}")

    # Errors that were reported as warnings because fail-closed is disabled
    evaluation_warnings = []

    def fatal_error(err, pull_request=None):
        # A required lookup failed: fail the workflow (fail-closed) or end the review as incomplete
        handle_evaluation_error(err, fail_closed, evaluation_warnings)
        complete_incomplete_review(pull_request_number, pull_request, evaluation_warnings, disable_workflow_summary)

    # Get the pull request information:
    logging.debug("Getting the pull request information.")
    try:
        pull_request = get_pull_request(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl)
    except EvaluationError as err:
        fatal_error(err)

    # Get the commit SHAs for the PR (falls back to the compare endpoint for PRs with more than 250 commits):
    logging.debug("Getting the commits for the PR.")
    try:
        commit_shas = get_commit_shas_for_pr(github_token, repo_owner, repo_name, pull_request, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl)
    except EvaluationError as err:
        fatal_error(err, pull_request)
    logging.debug(f"Found {len(commit_shas)} commits.")
    expected_commit_count = int(pull_request.get('commits') or 0)
    if len(commit_shas) < expected_commit_count:
        handle_evaluation_error(
            EvaluationError(f"Only {len(commit_shas)} of {expected_commit_count} commits could be listed for '{repo_owner}/{repo_name}' PR#{pull_request_number}. Secrets in the remaining commits are not reviewed."),
            fail_closed, evaluation_warnings
        )

    # Get the secret scanning alerts for the repo:
    # Make two API calls: one for default provider-based patterns, and another for generic secrets
    logging.debug("Getting the secret scanning alerts for the repo (default provider-based patterns).")
    try:
        alerts = get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts)
    except EvaluationError as err:
        fatal_error(err, pull_request)
    logging.debug(f"Found {len(alerts)} default alerts.")
    
    # Get generic secrets (non-provider patterns and copilot patterns)
    logging.debug("Getting the secret scanning alerts for the repo (generic secret types).")
    try:
        generic_alerts = get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts, secret_type=GENERIC_SECRET_TYPES)
    except EvaluationError as err:
        handle_evaluation_error(EvaluationError(f"{err} Only default secret scanning alerts are reviewed.", err.status_code), fail_closed, evaluation_warnings)
        generic_alerts = []
    logging.debug(f"Found {len(generic_alerts)} generic alerts.")
    
    # Merge alerts and deduplicate by alert number
    alert_numbers_seen = {alert['number'] for alert in alerts}
    for alert in generic_alerts:
        if alert['number'] not in alert_numbers_seen:
            alerts.append(alert)
            alert_numbers_seen.add(alert['number'])
    
    logging.debug(f"Found {len(alerts)} total alerts after merging and deduplication.")

    # For each alert check if the alert's commit is in the list of PR commits
    logging.debug("Checking if any alert location commits are in the list of PR commits...")
    alerts_in_pr = []
    alerts_reviewed = 0
    alert_locations_by_number = {}
    pr_comments = None
    for alert in alerts:
        try:
            alert_locations = get_locations_for_alert(github_token, repo_owner, repo_name, alert['number'], http_proxy_url, https_proxy_url, verify_ssl)
        except EvaluationError as err:
            handle_evaluation_error(err, fail_closed, evaluation_warnings)
            alerts_reviewed += 1
            continue
        alert_locations_by_number[alert['number']] = alert_locations
        for location in alert_locations:
            if location['type'] == 'commit':
                if location['details']['commit_sha'] in commit_shas:
                    logging.debug(f"MATCH FOUND: Alert {alert['number']} is in a commit in the PR.")
                    alerts_in_pr.append(alert)
                    break
            elif location['type'] == 'pull_request_title':
                if location['details']['pull_request_title_url'] == pull_request['url']:
                    logging.debug(f"MATCH FOUND: Alert {alert['number']} is in the PR title.")
                    alerts_in_pr.append(alert)
                    break
            elif location['type'] == 'pull_request_body':
                if location['details']['pull_request_body_url'] == pull_request['url']:
                    logging.debug(f"MATCH FOUND: Alert {alert['number']} is in the PR body.")
                    alerts_in_pr.append(alert)
                    break
            elif location['type'] == 'pull_request_comment':
                if pr_comments is None:
                    try:
                        pr_comments = get_pull_request_comments(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl)
                    except EvaluationError as err:
                        pr_comments = []
                        handle_evaluation_error(EvaluationError(f"{err} Secrets in PR comments are not reviewed.", err.status_code), fail_closed, evaluation_warnings)
                comment_id = location['details']['pull_request_comment_url'].split('/')[-1]
                for comment in pr_comments:
                    if str(comment['id']) == comment_id:
                        logging.debug(f"MATCH FOUND: Alert {alert['number']} is in a PR comment.")
                        alerts_in_pr.append(alert)
                        break
            elif location['type'] == 'pull_request_review':
                # remove '/reviews/1234567890' from the end of the pull_request_review_url to compare against the PR URL:
                shortened_pr_review_url = location['details']['pull_request_review_url'].rstrip('/').rsplit('/', 2)[0]
                if shortened_pr_review_url == pull_request['url']:
                    logging.debug(f"MATCH FOUND: Alert {alert['number']} is in a PR review.")
                    alerts_in_pr.append(alert)
                    break
            elif location['type'] == 'pull_request_review_comment':
                # Look up the review comment to confirm it belongs to this PR (via pull_request_url).
                # Pending review comments are not accessible via the API (404) but are still detected by
                # secret scanning, and the comment may also have been deleted after detection.
                # A 404 is counted as a match when fail-closed is enabled, and skipped with a warning otherwise.
                pr_review_comment_url = location['details'].get('pull_request_review_comment_url')
                if not pr_review_comment_url:
                    continue
                try:
                    pr_review_comment = get_pull_request_review_comment(github_token, pr_review_comment_url, http_proxy_url, https_proxy_url, verify_ssl)
                except EvaluationError as err:
                    if err.status_code == 404:
                        if fail_closed:
                            logging.info(f"Alert {alert['number']} review comment '{pr_review_comment_url}' is not accessible (pending or deleted). Counting it as a match because fail-closed is enabled.")
                            alerts_in_pr.append(alert)
                            break
                        warning_message = f"Alert {alert['number']} review comment '{pr_review_comment_url}' is not accessible (pending or deleted) and could not be verified for PR#{pull_request_number}."
                        print(f"::warning::{escape_command_data(warning_message + ' (fail-closed is disabled, continuing)')}")
                        evaluation_warnings.append(warning_message)
                    else:
                        handle_evaluation_error(err, fail_closed, evaluation_warnings)
                    continue
                if pr_review_comment.get('pull_request_url') == pull_request['url']:
                    logging.debug(f"MATCH FOUND: Alert {alert['number']} is in a PR review comment.")
                    alerts_in_pr.append(alert)
                    break

        # Increment the counter and log the progress
        alerts_reviewed += 1
        logging.info(f"Reviewed {alerts_reviewed} out of {len(alerts)} alerts.")

    # Build output for each alert that was found
    num_secrets_alerts_detected = 0
    num_secrets_alert_locations_detected = 0
    should_fail_action = False
    markdown_summary_table_rows = ''
    dismissal_statuses = {}

    for alert in alerts_in_pr:
        num_secrets_alerts_detected += 1

        # Fetch dismissal request for this alert (may return None if feature is not enabled or no request exists)
        dismissal_request = get_dismissal_request_for_alert(github_token, repo_owner, repo_name, alert['number'], http_proxy_url, https_proxy_url, verify_ssl)
        dismissal_status = dismissal_request.get('status') if dismissal_request else None
        dismissal_statuses[alert['number']] = dismissal_status

        # Check if alert has dismissal-related fields but the dismissal API returned nothing (likely missing contents:read permission on FGP)
        has_dismissal_fields = (
            alert.get('closure_request_comment') is not None
            or alert.get('closure_request_reviewer_comment') is not None
            or alert.get('closure_request_reviewer') is not None
        )

        # Format state with dismissal request status as hover tooltip on "dismissal" text
        state_value = alert['state']
        if dismissal_status:
            state_value = f'{alert["state"]} ([dismissal](# "Dismissal request: {dismissal_status}"))'
        elif has_dismissal_fields and not dismissal_status:
            state_value = f'{alert["state"]} (dismissal)'
            logging.warning(f"Alert #{alert['number']} has a dismissal request but the dismissal request status could not be retrieved. Ensure your token has 'contents: read' permission for dismissal request details.")

        # Reuse the locations fetched while matching the alert to the PR
        alert_locations = alert_locations_by_number.get(alert['number'], [])
        for location in alert_locations:
            num_secrets_alert_locations_detected += 1
            alert_type = location['type']
            alert_location = get_alert_location_type(location)
            message = (
                f"A {'Closed as ' + alert['resolution'] if alert['state'] == 'resolved' else 'New'} Secret Detected in "
                f"Pull Request #{pull_request_number}. "
                f"'{alert['secret_type_display_name']}' Secret: {alert['html_url']} Location: {alert_location}"
            )
            if alert_type == 'commit':
                annotation_properties = (
                    f"file={escape_command_property(location['details']['path'])},"
                    f"line={escape_command_property(location['details']['start_line'])},"
                    f"col={escape_command_property(location['details']['start_column'])}"
                )
            should_bypass = (alert['state'] == 'resolved') and fail_on_alert_exclude_closed
            if fail_on_alert and not should_bypass:
                if alert_type == 'commit':
                    print(f"::error {annotation_properties}::{escape_command_data(message)}")
                should_fail_action = True
                pass_fail = "[🔴](# 'Error')"
            else:
                if alert_type == 'commit':
                    print(f"::warning {annotation_properties}::{escape_command_data(message)}")
                pass_fail = "[🟡](# 'Warning')"

            if alert_type == 'commit':
                commit_sha = location['details']['commit_sha'][:7]
                location_value = f"Commit [{commit_sha}]({pull_request['html_url']}/commits/{location['details']['commit_sha']})"
            else:
                location_value = alert_location
            
            # Format validity with checked date as hover tooltip
            validity_value = alert.get('validity')
            if validity_value is None:
                validity_value = '❌'
            if alert.get('validity_checked_at'):
                validity_value = f'[{validity_value}](# "{alert["validity_checked_at"]}")'
            
            markdown_summary_table_rows += (
                f"| {pass_fail} | :key: [{alert['number']}]({alert['html_url']}) | {alert['secret_type_display_name']} | "
                f"{state_value} | {'❌' if alert['resolution'] is None else alert['resolution']} | "
                f"{alert['push_protection_bypassed']} | {validity_value} | {location_value} |\n"
            )

    # One line summary of alerts found
    summary = (
        f"{'🚨' if num_secrets_alerts_detected > 0 else '👍'} Found [{num_secrets_alerts_detected}] secret scanning alert"
        f"{'' if num_secrets_alerts_detected == 1 else 's'} across [{num_secrets_alert_locations_detected}] location"
        f"{'' if num_secrets_alert_locations_detected == 1 else 's'} that originated from PR#{pull_request_number}"
    )

    markdown_summary = (
        f"# :unlock: [PR#{pull_request_number}]({pull_request['html_url']}) SECRET SCANNING REVIEW SUMMARY :unlock: \n {summary} \n"
    )

    # Build a markdown table of any alerts
    if len(alerts_in_pr) > 0:
        markdown_summary += (
            "| Status 🚦 | Secret Alert 🚨 | Secret Type 𝌎 | State :question: | Resolution :checkered_flag: | Push Bypass 👋 | Validity :white_check_mark: | Location #️⃣ |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
        )
        markdown_summary += markdown_summary_table_rows
    
    # PR Comment Summary only if not disabled and alerts were found
    if not disable_pr_comment and len(alerts_in_pr) > 0:
        try:
            update_pull_request_comment(github_token, repo_owner, repo_name, pull_request_number, markdown_summary + get_evaluation_warning_markdown(evaluation_warnings), http_proxy_url, https_proxy_url, verify_ssl)
        except EvaluationError as err:
            handle_evaluation_error(err, fail_closed, evaluation_warnings)
    else:
        print(f"Skipping PR comment update - disable-pr-comment is set to {disable_pr_comment} and alert count in PR is {len(alerts_in_pr)}")

    # Include any errors that were reported as warnings (fail-closed disabled)
    markdown_summary += get_evaluation_warning_markdown(evaluation_warnings)
    
    if disable_workflow_summary:
        print(f"Skipping workflow summary - disable-workflow-summary is set to {disable_workflow_summary}")
    else:
        # Output Step Summary - To the GITHUB_STEP_SUMMARY environment file. GITHUB_STEP_SUMMARY is unique for each step in a job
        github_step_summary = os.environ.get('GITHUB_STEP_SUMMARY')
        
        if github_step_summary:
            with open(github_step_summary, 'w') as summary_file:
                summary_file.write(markdown_summary)
            
            # Log the path of the GITHUB_STEP_SUMMARY file
            print(f"Markdown Summary from env var GITHUB_STEP_SUMMARY: '{github_step_summary}'")
            
            # Read and log the content of the GITHUB_STEP_SUMMARY file
            with open(github_step_summary, 'r') as summary_file:
                content = summary_file.read()
                print(content)
        else:
            print("GITHUB_STEP_SUMMARY environment variable is not set.")

    # Create step output JSON with alert number, URL, push protection bypass boolean, and push protection bypass actor
    step_output = []
    for alert in alerts_in_pr:
        step_output.append({
            "number": alert["number"],
            "secret_type": alert["secret_type"],
            "push_protection_bypassed": alert["push_protection_bypassed"],
            "push_protection_bypassed_by": alert["push_protection_bypassed_by"],
            "state": alert["state"],
            "resolution": alert["resolution"],
            "validity": alert.get("validity"),
            "validity_checked_at": alert.get("validity_checked_at"),
            "html_url": alert["html_url"],
            "dismissal_request_status": dismissal_statuses.get(alert["number"])
        })

    # convert step_output to valid JSON:
    step_output_json = json.dumps(step_output)
    
    if "GITHUB_OUTPUT" in os.environ :
        with open(os.environ["GITHUB_OUTPUT"], "a") as f :
            f.write(f"alerts={step_output_json}\n")

    # Output Message Summary and set exit code
    # - any error alerts were found in FailOnAlert mode (observing FailOnAlertExcludeClosed), exit with error code 1
    # - otherwise, return 0
    if len(alerts_in_pr) > 0 and should_fail_action:
        # Log an error message and set the action as failed
        print(f"::error::{escape_command_data(summary)}")
        exit(1)
    else:
        # Log an informational message
        print(f"::notice::{escape_command_data(summary)}")
        exit(0)


if __name__ == "__main__":
    
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description="Process input parameters.")
    parser.add_argument("--GitHubToken", type=str, required=False, default=None, help="GitHub Token (prefer GITHUB_TOKEN env var)")
    parser.add_argument("--FailOnAlert", type=str2bool, required=True, help="Fail on alert")
    parser.add_argument("--FailOnAlertExcludeClosed", type=str2bool, required=True, help="Fail on alert exclude closed")
    parser.add_argument("--DisablePRComment", type=str2bool, required=True, help="Disable PR comment")
    parser.add_argument("--ProxyURLHTTP", type=str, required=False, help="HTTP Proxy URL")
    parser.add_argument("--ProxyURLHTTPS", type=str, required=False, help="HTTPS Proxy URL")
    parser.add_argument("--VerifySSL", type=str2bool, required=False, help="Verify SSL")
    parser.add_argument("--SkipClosedAlerts", type=str2bool, required=False, help="Skip closed alerts")
    parser.add_argument("--DisableWorkflowSummary", type=str2bool, required=False, help="Disable workflow summary")
    parser.add_argument("--FailClosed", type=str2bool, required=False, default=True, help="Fail the workflow when a GitHub API error prevents a complete review (default: true). When false, errors are reported as warnings.")

    args = parser.parse_args()

    # Normalize proxy URLs: treat '""' (legacy default) and empty strings as None
    proxy_http = args.ProxyURLHTTP if args.ProxyURLHTTP and args.ProxyURLHTTP.strip('"') else None
    proxy_https = args.ProxyURLHTTPS if args.ProxyURLHTTPS and args.ProxyURLHTTPS.strip('"') else None

    main(args.GitHubToken, args.FailOnAlert, args.FailOnAlertExcludeClosed, args.DisablePRComment, proxy_http, proxy_https, args.VerifySSL, args.SkipClosedAlerts, args.DisableWorkflowSummary, args.FailClosed)
