# This script is intended to be a Python equivalent of action.ps1

import os
import logging
import requests
import argparse
import re
import json
import subprocess
from datetime import datetime, timezone

# List of supported generic secret types as per:
# https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns
# Includes non-provider patterns and copilot patterns
GENERIC_SECRET_TYPES = "password,ec_private_key,generic_private_key,http_basic_authentication_header,http_bearer_authentication_header,mongodb_connection_string,mysql_connection_string,openssh_private_key,pgp_private_key,postgres_connection_string,rsa_private_key"

def get_commits_for_pr(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls?apiVersion=2022-11-28#list-commits-on-a-pull-request
    all_commits = []
    per_page = 100
    page = 1
    while True:
        try:
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pull_request_number}/commits?per_page={per_page}&page={page}"
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
        except requests.exceptions.HTTPError as err:
            if response.status_code != 200:
                print("Ensure that the access token has at least read access to pull requests.")
                exit(1)
        except Exception as err:
            print(f"An error occurred: {err}")
            exit(1)
    return all_commits

def get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts, secret_type=None):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository
    all_alerts = []
    per_page = 100
    page = 1
    while True:
        try:
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/secret-scanning/alerts?per_page={per_page}&page={page}"
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
        except requests.exceptions.HTTPError as err:
            if response.status_code == 404:
                print("Ensure that secret scanning is enabled for the repository and that the access token has at least read access to secret scanning alerts.")
                exit(1)
            elif response.status_code == 503:
                print("Secret scanning service unavailable, please re-run the job to try again.")
                exit(1)
            elif response.status_code != 200:
                print(f"HTTP error occurred: {err}")
                exit(1)
        except Exception as err:
            print(f"An error occurred: {err}")
            exit(1)
    return all_alerts

def get_locations_for_alert(github_token, repo_owner, repo_name, alert_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-locations-for-a-secret-scanning-alert
    all_locations = []
    per_page = 100
    page = 1
    while True:
        try:
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/secret-scanning/alerts/{alert_number}/locations?per_page={per_page}&page={page}"
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
        except requests.exceptions.HTTPError as err:
            if response.status_code == 404:
                print("Ensure that secret scanning is enabled for the repository and that the access token has at least read access to secret scanning alerts.")
                exit(1)
            elif response.status_code == 503:
                print("Service unavailable, please try again.")
                exit(1)
            elif response.status_code != 200:
                print(f"HTTP error occurred: {err}")
                exit(1)
        except Exception as err:
            print(f"An error occurred: {err}")
            exit(1)
    return all_locations

def get_pull_request(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls?apiVersion=2022-11-28#get-a-pull-request
    try:
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pull_request_number}"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
        }
        proxies = { "http": http_proxy_url, "https": https_proxy_url }
        response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        if response.status_code == 404:
            print("Ensure that the access token has at least read access to pull requests.")
            exit(1)
        elif response.status_code == 503:
            print("Pull request service unavailable, please re-run the job to try again.")
            exit(1)
        elif response.status_code != 200:
            print(f"HTTP error occurred: {err}")
            exit(1)
    except Exception as err:
        print(f"An error occurred: {err}")
        exit(1)

def update_pull_request_comment(github_token, repo_owner, repo_name, pull_request_number, markdown_summary, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/issues/comments?apiVersion=2022-11-28#get-an-issue-comment    
    comments = []
    per_page = 100
    page = 1
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pull_request_number}/comments?per_page={per_page}&page={page}"
    headers = {
        'Authorization': f'Bearer {github_token}',
        'Accept': 'application/vnd.github+json'
    }
    proxies = { "http": http_proxy_url, "https": https_proxy_url }
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
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error reading comment from '{repo_owner}/{repo_name}' Pull Request#{pull_request_number}. Ensure GITHUB_TOKEN has `pull_requests:read` repo permissions. (StatusCode:{e.response.status_code} Message:{e})")
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
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error adding comment to '{repo_owner}/{repo_name}' Pull Request#{pull_request_number}. Ensure GITHUB_TOKEN has `pull_requests:write` repo permissions. (StatusCode:{e.response.status_code} Message:{e})")

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
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pull_request_number}/comments?per_page={per_page}&page={page}"
    headers = {
        'Authorization': f'Bearer {github_token}',
        'Accept': 'application/vnd.github+json'
    }
    proxies = { "http": http_proxy_url, "https": https_proxy_url }
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
        return comments
    except requests.exceptions.HTTPError as err:
        if response.status_code == 404:
            print("Ensure that the access token has at least read access to pull requests.")
            exit(1)
        elif response.status_code == 410:
            print("Pull request has been deleted.")
            exit(1)
        elif response.status_code != 200:
            print(f"HTTP error occurred: {err}")
            exit(1)
    except Exception as err:
        print(f"An error occurred: {err}")
        exit(1)

def get_pull_request_review_comment(github_token, pr_review_comment_url, http_proxy_url, https_proxy_url, verify_ssl):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/comments?apiVersion=2022-11-28#get-a-review-comment-for-a-pull-request
    url = pr_review_comment_url
    headers = {
        'Authorization': f'Bearer {github_token}',
        'Accept': 'application/vnd.github+json'
    }
    proxies = { "http": http_proxy_url, "https": https_proxy_url }
    try:
        response = requests.get(url, headers=headers, proxies=proxies, verify=verify_ssl)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        if response.status_code == 404:
            print("Ensure that the access token has at least read access to pull requests.")
            exit(1)
        elif response.status_code != 200:
            print(f"HTTP error occurred: {err}")
            exit(1)
    except Exception as err:
        print(f"An error occurred: {err}")
        exit(1)

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

def main(github_token, fail_on_alert, fail_on_alert_exclude_closed, disable_pr_comment, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts, disable_workflow_summary):
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

    # Get the pull request information:
    logging.debug("Getting the pull request information.")
    pull_request = get_pull_request(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl)

    # Get the commits for the PR:
    logging.debug("Getting the commits for the PR.")
    commits = get_commits_for_pr(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl)
    logging.debug(f"Found {len(commits)} commits.")

    # For each PR commit add the commit sha to the list
    commit_shas = []
    for commit in commits:
        commit_shas.append(commit['sha'])

    # Get the secret scanning alerts for the repo:
    # Make two API calls: one for default provider-based patterns, and another for generic secrets
    logging.debug("Getting the secret scanning alerts for the repo (default provider-based patterns).")
    alerts = get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts)
    logging.debug(f"Found {len(alerts)} default alerts.")
    
    # Get generic secrets (non-provider patterns and copilot patterns)
    logging.debug("Getting the secret scanning alerts for the repo (generic secret types).")
    generic_alerts = get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name, http_proxy_url, https_proxy_url, verify_ssl, skip_closed_alerts, secret_type=GENERIC_SECRET_TYPES)
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
    for alert in alerts:
        alert_locations = get_locations_for_alert(github_token, repo_owner, repo_name, alert['number'], http_proxy_url, https_proxy_url, verify_ssl)
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
                pr_comments = get_pull_request_comments(github_token, repo_owner, repo_name, pull_request_number, http_proxy_url, https_proxy_url, verify_ssl)
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
                pr_review_comment_url = location['details']['pull_request_review_comment_url']
                pr_review_comment = get_pull_request_review_comment(github_token, pr_review_comment_url, http_proxy_url, https_proxy_url, verify_ssl)
                if pr_review_comment['pull_request_url'] == pull_request['url']:
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

    for alert in alerts_in_pr:
        num_secrets_alerts_detected += 1
        # Need to get locations for the alert
        alert_locations = get_locations_for_alert(github_token, repo_owner, repo_name, alert['number'], http_proxy_url, https_proxy_url, verify_ssl)
        for location in alert_locations:
            num_secrets_alert_locations_detected += 1
            alert_type = location['type']
            alert_location = get_alert_location_type(location)
            message = (
                f"A {'Closed as ' + alert['resolution'] if alert['state'] == 'resolved' else 'New'} Secret Detected in "
                f"Pull Request #{pull_request_number}. "
                f"'{alert['secret_type_display_name']}' Secret: {alert['html_url']} Location: {alert_location}"
            )
            should_bypass = (alert['state'] == 'resolved') and fail_on_alert_exclude_closed
            if fail_on_alert and not should_bypass:
                if alert_type == 'commit':
                    print(f"::error file={location['details']['path']},line={location['details']['start_line']},col={location['details']['start_column']}::{message}")
                should_fail_action = True
                pass_fail = "[🔴](# 'Error')"
            else:
                if alert_type == 'commit':
                    print(f"::warning file={location['details']['path']},line={location['details']['start_line']},col={location['details']['start_column']}::{message}")
                pass_fail = "[🟡](# 'Warning')"

            if alert_type == 'commit':
                commit_sha = location['details']['commit_sha'][:7]
                location_value = f"Commit [{commit_sha}]({pull_request['html_url']}/commits/{location['details']['commit_sha']})"
            else:
                location_value = alert_location
            
            markdown_summary_table_rows += (
                f"| {pass_fail} | :key: [{alert['number']}]({alert['html_url']}) | {alert['secret_type_display_name']} | "
                f"{alert['state']} | {'❌' if alert['resolution'] is None else alert['resolution']} | "
                f"{alert['push_protection_bypassed']} | {location_value} |\n"
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
            "| Status 🚦 | Secret Alert 🚨 | Secret Type 𝌎 | State :question: | Resolution :checkered_flag: | Push Bypass 👋 | Location #️⃣ |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
        )
        markdown_summary += markdown_summary_table_rows
    
    # PR Comment Summary only if not disabled and alerts were found
    if not disable_pr_comment and len(alerts_in_pr) > 0:
        update_pull_request_comment(github_token, repo_owner, repo_name, pull_request_number, markdown_summary, http_proxy_url, https_proxy_url, verify_ssl)
    else:
        print(f"Skipping PR comment update - disable-pr-comment is set to {disable_pr_comment} and alert count in PR is {len(alerts_in_pr)}")
    
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
            "html_url": alert["html_url"]
        })

    # convert step_output to valid JSON:
    step_output_json = json.dumps(step_output)
    
    if "GITHUB_OUTPUT" in os.environ :
        with open(os.environ["GITHUB_OUTPUT"], "a") as f :
            f.write(f"alerts={step_output_json}")

    # Output Message Summary and set exit code
    # - any error alerts were found in FailOnAlert mode (observing FailOnAlertExcludeClosed), exit with error code 1
    # - otherwise, return 0
    if len(alerts_in_pr) > 0 and should_fail_action:
        # Log an error message and set the action as failed
        print(f"::error::{summary}")
        exit(1)
    else:
        # Log an informational message
        print(f"::notice::{summary}")
        exit(0)


if __name__ == "__main__":
    
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description="Process input parameters.")
    parser.add_argument("--GitHubToken", type=str, required=True, help="GitHub Token")
    parser.add_argument("--FailOnAlert", type=str2bool, required=True, help="Fail on alert")
    parser.add_argument("--FailOnAlertExcludeClosed", type=str2bool, required=True, help="Fail on alert exclude closed")
    parser.add_argument("--DisablePRComment", type=str2bool, required=True, help="Disable PR comment")
    parser.add_argument("--ProxyURLHTTP", type=str, required=False, help="HTTP Proxy URL")
    parser.add_argument("--ProxyURLHTTPS", type=str, required=False, help="HTTPS Proxy URL")
    parser.add_argument("--VerifySSL", type=str2bool, required=False, help="Verify SSL")
    parser.add_argument("--SkipClosedAlerts", type=str2bool, required=False, help="Skip closed alerts")
    parser.add_argument("--DisableWorkflowSummary", type=str2bool, required=False, help="Disable workflow summary")

    args = parser.parse_args()
    main(args.GitHubToken, args.FailOnAlert, args.FailOnAlertExcludeClosed, args.DisablePRComment, args.ProxyURLHTTPS, args.ProxyURLHTTP, args.VerifySSL, args.SkipClosedAlerts, args.DisableWorkflowSummary)