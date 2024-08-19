# This script is intended to be a Python equivalent of action.ps1

import os
import logging
import requests
import argparse
import re

def get_commits_for_pr(github_token, repo_owner, repo_name, pull_request_number):
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
            response = requests.get(url, headers=headers)
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
                break
        except Exception as err:
            print(f"An error occurred: {err}")
            break
    return all_commits

def get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning/secret-scanning?apiVersion=2022-11-28#list-secret-scanning-alerts-for-a-repository
    all_alerts = []
    per_page = 100
    page = 1
    while True:
        try:
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/secret-scanning/alerts?per_page={per_page}&page={page}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            }
            response = requests.get(url, headers=headers)
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
                break
            elif response.status_code == 503:
                print("Service unavailable, please try again.")
                break
            else:
                print(f"HTTP error occurred: {err}")
                break
        except Exception as err:
            print(f"An error occurred: {err}")
            break
    return all_alerts

def get_locations_for_alert(github_token, repo_owner, repo_name, alert_number):
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
            response = requests.get(url, headers=headers)
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
                break
            elif response.status_code == 503:
                print("Service unavailable, please try again.")
                break
            else:
                print(f"HTTP error occurred: {err}")
                break
        except Exception as err:
            print(f"An error occurred: {err}")
            break
    return all_locations

def get_pull_request(github_token, repo_owner, repo_name, pull_request_number):
    # API documentation: https://docs.github.com/en/enterprise-cloud@latest/rest/pulls/pulls?apiVersion=2022-11-28#get-a-pull-request
    try:
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pull_request_number}"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        if response.status_code == 404:
            print("Ensure that the access token has at least read access to pull requests.")
        elif response.status_code == 503:
            print("Service unavailable, please try again.")
        else:
            print(f"HTTP error occurred: {err}")
    except Exception as err:
        print(f"An error occurred: {err}")

def main(github_token, fail_on_alert, fail_on_alert_exclude_closed, disable_pr_comment):
    # Check if GITHUB_TOKEN is set
    github_token = os.getenv('GitHubToken', None)
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
    pull_request = get_pull_request(github_token, repo_owner, repo_name, pull_request_number)

    # Get the commits for the PR:
    logging.debug("Getting the commits for the PR.")
    commits = get_commits_for_pr(github_token, repo_owner, repo_name, pull_request_number)
    logging.debug(f"Found {len(commits)} commits.")

    # For each PR commit add the commit sha to the list
    commit_shas = []
    for commit in commits:
        commit_shas.append(commit['sha'])

    # Get the secret scanning alerts for the repo:
    logging.debug("Getting the secret scanning alerts for the repo.")
    alerts = get_secret_scanning_alerts_for_repo(github_token, repo_owner, repo_name)
    logging.debug(f"Found {len(alerts)} alerts.")

    # For each alert check if the alert's commit is in the list of PR commits
    logging.debug("Checking if any alert location commits are in the list of PR commits...")
    alerts_in_pr = []
    alerts_reviewed = 0
    for alert in alerts:
        alert_locations = get_locations_for_alert(github_token, repo_owner, repo_name, alert['number'])
        for location in alert_locations:
            if location['type'] == 'commit':
                if location['details']['commit_sha'] in commit_shas:
                    logging.debug(f"MATCH FOUND: Alert {alert['number']} is in the PR.")
                    alerts_in_pr.append(alert)
                    break
        # Increment the counter and log the progress
        alerts_reviewed += 1
        logging.info(f"Reviewed {alerts_reviewed} out of {len(alerts)} alerts.")

    # Build output for each alert that was found
    num_secrets_alerts_detected = 0
    num_secrets_alert_locations_detected = 0
    should_fail_action = False
    markdown_summary_table_rows = None

    for alert in alerts_in_pr:
        num_secrets_alerts_detected += 1
        # Need to get locations for the alert
        alert_locations = get_locations_for_alert(github_token, repo_owner, repo_name, alert['number'])
        for location in alert_locations:
            num_secrets_alert_locations_detected += 1
            message = (
                f"A {'Closed as ' + alert['resolution'] if alert['state'] == 'resolved' else 'New'} Secret Detected in "
                f"Pull Request #{pull_request_number} Commit SHA:{location['details']['commit_sha'][:7]}. "
                f"'{alert['secret_type_display_name']}' Secret: {alert['html_url']} Commit: {pull_request['html_url']}/commits/{location['details']['commit_sha']}"
            )
            should_bypass = (alert['state'] == 'resolved') and fail_on_alert_exclude_closed
            if fail_on_alert and not should_bypass:
                print(f"::error file={location['details']['path']},line={location['details']['start_line']},col={location['details']['start_column']}::{message}")
                should_fail_action = True
                passFail = "[🔴](# 'Error')"
            else:
                print(f"::warning file={location['details']['path']},line={location['details']['start_line']},col={location['details']['start_column']}::{message}")
                passFail = "[🟡](# 'Warning')"

                # LEFT OFF ON action.ps1 LINE 275
                                       




if __name__ == "__main__":
    
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description="Process some parameters.")
    parser.add_argument("--GitHubToken", type=str, required=True, help="GitHub Token")
    parser.add_argument("--FailOnAlert", type=bool, required=True, help="Fail on alert")
    parser.add_argument("--FailOnAlertExcludeClosed", type=bool, required=True, help="Fail on alert exclude closed")
    parser.add_argument("--DisablePRComment", type=bool, required=True, help="Disable PR comment")

    args = parser.parse_args()
    main(args.GitHubToken, args.FailOnAlert, args.FailOnAlertExcludeClosed, args.DisablePRComment)