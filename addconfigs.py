import csv
import requests
import json
import base64
import time
import argparse

GITHUB_API_URL = "https://api.github.com"
PRE_COMMIT_FILE_PATH = ".pre-commit-config.yaml"
GITLEAKS_FILE_PATH = ".github/workflows/gitleaks_secret_scan.yml"
INPUT_FILE = "repos_last_30_days.csv"
OUTPUT_FILE = "repos_last_30_days.csv"  # Overwrites the same file

PRE_COMMIT_CONTENT = """repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
"""

GITLEAKS_WORKFLOW_CONTENT = """name: Gitleaks - Scanning Secrets in PR
on:
  pull_request:
    types: [synchronize, opened]
    branches: [main, master]
jobs:
  scan:
    uses: Capillary/security-workflows/.github/workflows/gitLeaks_reusable_worflow.yml@main
    secrets:
      GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
"""

NEW_BRANCH = "add-gitleaks-config"
PR_TITLE = "Add Gitleaks configs"
PR_BODY = "Adding `.pre-commit-config.yaml` and Gitleaks secret scan workflow."
RETRY_LIMIT = 3
RETRY_DELAY = 2  # seconds


def safe_request(method, url, headers, **kwargs):
    for attempt in range(RETRY_LIMIT):
        try:
            response = requests.request(method, url, headers=headers, **kwargs)
            if response.status_code < 500:
                return response
            print(f"Retryable error {response.status_code}, retrying...")
        except Exception as e:
            print(f"Request failed: {e}, retrying...")
        time.sleep(RETRY_DELAY)
    raise Exception(f"Failed after {RETRY_LIMIT} retries: {url}")


def get_file_sha(repo, path, headers):
    url = f"{GITHUB_API_URL}/repos/{repo}/contents/{path}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()["sha"]
    return None


def get_branch_sha(repo, branch, headers):
    url = f"{GITHUB_API_URL}/repos/{repo}/git/ref/heads/{branch}"
    r = safe_request("GET", url, headers)
    return r.json()["object"]["sha"]


def create_branch(repo, from_sha, headers):
    url = f"{GITHUB_API_URL}/repos/{repo}/git/refs"
    data = {"ref": f"refs/heads/{NEW_BRANCH}", "sha": from_sha}
    safe_request("POST", url, headers, data=json.dumps(data))


def commit_file(repo, path, content, branch, headers):
    url = f"{GITHUB_API_URL}/repos/{repo}/contents/{path}"
    payload = {
        "message": "Add path",
        "content": base64.b64encode(content.encode()).decode(),
        "branch": branch
    }

    try:
        sha = get_file_sha(repo, path, headers)
        if sha:
            payload["sha"] = sha

        r = safe_request("PUT", url, headers, data=json.dumps(payload))

        if r.status_code not in [200, 201]:
            print(f"Failed to commit file. Status: {r.status_code}, Response: {r.text}")
            return False

        return True

    except Exception as e:
        print(f"Exception occurred during commit_file: {str(e)}")
        return False


def create_pull_request(repo, default_branch, headers):
    url = f"{GITHUB_API_URL}/repos/{repo}/pulls"
    data = {
        "title": PR_TITLE,
        "body": PR_BODY,
        "head": NEW_BRANCH,
        "base": default_branch,
    }
    r = safe_request("POST", url, headers, data=json.dumps(data))
    if r.status_code == 201:
        return r.json()["html_url"]
    return None


def process_repo(row, headers, org):
    repo = row["Repo Name"]
    repo_type = row["Repo_Type"]
    branch_protection = row["Branch Protection Enabled"].lower() == "true"
    default_branch = row["Default Branch Name"]

    # ✅ Column name updates
    pre_commit_present = row["Has .pre-commit-config.yaml"].lower() == "true"
    gitleaks_present = row["Has gitleaks_secret_scan.yml"].lower() == "true"

    full_repo = f"{org}/{repo}"

    result = {
        "pre_commit_added": "",
        "gitleaks_added": "",
        "pull_request_url": "",
        "status": "skipped"
    }

    try:
        if repo_type.lower() == "prod" and not pre_commit_present and not gitleaks_present:
            if not branch_protection:
                print(f"[{repo}] Direct committing...")
                pre_commit_success = commit_file(full_repo, PRE_COMMIT_FILE_PATH, PRE_COMMIT_CONTENT, default_branch, headers)
                gitleaks_success = commit_file(full_repo, GITLEAKS_FILE_PATH, GITLEAKS_WORKFLOW_CONTENT, default_branch, headers)

                if pre_commit_success:
                    result["pre_commit_added"] = "TRUE"
                if gitleaks_success:
                    result["gitleaks_added"] = "TRUE"
                if pre_commit_success and gitleaks_success:
                    result["status"] = "direct commit"
            else:
                print(f"[{repo}] Branch protection enabled. Creating PR.")
                sha = get_branch_sha(full_repo, default_branch, headers)
                create_branch(full_repo, sha, headers)
                commit_file(full_repo, PRE_COMMIT_FILE_PATH, PRE_COMMIT_CONTENT, NEW_BRANCH, headers)
                commit_file(full_repo, GITLEAKS_FILE_PATH, GITLEAKS_WORKFLOW_CONTENT, NEW_BRANCH, headers)
                pr_url = create_pull_request(full_repo, default_branch, headers)
                if pr_url:
                    result["pre_commit_added"] = "TRUE"
                    result["gitleaks_added"] = "TRUE"
                    result["pull_request_url"] = pr_url
                    result["status"] = "pull request"
    except Exception as e:
        print(f"[{repo}] Error: {e}")
        result["status"] = "error"

    return result


def main(github_token, org_name):
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    updated_rows = []

    with open(INPUT_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ["pre_commit_added", "gitleaks_added", "pull_request_url", "status"]
        for row in reader:
            result = process_repo(row, headers, org_name)
            row.update(result)
            updated_rows.append(row)

    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(updated_rows)

    print(f"✅ Updated results written to {OUTPUT_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Auto-configure GitHub repos.')
    parser.add_argument('-pat', '--github_token', required=True, help='GitHub Personal Access Token')
    parser.add_argument('-org', '--org_name', required=True, help='GitHub Organization Name')
    args = parser.parse_args()

    main(args.github_token, args.org_name)
