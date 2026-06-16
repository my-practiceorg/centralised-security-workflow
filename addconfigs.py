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
            response = requests.request(method, url, headers=headers, timeout=30, **kwargs)
            # Retry on 5xx; return otherwise
            if response.status_code < 500:
                return response
            print(f"[safe_request] Retryable error {response.status_code} for {url}, retrying...")
        except Exception as e:
            print(f"[safe_request] Request failed: {e}, retrying...")
        time.sleep(RETRY_DELAY)
    raise Exception(f"Failed after {RETRY_LIMIT} retries: {url}")


def get_file_sha(repo, path, headers, ref=None):
    """
    Return the file SHA if the file exists on the given ref (branch), else None.
    """
    url = f"{GITHUB_API_URL}/repos/{repo}/contents/{path}"
    params = {"ref": ref} if ref else None
    r = safe_request("GET", url, headers, params=params)
    if r.status_code == 200:
        return r.json().get("sha")
    elif r.status_code == 404:
        return None
    else:
        print(f"[get_file_sha] Unexpected status {r.status_code} for {repo}/{path}: {r.text}")
        return None


def get_branch_sha(repo, branch, headers):
    url = f"{GITHUB_API_URL}/repos/{repo}/git/ref/heads/{branch}"
    r = safe_request("GET", url, headers)
    if r.status_code == 200:
        return r.json()["object"]["sha"]
    raise Exception(f"[get_branch_sha] Cannot get SHA for {repo}@{branch}: {r.status_code} {r.text}")


def create_branch(repo, from_sha, headers):
    """
    Create NEW_BRANCH from from_sha. Safe if branch already exists (422).
    """
    url = f"{GITHUB_API_URL}/repos/{repo}/git/refs"
    data = {"ref": f"refs/heads/{NEW_BRANCH}", "sha": from_sha}
    r = safe_request("POST", url, headers, data=json.dumps(data))
    if r.status_code in (201,):  # created
        return True
    if r.status_code == 422:
        # Likely "Reference already exists"
        return True
    raise Exception(f"[create_branch] Failed to create branch for {repo}: {r.status_code} {r.text}")


def commit_file(repo, path, content, branch, headers):
    """
    Add or update a file on a given branch. Returns True on success.
    """
    url = f"{GITHUB_API_URL}/repos/{repo}/contents/{path}"
    payload = {
        "message": f"Add or update {path}",
        "content": base64.b64encode(content.encode()).decode(),
        "branch": branch
    }

    # If file exists on the target branch, add SHA to update it
    sha = get_file_sha(repo, path, headers, ref=branch)
    if sha:
        payload["sha"] = sha

    r = safe_request("PUT", url, headers, data=json.dumps(payload))
    if r.status_code in (200, 201):
        return True

    print(f"[commit_file] Failed to commit {path} to {repo}@{branch}. "
          f"Status: {r.status_code}, Response: {r.text}")
    return False


def find_existing_pr(repo, head_branch, base_branch, headers):
    """
    If an open PR exists from head->base, return its html_url, else None.
    """
    # GET /repos/{owner}/{repo}/pulls?state=open&head={owner}:{branch}&base={base}
    # head must include owner prefix: handled by caller
    url = f"{GITHUB_API_URL}/repos/{repo}/pulls"
    params = {"state": "open", "base": base_branch}
    r = safe_request("GET", url, headers, params=params)
    if r.status_code != 200:
        print(f"[find_existing_pr] Could not query PRs for {repo}: {r.status_code} {r.text}")
        return None
    for pr in r.json():
        # pr['head']['ref'] is branch name; pr['head']['repo']['full_name'] is owner/repo
        if pr.get("head", {}).get("ref") == head_branch:
            return pr.get("html_url")
    return None


def create_pull_request(repo, default_branch, headers):
    """
    Create a PR from NEW_BRANCH to default_branch. If a PR already exists, return its URL.
    """
    # Try reuse existing PR first
    existing = find_existing_pr(repo, NEW_BRANCH, default_branch, headers)
    if existing:
        return existing

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
    elif r.status_code == 422:
        # Validation failed — likely a PR already exists; try to find it
        existing = find_existing_pr(repo, NEW_BRANCH, default_branch, headers)
        if existing:
            return existing
    print(f"[create_pull_request] Failed to create PR for {repo}: {r.status_code} {r.text}")
    return None


def process_repo(row, headers, org):
    repo = row["Repo Name"]
    repo_type = row["Repo_Type"]
    branch_protection = row["Branch Protection Enabled"].lower() == "true"
    default_branch = row["Default Branch Name"]

    # CSV presence flags
    pre_commit_present_flag = row["Has .pre-commit-config.yaml"].lower() == "true"
    gitleaks_present_flag = row["Has gitleaks_secret_scan.yml"].lower() == "true"

    needs_pre_commit = not pre_commit_present_flag
    needs_gitleaks = not gitleaks_present_flag

    full_repo = f"{org}/{repo}"

    # Prepare result defaults
    result = {
        "pre_commit_added": "ALREADY" if not needs_pre_commit else "",
        "gitleaks_added": "ALREADY" if not needs_gitleaks else "",
        "pull_request_url": "",
        "status": "skipped"
    }

    try:
        # Only act on prod repos where at least one file is missing
        if repo_type.lower() == "prod" and (needs_pre_commit or needs_gitleaks):
            if not branch_protection:
                print(f"[{repo}] Direct committing missing files...")
                pre_commit_success = True
                gitleaks_success = True

                if needs_pre_commit:
                    pre_commit_success = commit_file(
                        full_repo, PRE_COMMIT_FILE_PATH, PRE_COMMIT_CONTENT, default_branch, headers
                    )
                    if pre_commit_success:
                        result["pre_commit_added"] = "TRUE"

                if needs_gitleaks:
                    gitleaks_success = commit_file(
                        full_repo, GITLEAKS_FILE_PATH, GITLEAKS_WORKFLOW_CONTENT, default_branch, headers
                    )
                    if gitleaks_success:
                        result["gitleaks_added"] = "TRUE"

                if ((needs_pre_commit and pre_commit_success) or
                    (needs_gitleaks and gitleaks_success)):
                    result["status"] = "direct commit"
                else:
                    result["status"] = "error"

            else:
                print(f"[{repo}] Branch protection enabled. Creating PR with missing files.")
                sha = get_branch_sha(full_repo, default_branch, headers)
                create_branch(full_repo, sha, headers)

                pre_commit_success = True
                gitleaks_success = True

                if needs_pre_commit:
                    pre_commit_success = commit_file(
                        full_repo, PRE_COMMIT_FILE_PATH, PRE_COMMIT_CONTENT, NEW_BRANCH, headers
                    )
                    if pre_commit_success:
                        result["pre_commit_added"] = "TRUE"

                if needs_gitleaks:
                    gitleaks_success = commit_file(
                        full_repo, GITLEAKS_FILE_PATH, GITLEAKS_WORKFLOW_CONTENT, NEW_BRANCH, headers
                    )
                    if gitleaks_success:
                        result["gitleaks_added"] = "TRUE"

                # Open PR only if at least one commit was successful
                if ((needs_pre_commit and pre_commit_success) or
                    (needs_gitleaks and gitleaks_success)):
                    pr_url = create_pull_request(full_repo, default_branch, headers)
                    if pr_url:
                        result["pull_request_url"] = pr_url
                        result["status"] = "pull request"
                    else:
                        result["status"] = "error"
                else:
                    result["status"] = "error"
        else:
            # Not prod or nothing missing
            result["status"] = "skipped"

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

        # Ensure output has extra fields even if input didn’t
        extra_fields = ["pre_commit_added", "gitleaks_added", "pull_request_url", "status"]
        fieldnames = list(reader.fieldnames or [])
        for f in extra_fields:
            if f not in fieldnames:
                fieldnames.append(f)

        for row in reader:
            # Normalize missing expected columns to avoid KeyErrors
            for k in ["Repo Name", "Repo_Type", "Branch Protection Enabled",
                      "Default Branch Name", "Has .pre-commit-config.yaml",
                      "Has gitleaks_secret_scan.yml"]:
                if k not in row:
                    row[k] = ""

            result = process_repo(row, headers, org_name)
            row.update(result)
            updated_rows.append(row)

    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(updated_rows)

    print(f"✅ Updated results written to {OUTPUT_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Auto-configure GitHub repos with Gitleaks and pre-commit.')
    parser.add_argument('-pat', '--github_token', required=True, help='GitHub Personal Access Token')
    parser.add_argument('-org', '--org_name', required=True, help='GitHub Organization Name')
    args = parser.parse_args()

    main(args.github_token, args.org_name)
