import csv
import requests
import argparse

# Updated Branch protection settings
protection_data = {
    "required_status_checks": {
        "strict": True,
        "contexts": [
            "scan / Gitleaks Secret Scanning"
        ]
    },
    "enforce_admins": True,
    "required_conversation_resolution": True,
    "required_pull_request_reviews": {
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "required_approving_review_count": 1
    },
    "restrictions": None,  # No restrictions on who can push
    "allow_force_pushes": False,
    "allow_deletions": False,
    "required_linear_history": False,
    "required_signatures": False,  # Not enforced via this endpoint
    "lock_branch": False
}

# Helper function to normalize booleans from CSV
def is_false(val):
    return str(val).strip().lower() in ["false", "no", "none", "", "unknown"]

# Apply branch protection using GitHub API
def apply_branch_protection(repo_full_name, branch_name, headers):
    if not branch_name:
        print(f"⚠️ Skipping {repo_full_name} due to missing default branch name.")
        return "Failed"

    url = f"https://api.github.com/repos/{repo_full_name}/branches/{branch_name}/protection"
    headers_with_content_type = headers.copy()
    headers_with_content_type["Content-Type"] = "application/json"

    print(f"⏳ Applying protection on: {repo_full_name} (branch: {branch_name})")
    response = requests.put(url, headers=headers_with_content_type, json=protection_data)

    if response.status_code in [200, 201, 204]:
        print(f"✅ Protection applied on: {repo_full_name}")
        return "Yes"
    else:
        print(f"❌ Failed for {repo_full_name}: {response.status_code} - {response.text}")
        return "Failed"

# Read from CSV and apply protection
def apply_protection_from_csv(github_token, org_name):
    input_file = "repos_last_30_days.csv"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json"
    }

    updated_rows = []

    with open(input_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ['Branch Protection Newly Added']

        for row in reader:
            repo_name = row.get('Repo Name', '').strip()
            full_repo_name = f"{org_name}/{repo_name}"
            default_branch = row.get('Default Branch Name', '').strip()

            branch_protection = is_false(row.get('Branch Protection Enabled', ''))
            rulesets_enabled = is_false(row.get('Rulesets Enabled', ''))

            if branch_protection and rulesets_enabled:
                result = apply_branch_protection(full_repo_name, default_branch, headers)
            else:
                print(f"ℹ️ Skipping {repo_name}: branch protection or rulesets already enabled.")
                result = "No"

            row['Branch Protection Newly Added'] = result
            updated_rows.append(row)

    with open("branch_protection_results.csv", "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(updated_rows)

    print("✅ Completed. Output written to 'branch_protection_results.csv'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply branch protection to repos listed in a CSV.")
    parser.add_argument("-pat", "--github_token", required=True, help="GitHub Personal Access Token")
    parser.add_argument("-org", "--org_name", required=True, help="GitHub Organization Name")
    args = parser.parse_args()

    apply_protection_from_csv(args.github_token, args.org_name)
