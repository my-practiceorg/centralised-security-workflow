import csv
import requests
import argparse

# Branch protection settings to be applied
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
    "restrictions": None,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "required_linear_history": False,
    "required_signatures": False,
    "lock_branch": False
}

def is_false(val):
    return str(val).strip().lower() in ["false", "no", "none", "", "unknown"]

def apply_branch_protection(repo_full_name, branch_name, headers):
    if not branch_name:
        print(f"⚠️ Skipping {repo_full_name}: missing default branch.")
        return "Failed"

    url = f"https://api.github.com/repos/{repo_full_name}/branches/{branch_name}/protection"
    headers_with_ct = headers.copy()
    headers_with_ct["Content-Type"] = "application/json"

    print(f"⏳ Applying protection on: {repo_full_name} (branch: {branch_name})")
    response = requests.put(url, headers=headers_with_ct, json=protection_data)

    if response.status_code in [200, 201, 204]:
        print(f"✅ Protection applied on: {repo_full_name}")
        return "Yes"
    else:
        print(f"❌ Failed for {repo_full_name}: {response.status_code} - {response.text}")
        return "Failed"

def apply_protection_from_csv(github_token, org_name):
    input_file = "repos_last_30_days.csv"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json"
    }

    updated_rows = []

    with open(input_file, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ['Branch Protection Newly Added'] if 'Branch Protection Newly Added' not in reader.fieldnames else reader.fieldnames

        for row in reader:
            repo_name = row.get('Repo Name', '').strip()
            default_branch = row.get('Default Branch Name', '').strip()
            full_repo_name = f"{org_name}/{repo_name}"

            repo_type_raw = row.get('Repo_Type', '')
            bp_raw = row.get('Branch Protection Enabled', '')
            rs_raw = row.get('Rulesets Enabled', '')

            repo_type = repo_type_raw.strip().lower()
            branch_protection_enabled = not is_false(bp_raw)
            rulesets_enabled = not is_false(rs_raw)

            print(f"🔍 Checking {repo_name}: type='{repo_type_raw}' → {repo_type}, BP='{bp_raw}' → {branch_protection_enabled}, RS='{rs_raw}' → {rulesets_enabled}")

            if repo_type == 'prod' and not branch_protection_enabled and not rulesets_enabled:
                result = apply_branch_protection(full_repo_name, default_branch, headers)
            else:
                print(f"ℹ️ Skipping {repo_name}: conditions not met (type: {repo_type}, protection enabled: {branch_protection_enabled}, rulesets enabled: {rulesets_enabled})")
                result = "No"

            row['Branch Protection Newly Added'] = result
            updated_rows.append(row)

    with open("branch_protection_results.csv", "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(updated_rows)

    print("✅ Completed. Output written to 'branch_protection_results.csv'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apply branch protection to 'prod' repos with no protection or rulesets.")
    parser.add_argument("-pat", "--github_token", required=True, help="GitHub Personal Access Token")
    parser.add_argument("-org", "--org_name", required=True, help="GitHub Organization Name")
    args = parser.parse_args()

    apply_protection_from_csv(args.github_token, args.org_name)
