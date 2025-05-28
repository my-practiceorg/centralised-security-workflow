import requests
import datetime
import csv
import argparse

def get_repos_created_last_30_days(github_token, org_name):
    github_api_url = f"https://api.github.com/orgs/{org_name}/repos"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json"
    }

    today = datetime.date.today()
    thirty_days_ago = today - datetime.timedelta(days=30)

    params = {'per_page': 100}
    repo_list = []
    page = 1

    while True:
        params['page'] = page
        response = requests.get(github_api_url, headers=headers, params=params)

        if response.status_code != 200:
            print(f"Failed to fetch repos: {response.status_code} - {response.text}")
            break

        repos = response.json()
        if not repos:
            break

        for repo in repos:
            created_at = datetime.datetime.strptime(repo['created_at'], "%Y-%m-%dT%H:%M:%SZ").date()
            if thirty_days_ago <= created_at <= today:
                full_name = repo['full_name']
                default_branch = repo['default_branch']

                creator = get_repo_creator(full_name, headers)
                last_updated_by = get_last_updated_by(full_name, headers)
                has_pre_commit_config = check_pre_commit_config(full_name, headers)
                has_gitleaks_workflow = check_gitleaks_workflow(full_name, headers)
                custom_properties = get_repo_custom_properties(full_name, headers)
                branch_protection_enabled = check_branch_protection(full_name, default_branch, headers)
                rulesets_enabled = check_rulesets_enabled(full_name, headers)

                # Always fetch default branch name
                default_branch_name = get_default_branch_name(full_name, default_branch, headers)

                repo_list.append({
                    'name': repo['name'],
                    'created_at': repo['created_at'],
                    'creator': creator,
                    'last_updated_by': last_updated_by,
                    'has_pre_commit_config': has_pre_commit_config,
                    'has_gitleaks_workflow': has_gitleaks_workflow,
                    'Repo_Type': custom_properties,
                    'branch_protection_enabled': branch_protection_enabled,
                    'rulesets_enabled': rulesets_enabled,
                    'default_branch_name': default_branch_name
                })

        page += 1

    return repo_list

def get_repo_creator(repo_full_name, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/events"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return "Unknown"
    for event in response.json():
        if event['type'] == 'CreateEvent':
            return event['actor']['login']
    return "Unknown"

def get_last_updated_by(repo_full_name, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/commits?per_page=1"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return "Unknown"
    commits = response.json()
    if commits:
        return commits[0]['commit']['author']['name']
    return "Unknown"

def check_pre_commit_config(repo_full_name, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/contents/.pre-commit-config.yaml"
    return requests.get(url, headers=headers).status_code == 200

def check_gitleaks_workflow(repo_full_name, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/contents/.github/workflows/gitleaks_secret_scan.yml"
    return requests.get(url, headers=headers).status_code == 200

def get_repo_custom_properties(repo_full_name, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/properties/values"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        for prop in response.json():
            if prop['property_name'] == 'Repo_Type':
                return prop['value']
        return 'Repo_Type not found'
    return "Unknown"

def check_branch_protection(repo_full_name, default_branch, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/branches/{default_branch}/protection"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return True
    elif response.status_code == 404:
        return False
    else:
        return "Unknown"

def check_rulesets_enabled(repo_full_name, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/rulesets"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        for ruleset in response.json():
            if ruleset.get('enforcement') in ['active', 'evaluate']:
                return True
        return False
    elif response.status_code == 404:
        return False
    else:
        return "Unknown"

def get_default_branch_name(repo_full_name, branch_name, headers):
    url = f"https://api.github.com/repos/{repo_full_name}/branches/{branch_name}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('name', '')
    return ''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fetch repos created in the last 30 days with metadata.')
    parser.add_argument('-pat', '--github_token', required=True, help='GitHub Personal Access Token')
    parser.add_argument('-org', '--org_name', required=True, help='GitHub Organization Name')
    args = parser.parse_args()

    repos = get_repos_created_last_30_days(args.github_token, args.org_name)

    if repos:
        with open('repos_last_30_days.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                'Repo Name', 'Created At', 'Created By', 'Last Updated By',
                'Has .pre-commit-config.yaml', 'Has gitleaks_secret_scan.yml',
                'Repo_Type', 'Branch Protection Enabled', 'Rulesets Enabled',
                'Default Branch Name'
            ])
            for repo in repos:
                writer.writerow([
                    repo['name'], repo['created_at'], repo['creator'], repo['last_updated_by'],
                    repo['has_pre_commit_config'], repo['has_gitleaks_workflow'],
                    repo['Repo_Type'], repo['branch_protection_enabled'], repo['rulesets_enabled'],
                    repo['default_branch_name']
                ])
        print(f"✅ Repositories report written to 'repos_last_30_days.csv'.")
    else:
        print(f"No repositories were created in the last 30 days in '{args.org_name}'")
