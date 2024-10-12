#!/usr/bin/env python3
"""

Jira on macOS or Windows with Software ECA file using python

> NOTE: python has been tested with a software-based ECA, not a hardware-based ECA nor CAC.

1. Export your software-based ECA certificate (see below)

1a. macOS: Export your ECA certificate from KeyChain, set a password, and save as a .p12 or .pfx file
1b. Windows: Export your ECA certificate from the Certificate Store, set and password, and save as a .p12 or .pfx file

2. Convert your p12/pfx file to a passwordless PEM file with openssl:

openssl pkcs12 -in certfile.pfx -out certfile.pem -nodes -legacy

Set the 'certificate_file' vairable below:
certificate_file = 'certfile.pem'

3. Generate a Jira personal access token:
https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html

Set the 'token' variable below:
token = 'my-jira-personal-access-token'

4. Set the 'jira_project' variable below:
jira_project = 'TM2PRJ'

5. Set the 'jira_username' variable to your username below:
jira_username = 'my_username'

5. Install python packages:

python3 -m pip install requests

6. Run this script

python3 jira.py

"""

import requests

# Jira base URL
base_url = 'https://jira.arcus.mil'

# Jira API targets
issue_target='/rest/api/2/issue'
project_target = '/rest/api/2/project'
search_target = '/rest/api/2/search'

# Path to the exported client authentication cert
certificate_file = 'certfile.pem'

# Jira personal access token
jira_personal_access_token = 'my-jira-personal-access-token'

# Jira project
jira_project = 'TM2PRJ'

# Jira Username
jira_username = 'my_username'


# Set the headers
request_headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + jira_personal_access_token
}

# Set cookies for dashboard and consent
cookies = {
    'dashboard': 'yes',
    'consent': 'true'
}

# Request body to create a new issue
request_body_dict = {
    "fields": {
        "project":
            {
                "key": "TM2PRJ"
            },
        "summary": "Created a test issue using the ReST API with Python.",
        "description": "Creating of an issue using project keys and issue type names using the REST API",
        "issuetype": {
            "name": "Bug"
        }
    }
}

# Create the requests session
s = requests.Session()
s.headers.update(request_headers)

# Send the initial request to initialize a new session
initial_resp = s.get(base_url + project_target, cert=certificate_file, cookies=cookies, allow_redirects=True)

# Create a new issue
new_issue_resp = s.post(base_url + issue_target, json=request_body_dict, cert=certificate_file, allow_redirects=False)

print("Status Code", new_issue_resp.status_code)
print("JSON Response ", new_issue_resp.text)

# Set the target for assignee search using your username
target_assignee_search = search_target + '?jql=assignee=' + jira_username

# Search for issues assigned to you
assignee_search_resp = s.get(base_url + target_assignee_search, cert=certificate_file, cookies=cookies,
                             allow_redirects=False)

print("Status Code", assignee_search_resp.status_code)
print("JSON Response ", assignee_search_resp.text)

# Search for issues in a project with attachments
target_issue_search_params = search_target
target_issue_search_params += '?jql=project%20%3D%20'
target_issue_search_params += jira_project
target_issue_search_params += '%20AND%20NOT%20attachments%20is%20EMPTY&fields=attachment&maxResults=1000'

# Search for issues with attachments
issue_search_resp = s.get(base_url + target_issue_search_params, cert=certificate_file, cookies=cookies,
                          allow_redirects=False)

print("Status Code", issue_search_resp.status_code)
print("JSON Response ", issue_search_resp.text)
