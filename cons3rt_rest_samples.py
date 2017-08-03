#!/usr/bin/env python
"""
cons3rt_rest_samples.py

This sample code makes CONS3RT ReST API requests to Hanscom milCloud
using certificate-based authentication.

Prerequisites:
- Windows or Linux OS with Python 2.6+ installed
- These examples utilize the readily-available python requests and
 requests_toolbelt packages.  To install these packages run:

 pip install requests
 pip install requests_toolbelt

"""
import os
import requests
from requests_toolbelt import MultipartEncoder


"""
First, identify paths to your certificate files.  The following is 
an OS-agnostic way to achieve this.  This examples uses a "certs" 
directory in your home directory, update these accordingly.

Note: If you want to use an absolute path on Windows (please don't)
be sure to double your backslashes: C:\\Users\\Joe\\certs\\cert.pem

"""
home_dir = os.path.expanduser('~')
certs_dir = os.path.join(home_dir, 'certs')
cert_file = os.path.join(certs_dir, 'my_eca_cert.pem')
cert_bundle = os.path.join(certs_dir, 'dod_bundle.pem')

"""
Next, determine the CONS3RT site base URL:
- For HmC: https://www.milcloud.hanscom.hpc.mil
- For cons3rt.com: https://www.cons3rt.com

And your project API token.  To create an API token for yoru project
use these instructions:

https://kb.cons3rt.com/kb/accounts/api-tokens

"""
base_url = 'https://www.milcloud.hanscom.hpc.mil'
api_token = '12345-67890-12345-6789'

"""
Set the initial headers, including the api_token.  For cons3rt.com, 
you can use the following headers in this comment section, note the
username is required:

headers = {
    'username': cons3rt_username,
    'token': '12345-67890-12345-67890',
    'Accept': 'application/json'
    'Content-Type': 'application/json'
}

"""
headers = {
    'token': api_token,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

"""
########################################
Sample API Call to List Deployment Runs
########################################

Make the API call using requests.  Note the following arguments:

headers - Set to the headers dict defined above
verify - Set to False to ingore SSL issues, or set a path to a DoD Root CA certificate bundle (PEM file)
cert - Set to the path to your ECA certificate file, or set to None for cons3rt.com

"""
response = requests.get(base_url + '/rest/api/drs/?search_type=SEARCH_ALL&in_project=false', headers=headers, verify=False, cert=cert_file)
print('CONS3RT returned code: ' + str(response.status_code))
print('API call output: ' + str(response.content))

"""
########################################
Sample API Call to Import an Asset
########################################

First, create an asset zip file using these instructions:

https://kb.cons3rt.com/articles/creating-component-assets

Or use these samples:

Linux Sample Asset: https://github.com/cons3rt/software-asset-linux
Windows Sample: https://github.com/cons3rt/software-asset-windows-powershell

Next, define the path to your asset zip file to import.  This example 
uses a zip file called asset.zip, and places it in ~/assets

"""
asset_dir = os.path.join(home_dir, 'assets')
asset_file_name = 'asset.zip'
asset_zip = os.path.join(asset_dir, asset_file_name)

# Print an error if the file is not found
if not os.path.isfile(asset_zip):
    print('ERROR: Asset zip file not found: {f}'.format(f=asset_zip))
else:
    # Update headers to software asset import, for this call Keep-Alive is required.
    headers['Connection'] = 'Keep-Alive'

    # Make the API call
    with open(asset_zip, 'r') as f:
        form = MultipartEncoder({
            "file": (asset_file_name, f, "application/octet-stream"),
            "filename": asset_file_name
        })
        headers["Content-Type"] = form.content_type
        response = requests.post(base_url + '/rest/api/software/import', headers=headers, data=form, verify=False, cert=cert_file)
        print('CONS3RT returned code: ' + str(response.status_code))
        print('API call output: ' + str(response.content))
