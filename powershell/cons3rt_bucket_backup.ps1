<#

cons3rt_bucket_backup.ps1

This example PowerShell CONS3RT ReST API script syncs an example directory `T:\backups` folder
to an AWS S3 bucket with key prefix backups.  This script can run in 2 modes: (a) Generate an AWS identity
in the CONS3RT user interface, save it to `~\.aws\identity.txt`, and use that for the backup. (b) Or,
use the CONS3RT API to generate the AWS identity to use for the backup.

# Prerequisites

  1. Windows Server 2016, 2019, 2022, Windows Desktop 10, 11
  2. Powershell 5.1+
  3. Run: Set-ExecutionPolicy RemoteSigned
  4. You must have a client certificate imported into Windows, either a CAC inserted, or ECA software certificate
  5. Config file staged at ~\.cons3rt\conf\config.json with a rest API token, and cert_thumbprint specified as follows

{
  "api_url": "https://api.arcus.mil/rest/api/",
  "cert_thumbprint": "123456789123456789",
  "projects": [
    {
      "name": "Arcus Demo",
      "rest_key": "API_TOKEN_HERE"
    }
  ]
}

# Usage for file-based backup (A)

  * Use this method if you generated an identity in the CONS3RT UI and saved the file to ~\.aws\identity.txt

.\sync_backups_to_bucket.ps1 --BackupIdentityMethod "FILE" -BackupBucketName "BUCKETNAME"

# Usage for CONS3RT API-based backup (B)

.\sync_backups_to_bucket.ps1 --BackupIdentityMethod "API" -BackupBucketName "BUCKETNAME" -BackupDeploymentRunId "12345" -BackupHostId "1234"

  * Alternatively, scheduled task to run this script using one of the above methods

# Exit Codes

  0   = Success
  1   = The -BackupBucketName parameter is required
  2   = When -BackupIdentityMethod is API the -BackupDeploymentRunId parameter is required
  3   = When -BackupIdentityMethod is API the BackupHostId parameter is required
  4   = Problem generating a new identity for deployment run host
  5   = Problem generating credentials files for AWS from identity data
  6   = Problem converting the identity.txt UI CONS3RT output to AWS credentials
  7   = Unsupported BackupIdentityMethod, must be API or FILE
  8   = Problem syncing local backups to the S3 bucket

#>

##########################################################
# Script Parameters
#######################################################

param (
    [string]$BackupIdentityMethod = "API",    # Identity method, set to either "API" or "FILE"
    [string]$BackupDeploymentRunId = $null,   # Deployment Run ID to backup from
    [string]$BackupHostId = $null,            # Host ID in the deployment run to backup from
    [string]$BackupBucketName                 # AWS S3 Bucket Name to backup to
)

##########################################################
# Global Variables
##########################################################

# AWS configuration directory
$script:awsDir = "~\.aws"

# AWS Region
$script:awsRegion = "us-gov-west-1"

# Number of seconds to wait before syncing to S3
$script:syncWaitTimeSec = 120

##########################################################
# Functions
##########################################################


function Add-Identity() {
    # Queries CONS3RT API to generate and return a new identity for the specified host, to the specified service
    # This method returns a JSON string containing the Identity

    param(
        [string]$deploymentRun,
        [string]$hostId,
        [string]$serviceType = "BUCKET",
        [string]$serviceName = $null,
        [string]$serviceIdentity
    )

    Write-Host "INFO: Generating an Arcus Identity deployment run ID $deploymentRun and host ID $hostId..."

    # Get the cons3rt config data
    $cons3rtConfData = Get-Cons3rt-Config
    if ($null -eq $cons3rtConfData) {
        Write-Host "ERROR: Problem loading CONS3RT config data"
        return $null
    }

    # Get the certificate for API authentication
    $cert = Select-Certificate -certThumbprint $cons3rtConfData.cert_thumbprint
    if ($null -eq $cert) {
        Write-Host "ERROR: Problem selecting a client certificate"
        return $null
    }

    # Build the target
    $target = "drs/" + $deploymentRun + "/host/" + $hostId + "/identity"

    # Build the request body
    $identityData = @{
        'type' = $serviceType
        'identifier' = $serviceIdentity
    }

    # Add the name if provided
    if (($null -ne $serviceName) -And ($serviceName -ne "")) {
        $identityData['name'] = $serviceName
    }

    $identityBody = @($identityData)

    Write-Host "INFO: Add-Identity Request Body: $($identityBody | ConvertTo-Json -Depth 10)"

    # Send the request
    $identityResponse = Send-Request -apiBaseUrl $cons3rtConfData.api_url -Token $cons3rtConfData.token -Method "POST" -Target $target -bodyObject $identityBody -clientCertificate $cert

    # Check the result
    if ($identityResponse.Result -eq $false) {
        Write-Host "ERROR: Unable to generate an identity for deployment run ID $deploymentRun and host ID $hostId"
        return $null
    }

    Write-Host "INFO: Successfully generated a new identity for deployment run ID $deploymentRun and host ID $hostId"
    return $identityResponse.Content
}


function Convert-Identity-File() {
    # Converts ~\.aws\identity.txt to AWS credentials files
    # Returns the full bucket name or $null if there was a problem

    # Path to the CONS3RT-formatted identity file
    $identityFile = "$script:awsDir\identity.txt"

    Write-Host "INFO: Converting $identityFile to $awsCredentialsFile..."

    if ( -Not (Test-Path -Path $identityFile)) {
        Write-Host "ERROR: File not found [$identityFile], generate an Identity from Arcus and store the file in: ~\.aws\identity.txt"
        return $null
    }

    # Read the file
    $inputContent = Get-Content -Path $identityFile -Raw

    # Get the AWS credentials
    $accessKey = ($inputContent | Select-String -Pattern 'Access Key: (.*)').Matches.Groups[1].Value
    $sessionToken = ($inputContent | Select-String -Pattern 'Session Token: (.*)').Matches.Groups[1].Value
    $secretAccessKey = ($inputContent | Select-String -Pattern 'Secret Access Key: (.*)').Matches.Groups[1].Value

    # Create the AWS config and credentials files
    $fileResult = Format-Aws-Files -accessKey $accessKey -secretAccessKey $secretAccessKey -sessionToken $sessionToken -region $script:awsRegion
    if ($fileResult -eq $false) {
        Write-Host "ERROR: Problem creating AWS config and credentials files"
        return $null
    }

    # Get the bucket name
    $bucketName = Get-BucketName -identityFileContent $inputContent
    if ($null -eq $bucketName) {
        Write-Host "ERROR: Problem getting the bucket name from identity content"
        return $null
    }

    # Ensure the bucket name was found in identity.txt file (output by Arcus)
    if ($null -eq $bucketName) {
        Write-Host "ERROR: Bucket name is NULL"
        return $null
    } elseif ($bucketName -eq "") {
        Write-Host "ERROR: Bucket name is blank"
        return $null
    }
    Write-Host "INFO: Found bucket name: $bucketName"

    # Return the bucket name
    return $bucketName
}


function Format-Aws-Credentials-From-Api-Identity() {
    # Takes the JSON API response from generating a new identity can created AWS credentials files

    param(
        [string]$identityJson      # JSON response from the API call to generate an identity
    )

    # Path to the CONS3RT-formatted identity file
    $identityFile = "$script:awsDir\identity.json"

    Write-Host "INFO: Converting $identityFile to an AWS credentials file..."

    # Remove existing identity json file
    if (Test-Path -Path $identityFile) {
        Write-Host "INFO: Removing existing file: $identityFile"
        Remove-Item -Path $identityFile
    }

    # Save the nicely formatted JSON to a file
    Write-Host "INFO: Saving identity to file: $identityFile"
    $identityJson | Set-Content -Path $identityFile

    # Load the JSON string to a PowerShell object
    $identityObj = $identityJson | ConvertFrom-Json

    # Collect the access key data
    $accessKey = $identityObj.credentials.'Access Key'
    $sessionToken = $identityObj.credentials.'Session Token'
    $secretAccessKey = $identityObj.credentials.'Secret Access Key'

    # Create the AWS config and credentials files
    $fileResult = Format-Aws-Files -accessKey $accessKey -secretAccessKey $secretAccessKey -sessionToken $sessionToken -region $script:awsRegion
    if ($fileResult -eq $false) {
        Write-Host "ERROR: Problem creating AWS config and credentials files"
        return $false
    }

    Write-Host "INFO: Generated AWS credentials and config files"
    return $true
}


function Format-Aws-Files() {
    # Creates the AWS credentials and config files given the access key, secret key, session token, and region
    # Returns $true for success, $false for an issue

    param(
        [string]$accessKey,         # AWS Access Key ID
        [string]$secretAccessKey,   # AWS Secret Access Key
        [string]$sessionToken,      # AWS Session Token
        [string]$region             # AWS region
    )

    # AWS directory and file locations
    $awsCredentialsFile = "$awsDir\credentials"
    $awsConfigFile = "$awsDir\config"

    $outputContent = @"
[default]
aws_access_key_id = $accessKey
aws_secret_access_key = $secretAccessKey
aws_session_token = $sessionToken
"@

    # Delete existing credentials file
    if (Test-Path -Path $awsCredentialsFile) {
        Write-Host "INFO: Deleting existing file: $awsCredentialsFile"
        Remove-Item -Path $awsCredentialsFile
    }

    # Write the new credentials file
    Write-Host "INFO: Creating new credentials file with access key [$accessKey]: $awsCredentialsFile"
    $outputContent | Out-File -FilePath $awsCredentialsFile -Encoding UTF8

    # Write the config file
    $configContent = @"
[default]
region = $region
output = text
"@

    # Delete existing config file
    if (Test-Path -Path $awsConfigFile) {
        Write-Host "INFO: Deleting existing file: $awsConfigFile"
        Remove-Item -Path $awsConfigFile
    }

    # Write the new config file
    Write-Host "INFO: Creating new config file: $awsConfigFile"
    $configContent | Out-File -FilePath $awsConfigFile -Encoding UTF8

    # Return true for success
    return $true
}


function Get-BucketName() {

    param (
        [string]$identityFileContent    # Content of the identity.txt file
    )

    # Store the string of the last non-empty line
    $lastNonEmptyLine = $null

    # Find the last non-empty line
    foreach ($line in $identityFileContent) {
        if ($line -match '\S') {
            $lastNonEmptyLine = $line
        }
    }

    # Ensure the last non-empty line was found
    if ($null -eq $lastNonEmptyLine) {
        Write-Host "ERROR: Problem finding the bucket name from content: $identityFileContent"
        return $null
    }

    # Split the bucket name on :
    $bucketName = ($lastNonEmptyLine -split ':')[-1].Trim()

    Write-Host "INFO: Found bucket name: $bucketName"
    return $bucketName
}


function Get-Cons3rt-Config() {

    param (
            [string]$project = $null  # Optionally specify a project to set as the main API token, otherwise the first
                                      # will be used
    )

    Write-Host "INFO: Loading the CONS3RT config file..."

    $cons3rtHome = Get-Cons3rt-Home
    if ($null -eq $cons3rtHome) {
        Write-Host "INFO: CONS3RT_HOME environment variable is not set"
        $cons3rtHome = "~\.cons3rt"
    } else {
        Write-Host "INFO: Found CONS3RT_HOME environment variable"
    }
    Write-Host "INFO: Using CONS3RT_HOME: $cons3rtHome"

    # CONS3RT conf directory
    $cons3rtConfDir = "$cons3rtHome\conf"

    # Path to the CONS3RT config file
    $cons3rtConfFile = "$cons3rtConfDir\config.json"

    if ( -Not (Test-Path -Path $cons3rtConfFile)) {
        Write-Host "ERROR: File not found [$cons3rtConfFile], this needs ot be staged with API info and key"
        return $null
    }

    # Read the file and convert to JSON
    $cons3rtConfJson = Get-Content -Path $cons3rtConfFile -Raw
    $cons3rtConfData = ConvertFrom-Json $cons3rtConfJson

    # Ensure required fields are provided

    # Check for the existence of required data in the CONS3RT config file
    if ($null -eq $cons3rtConfData.api_url) {
        Write-Host "ERROR: The 'api_url' is required but not set in CONS3RT config file: $cons3rtConfFile"
        return $null
    }
    if ($null -eq $cons3rtConfData.cert_thumbprint) {
        Write-Host "ERROR: The 'cert_thumbprint' is required but not set in CONS3RT config file: $cons3rtConfFile"
        return $null
    }
    if ($null -eq $cons3rtConfData.projects) {
        Write-Host "ERROR: The 'projects' is required but not set in CONS3RT config file: $cons3rtConfFile"
        return $null
    }
    if ($cons3rtConfData.projects.Length -lt 1) {
        Write-Host "ERROR: At least one entry in 'projects' is required but not set in CONS3RT config file: $cons3rtConfFile"
        return $null
    }

    Write-Host "INFO: CONS3RT API URL: $($cons3rtConfData.api_url)"
    Write-Host "INFO: CONS3RT client certificate thumbprint: $($cons3rtConfData.cert_thumbprint)"
    Write-Host "INFO: CONS3RT config contains $($cons3rtConfData.projects.Length) projects"

    # Access values within the 'projects' array (assuming there can be multiple projects)
    # If a $project arg param was provided, attempt to match the project name
    $projectFound = $false

    foreach ($projectData in $cons3rtConfData.projects) {
        if ($null -eq $projectData.name) {
            Write-Host "ERROR: The 'name' is required for each project in CONS3RT config file: $cons3rtConfFile"
            return $null
        }
        if ($null -eq $projectData.rest_key) {
            Write-Host "ERROR: The 'rest_key' is required for each project in CONS3RT config file: $cons3rtConfFile"
            return $null
        }
        Write-Host "Found ReST API key for project: $($projectData.name)"

        # If a project param was provided, check if the current projectData matches, and set the project and token values
        if ($project -ne $null) {
            if ($projectData.name -eq $project) {
                $cons3rtConfData | Add-Member -MemberType NoteProperty -Name "token" -Value $projectData.rest_key
                $cons3rtConfData | Add-Member -MemberType NoteProperty -Name "project" -Value $projectData.name
                $projectFound = $true
            }
        }
    }

    # If a project param was not provided, use the first project in the list
    if ($projectFound -eq $false) {
        $cons3rtConfData | Add-Member -MemberType NoteProperty -Name "token" -Value $cons3rtConfData.projects[0].rest_key
        $cons3rtConfData | Add-Member -MemberType NoteProperty -Name "project" -Value $cons3rtConfData.projects[0].name
    }
    Write-Host "INFO: Using token for project name: $($cons3rtConfData.project)"
    return $cons3rtConfData
}


function Get-Cons3rt-Home() {
    Write-Host "INFO: Determining CONS3RT home..."
    if (Test-Path "env:CONS3RT_HOME") {
        if ($env:CONS3RT_HOME -ne "") {
            Write-Host "INFO: Found environment variable CONS3RT_HOME: $env:CONS3RT_HOME"
            return $env:CONS3RT_HOME
        }
    } else {
        Write-Host "INFO: Environment variable CONS3RT_HOME is not set"
        return $null
    }
}

function Get-Identities() {
    # Returns a list of identities for this VM

    param(
        [string]$deploymentRunId,  # Deployment run ID
        [string]$hostId            # Deployment run host ID
    )

    Write-Host "INFO: Getting identities for run ID $deploymentRunId and host ID $hostId..."

    # Get the cons3rt config data
    $cons3rtConfData = Get-Cons3rt-Config
    if ($null -eq $cons3rtConfData) {
        Write-Host "ERROR: Problem loading CONS3RT config data"
        return $null
    }

    # Get the certificate for API authentication
    $cert = Select-Certificate -certThumbprint $cons3rtConfData.cert_thumbprint
    if ($null -eq $cert) {
        Write-Host "ERROR: Problem selecting a client certificate"
        return $null
    }

    # Build the target
    $target = "drs/" + $deploymentRunId + "/host/" + $hostId + "/identity"

    # Send the request
    $identityResponse = Send-Request -apiBaseUrl $cons3rtConfData.api_url -Token $cons3rtConfData.token -Method "GET" -Target $target -clientCertificate $cert

    # Check for a failed response
    if ($identityResponse.Result -eq $false) {
        Write-Host "WARN: Problem getting identities from host $hostId in deployment run $deploymentRunId"
        return @()
    }

    # Get the identities array
    $identities = $identityResponse.Content | ConvertFrom-Json

    Write-Host "INFO: Completed listing identities for run ID $deploymentRunId and host ID $hostId, found $($identities.Length) identities"
    return $identities
}


function Remove-Identity() {
    # Removes an identity from this VM, returns $true or $false

    param(
        [string]$deploymentRunId,  # Deployment run ID
        [string]$hostId            # Deployment run host ID
    )

    Write-Host "INFO: Attempting to remove identities for run ID $deploymentRunId and host ID $hostId..."

    # Get the cons3rt config data
    $cons3rtConfData = Get-Cons3rt-Config
    if ($null -eq $cons3rtConfData) {
        Write-Host "ERROR: Problem loading CONS3RT config data"
        return $false
    }

    # Get the certificate for API authentication
    $cert = Select-Certificate -certThumbprint $cons3rtConfData.cert_thumbprint
    if ($null -eq $cert) {
        Write-Host "ERROR: Problem selecting a client certificate"
        return $false
    }

    # Build the target
    $target = "drs/" + $deploymentRunId + "/host/" + $hostId + "/identity"

    # Send the request
    $deleteResponse = Send-Request -apiBaseUrl $cons3rtConfData.api_url -Token $cons3rtConfData.token -Method "DELETE" -Target $target -clientCertificate $cert

    # Check for a failed response
    if ($deleteResponse.Result -eq $false) {
        Write-Host "WARN: Problem removing identities from host $hostId in deployment run $deploymentRunId"
        return $false
    }

    Write-Host "INFO: Completed removing identities for run ID $deploymentRunId and host ID $hostId"
    return $true
}


function Select-Certificate() {

    param (
            [string]$certThumbprint = $null    # Thumbprint of the certificate to select from the store
                                               # If not provided, the user is prompted for a cert
        )

    # Open the certificate store for CurrentUser in read-only mode
    $store = New-Object system.security.cryptography.X509Certificates.x509Store("My", "CurrentUser")
    $store.Open("ReadOnly")
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

    # Initialize the certificate to $null
    $certificate = $null

    # If a certificate thumbprint was provided, try to find it
    if (($null -ne $certThumbprint) -And ($certThumbprint -ne "")) {
        Write-Host "INFO: Checking for certificate with thumbprint: $certThumbprint"
        $certificate = $store.certificates | Where-Object { $_.Thumbprint -eq $certThumbprint }

        # Write an error if the cert thumbprint was not found
        if ($null -eq $certificate) {
            Write-Host "ERROR: Certificate with thumbprint [$certThumbprint] not found" -ForegroundColor Red
        } else {
            Write-Host "INFO: Found certificate by thumbprint: $certThumbprint"
        }
    }

    # Either a certificate thumbprint was not provided or not found, prompt the user to select
    if ($null -eq $certificate) {
        Write-Host "INFO: Prompting the user to select a certificate..."
        $certificate = [System.Security.Cryptography.x509Certificates.X509Certificate2UI]::SelectFromCollection($store.certificates, "Your certificates", "Please select", 0)
    }

    # Close the certificate store
    $store.Close()

    # Ensure a certificate was found or selected
    if (!$certificate) {
        Write-Host "ERROR: Please ensure you provide a certificate thumbprint or select a certificate" -foregroundColor Red
        return $null
    }
    Write-Host "INFO: Using certificate with thumbprint: $($certificate.Thumbprint)"

    # Create and return the X509Certificate2 object
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)
    return $cert
}


function Send-Request() {
    # Sends a request to CONS3RT and returns the response

    param(
        [string]$apiBaseUrl,                 # CONS3RT API base URL (e.g. https://api.arcus.mil/rest/api)
        [object]$bodyObject = $null,         # Object to be sent in the request body as JSON
        [object]$clientCertificate = $null,  # Client certificate object
        [string]$method = "GET",             # HTTP method GET, PUT, POST, DELETE, etc.
        [string]$target,                     # ReST API target after the base endpoint URL (e.g. "teams/ID")
        [string]$token,                      # Arcus ReST API token
        [string]$username = $null            # Arcus username
    )

    # Stores the output
    $apiResponse = New-Object –TypeName PSObject
    $apiResponse | Add-Member -MemberType NoteProperty -Name Result -Value $null -TypeName [System.Bool]
    $apiResponse | Add-Member -MemberType NoteProperty -Name StatusCode -Value $null -TypeName [System.Int32]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Content -Value $null -TypeName [System.String]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Info -Value $null -TypeName [System.String]

    # Set the full request URI
    if (-Not $apiBaseUrl.EndsWith("/")) {
        $apiBaseUrl = $apiBaseUrl + "/"
    }
    $requestUri = $apiBaseUrl + $target

    # Adding 'odata.metadata=none' to the Accept header to make the response payloads more concise and readable.
    # "Accept"="application/json;odata.metadata=none"
    $headers = @{
        "token" = $token
        "Accept" = "application/json"
    }

    # Convert the object to JSON and set it as the request body
    $jsonBody = $null
    if ($null -ne $bodyObject) {
        $jsonBody = ConvertTo-Json $bodyObject -Depth 10 -Compress
    }

    # Making the HTTP request
    Write-Host "INFO: Making [$method] request to URI [$requestUri]..."

    # Send the request with a client certificate and a JSON request body
    if (($null -ne $jsonBody) -And ($null -ne $clientCertificate)) {
        #Write-Host "DEBUG: Sending request with client certificate:`n$clientCertificate"
        Write-Host "INFO: Sending request with a client certificate and body JSON: $jsonBody"
        Show-Headers -headers $headers
        $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -Certificate $clientCertificate -Body $jsonBody -ContentType "application/json; charset=utf-8"
    # Send the request with a client certificate without a JSON request body
    } elseif (($null -eq $jsonBody) -And ($null -ne $clientCertificate)) {
        #Write-Host "DEBUG: Sending request with client certificate:`n$clientCertificate"
        Write-Host "INFO: Sending request with a client certificate without a body..."
        Show-Headers -headers $headers
        $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -Certificate $clientCertificate
    # Send the request with a username and a JSON request body
    } elseif (($null -ne $jsonBody) -And ($null -ne $username)) {
        Write-Host "INFO: Sending request with a username $username and body JSON: $jsonBody"
        $headers["username"] = "$username"
        Show-Headers -headers $headers
        $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -Body $jsonBody -ContentType "application/json; charset=utf-8"
    # Send the request with a username without a JSON request body
    } elseif (($null -eq $jsonBody) -And ($null -ne $username)) {
        Write-Host "INFO: Sending request with a username $username without a body..."
        $headers["username"] = "$username"
        Show-Headers -headers $headers
        $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers
    # Otherwise, error out if neither a username not client certificate was provided
    } else {
        $errMsg = "ERROR: Either a client certificate or a username is required for authentication"
        $apiResponse.Result = $false
        $apiResponse.Info = $errMsg
        return $apiResponse
    }

    # Output the full api response
    #Write-Host "INFO: Full API Response: $($serverResponse | ConvertTo-Json -Depth 10 -Compress)"

    # Handle the error case where Invoke-WebRequest returned false or a bad http status code
    if (($null -eq $serverResponse.StatusCode) -Or ($serverResponse.StatusCode -lt 200) -Or ($serverResponse.StatusCode -gt 299)) {

        # Set the error message
        if ($null -eq $serverResponse.StatusCode) {
            $errMsg = "ERROR: Invoke-WebRequest returned a false error result (probably no http status code)"
        } else {
            $errMsg = "ERROR: API returned an error code: $($serverResponse.StatusCode)"
        }

        # Print results
        Write-Host $errMsg
        Write-Host "ERROR: Problem making [$method] request to URI: $requestUri"
        Write-Host "ERROR: Response status code: $($serverResponse.StatusCode)"
        Write-Host "ERROR: Response body: $($serverResponse.Content)"

        # Set the apiResponse return object
        $apiResponse.Result = $false
        $apiResponse.Info = $errMsg
        $apiResponse.StatusCode = $serverResponse.StatusCode
        $apiResponse.Content = $serverResponse.Content

        # Return
        return $apiResponse
    }

    # Build and return the response object for the successful response case
    $msg = "INFO: [$method] request to URI [$requestUri] returned status code: $($serverResponse.StatusCode)"
    Write-Host $msg
    Write-Host "INFO: Response content: $($serverResponse.Content | ConvertTo-Json -Depth 10 -Compress)"
    $apiResponse.Result = $true
    $apiResponse.Info = $msg
    $apiResponse.StatusCode = $serverResponse.StatusCode
    $apiResponse.Content = $serverResponse.Content
    return $apiResponse
}


function Show-Headers() {
    param(
        [Hashtable]$headers         # Hashtable of headers
    )
    Write-Host "INFO: Sending request with headers: "
    foreach ($key in $headers.Keys) {
        if ($key -eq "token") {
            $lastSixTokenChars = $headers[$key][-6..-1] -join ''
            Write-Host "$key = (ends with) $lastSixTokenChars"
        } else {
            Write-Host "$key = $($headers[$key])"
        }
    }
}


function Sync-Backups() {

    param(
        [string]$localShareFolder,  # Path of the backups on the local share
        [string]$bucketName,        # Bucket name
        [string]$keyPrefix          # Path in the bucket to sync to
    )

    # Create the key prefix if it does not exist
    Write-Host "INFO: Syncing local folder $localShareFolder to s3://$bucketName/$keyPrefix..."
    Write-S3Object -BucketName $bucketName -Folder $localShareFolder -KeyPrefix $keyPrefix
    if ($? -eq $False) {
        # Check for error and exit with code 100 if error detected
        Write-Host "ERROR: Problem syncing local folder $localShareFolder to s3://$bucketName/$keyPrefix"
        return $false
    }
    # Print success
    Write-Host "INFO: Completing syncing local folder $localShareFolder to s3://$bucketName/$keyPrefix"
    return $true
}

##########################################################
# Main
##########################################################

function Main() {
    Write-Host "INFO: Running the cons3rt_bucket_backup.ps1 script..."

    if ($null -eq $BackupBucketName) {
        Write-Host "ERROR: The -BackupBucketName parameter is required"
        exit 1
    }
    Write-Host "INFO: Backing up to bucket name: [$BackupBucketName]..."

    # Setup service identity parameters
    $serviceType = "BUCKET"

    if ($BackupIdentityMethod -eq "API") {
        Write-Host "INFO: Using the API-based identity method..."

        # Ensure the BackupDeploymentRunId and BackupHostId parameters were provided
        if ($null -eq $BackupDeploymentRunId) {
            Write-Host "ERROR: When -BackupIdentityMethod is API the -BackupDeploymentRunId parameter is required"
            exit 2
        }
        if ($null -eq $BackupHostId) {
            Write-Host "ERROR: When -BackupIdentityMethod is API the -BackupHostId parameter is required"
            exit 3
        }

        # Get existing identities
        $currentIdentities = Get-Identities -deploymentRunId $BackupDeploymentRunId -hostId $BackupHostId

        # Delete existing identities if they exist
        if ($currentIdentities.Length -gt 0) {
            Write-Host "INFO: Removing identities for host [$BackupHostId] in deployment run [$BackupDeploymentRunId]..."
            Remove-Identity deploymentRunId $BackupDeploymentRunId -hostId $BackupHostId
        } else {
            Write-Host "INFO: No identities to remove for host [$BackupHostId] in deployment run [$BackupDeploymentRunId]"
        }

        # Query Arcus API to generate an identity
        $newIdentity = Add-Identity -deploymentRun $BackupDeploymentRunId -hostId $BackupHostId -serviceType $serviceType -serviceIdentity $BackupBucketName
        if ($null -eq $newIdentity) {
            Write-Host "ERROR: Problem generating a new identity for deployment run ID $BackupDeploymentRunId host $BackupHostId"
            exit 4
        }

        # Convert the new identity to AWS credentials files
        $awsResult = Format-Aws-Credentials-From-Api-Identity -identityJson $newIdentity
        if ($awsResult -eq $false) {
            Write-Host "ERROR: Problem generating credentials files for AWS from identity data: $($newIdentity)"
            exit 5
        }

        # Wait before using the new identity -- needed for the KMS key to be allowed on the new identity, which happens every 60 seconds
        Write-Host "INFO: Waiting $script:syncWaitTimeSec seconds before attempting to sync..."
        Start-Sleep -s $script:syncWaitTimeSec

    } elseif ($BackupIdentityMethod -eq "FILE") {
        Write-Host "INFO: Using the file-based identity method..."

        # Convert the identity to AWS config and credentials files, and get the full bucket name
        $fullBucketName = Convert-Identity-File
        if ($null -eq $fullBucketName) {
            Write-Host "ERROR: Problem converting the identity.txt UI CONS3RT output to AWS credentials"
            exit 6
        }

    } else {
        Write-Host "ERROR: Unsupported BackupIdentityMethod, must be API or FILE, found: $BackupIdentityMethod"
        exit 7
    }


    # Sync the local backup folder to S3
    $syncResult = Sync-Backups -localShareFolder "T:\backups" -bucketName $BackupBucketName -keyPrefix "backups"
    if ($syncResult -eq $false) {
        Write-Host "ERROR: Problem syncing backups from T:\backups to $BackupBucketName"
        exit 8
    }

    Write-Host "INFO: Completed running: cons3rt_bucket_backup.ps1, exiting with success"
}

##########################################################
# Script Execution
#########################################################

# Execute the Main function
Main

# Exit with code 0 if no errors detected
exit 0
