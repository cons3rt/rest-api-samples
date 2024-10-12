<#

jira.ps1

This script shows an example for connecting to Jira with a CAC on Windows with Windows Powershell.

Note - This has not been tested with Powershell 7.

Prerequisites:

1. DoD CAC or ECA Installed in your browser with the proper root CA certificates configured
2. Arcus account is active with your certificate registered
3. Jira team service, and you have logged into it through https://arcus.mil
4. Jira Personal Access Token

Usage:

1. Run: .\jira.ps1
2. When prompted, enter your Jira Personal Access Token
3. When prompted, select the desired CAC or ECA certificate
4. Enter PIN if requested

#>

# Global variables
$script:baseUrl = "https://jira.arcus.mil"
$script:searchTarget = "rest/api/2/search"
$script:issueTarget = "rest/api/2/issue"
$script:projectTarget = "rest/api/2/project"

function Get-Token() {
    # Promps the user to enter the Jira Personal Access Token and returns a string

    $jiraPersonalAccessTokenSecureStr = Read-Host -AsSecureString -Prompt "What is your Jira personal access token? "
    $jiraPersonalAccessToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($jiraPersonalAccessTokenSecureStr))
    return $jiraPersonalAccessToken
}

function Select-Certificate() {
    # Selects a user-certificate from the Windows Certificate Store, or prompts the user to select a certificate
    # Note - The user may be prompted to enter a PIN
    # Returns a X509Certificate2 object

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
        Write-Host "INFO: Prompting to select a certificate..."
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

function Send-Initial-Request() {
    # Send an initial request to Jira using the provided params and the basic project URL.  The purpose of this function is
    # to return a WebSession object

    param(
        [string]$apiBaseUrl,                 # API base URL
        [object]$clientCertificate = $null,  # Client certificate object
        [string]$token                       # ReST API token
    )

    # This request will always be a GET
    $method = "GET"

    # Stores the output
    $apiResponse = New-Object –TypeName PSObject
    $apiResponse | Add-Member -MemberType NoteProperty -Name Result -Value $null -TypeName [System.Bool]
    $apiResponse | Add-Member -MemberType NoteProperty -Name StatusCode -Value $null -TypeName [System.Int32]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Content -Value $null -TypeName [System.String]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Info -Value $null -TypeName [System.String]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Session -Value $null -TypeName [Microsoft.PowerShell.Commands.WebRequestSession]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Color -Value $null -TypeName [System.String]

    # Set the full request URI
    if (-Not $apiBaseUrl.EndsWith("/")) {
        $apiBaseUrl = $apiBaseUrl + "/"
    }

    # Using the project target as the simple example to get the session
    $requestUri = $apiBaseUrl + $script:projectTarget

    # Create the headers
    $headers = @{
        "Authorization" = "Bearer $token"
    }

    # Making the HTTP request
    Write-Host "INFO: Making [$method] request to URI [$requestUri]..."

    # Print the headers
    #Show-Headers -headers $headers

    # Capture the message
    $msg = ""

    try
    {
        # Send the API call either with or without a client certificate
        if ($null -ne $clientCertificate) {
            # Send the request with a client certificate
            #Write-Host "DEBUG: Sending initial request with client certificate:`n$clientCertificate"
            #Write-Host "DEBUG: Sending initial request with a client certificate, making [$method] request to URI: [$requestUri]..."
            $initialResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -Certificate $clientCertificate -SessionVariable "InitialSession"
        } else {
            # Send the request without a client certificate and without a JSON request body
            #Write-Host "DEBUG: Sending initial request without a client certificate, making [$method] request to URI: [$requestUri]..."
            $initialResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -SessionVariable "InitialSession"
        }

        # Set the apiResponse object to the successful state
        $apiResponse.Result = $true
        $apiResponse.Color = "Green"
        $apiResponse.StatusCode = $initialResponse.StatusCode
        $apiResponse.Content = $initialResponse.Content
        $apiResponse.Session = $InitialSession

        # Set the message
        $msg += "INFO: [$method] request to URI [$requestUri] returned status code: [$($apiResponse.StatusCode)]"

    } catch {
        # Handle failed API calls

        # Set the apiResponse object to failed state
        $apiResponse.Result = $false
        $apiResponse.Color = "Red"
        $apiResponse.StatusCode = $_.Exception.Response.StatusCode.value__
        $apiResponse.Content = "Exception:`n" + $_.Exception.Message

        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $errorContent = $streamReader.ReadToEnd() | ConvertFrom-Json
        foreach ($errorMessage in $errorContent.errorMessages) {
            $apiResponse.Content += "`nHTTP Error Response:: $($errorMessage)"
        }
        $streamReader.Close()

        # Set the error message
        if ($null -eq $apiResponse.StatusCode) {
            $msg += "ERROR: [$method] request to URI [$requestUri] encountered an error (probably no http status code)"
        } else {
            $msg += "ERROR: [$method] request to URI [$requestUri] returned error code: [$($apiResponse.StatusCode)]"
        }

        # Add content to the output message if it exists
        if ($null -ne $apiResponse.Content) {
            $msg += "`n$($apiResponse.Content)"
        }
    }

    # Set the info message and WebSession
    $apiResponse.Info = $msg
    $apiResponse.Session = $session

    # Print the message and return
    Write-Host $msg -ForegroundColor $apiResponse.Color
    return $apiResponse
}

function Send-Request() {
    # Sends an API call to JIRA, with or without a request body

    param(
        [string]$apiBaseUrl,                 # API base URL
        [object]$bodyObject = $null,         # Object to be sent in the request body as JSON
        [object]$clientCertificate = $null,  # Client certificate object
        [string]$method = "GET",             # HTTP method GET, PUT, POST, DELETE, etc.
        [string]$target,                     # ReST API target after the base endpoint URL (e.g. "teams/ID")
        [string]$token,                      # ReST API token
        [Microsoft.PowerShell.Commands.WebRequestSession]$session = $null   # WebSession object either created or output
    )

    # Stores the output
    $apiResponse = New-Object –TypeName PSObject
    $apiResponse | Add-Member -MemberType NoteProperty -Name Result -Value $null -TypeName [System.Bool]
    $apiResponse | Add-Member -MemberType NoteProperty -Name StatusCode -Value $null -TypeName [System.Int32]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Content -Value $null -TypeName [System.String]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Info -Value $null -TypeName [System.String]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Session -Value $null -TypeName [Microsoft.PowerShell.Commands.WebRequestSession]
    $apiResponse | Add-Member -MemberType NoteProperty -Name Color -Value $null -TypeName [System.String]

    # Set the full request URI
    if (-Not $apiBaseUrl.EndsWith("/")) {
        $apiBaseUrl = $apiBaseUrl + "/"
    }
    $requestUri = $apiBaseUrl + $target

    # Create the headers
    $headers = @{
        "Authorization" = "Bearer $token"
        "Accept" = "application/json"
    }

    # Create the web session to store the cookies if not provided
    if ($null -eq $session) {
        #Write-Host "DEBUG: No WebSession provided, creating a new WebSession..."
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    } else {
        #Write-Host "DEBUG: Using the provided WebSession object..."
    }

    # Create the dashboard cookie and add it to the session
    $dashboardCookie = New-Object System.Net.Cookie('dashboard','yes','/','jira.arcus.mil')
    $consentCookie = New-Object System.Net.Cookie('consent','true','/','jira.arcus.mil')
    $session.Cookies.Add($dashboardCookie)
    $session.Cookies.Add($consentCookie)

    # Convert the object to JSON and set it as the request body
    $jsonBody = $null
    if ($null -ne $bodyObject) {
        $jsonBody = ConvertTo-Json $bodyObject -Depth 10 -Compress
    }

    # Output message
    $msg = ""

    # Making the HTTP request
    Write-Host "INFO: Making [$method] request to URI [$requestUri]..."
    #Show-Headers -headers $headers

    try
    {
        if (($null -ne $jsonBody) -And ($null -ne $clientCertificate)) {
            # Send the request with a client certificate and a JSON request body
            #Write-Host "DEBUG: Sending request with client certificate:`n$clientCertificate"
            #Write-Host "DEBUG: Sending request with a client certificate and body JSON:`n$jsonBody"
            $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -Certificate $clientCertificate -Body $jsonBody -ContentType "application/json; charset=utf-8" -WebSession $session
        }
        elseif (($null -eq $jsonBody) -And ($null -ne $clientCertificate)) {
            # Send the request with a client certificate without a JSON request body
            #Write-Host "DEBUG: Sending request with client certificate:`n$clientCertificate"
            #Write-Host "DEBUG: Sending request with a client certificate without a body..."
            $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -Certificate $clientCertificate -WebSession $session
        }
        elseif (($null -ne $jsonBody) -And ($null -eq $clientCertificate)) {
            # Send the request without a client certificate and with a JSON request body
            #Write-Host "DEBUG: Sending request without a client certificate and with a body JSON:`n$jsonBody"
            $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -Body $jsonBody -ContentType "application/json; charset=utf-8" -WebSession $session
        }
        else {
            # Send the request without a client certificate and without a JSON request body
            #Write-Host "DEBUG: Sending request without a client certificate and without a JSON body..."
            $serverResponse = Invoke-WebRequest $requestUri -Method $method -Headers $headers -WebSession $session
        }


        # Set the apiResponse object to the successful state
        $apiResponse.Result = $true
        $apiResponse.Color = "Green"
        $apiResponse.StatusCode = $serverResponse.StatusCode
        $apiResponse.Content = $serverResponse.Content

        # Set the message
        $msg += "INFO: [$method] request to URI [$requestUri] returned status code: [$($apiResponse.StatusCode)]"
    } catch {

        # Handle failed API calls

        # Set the apiResponse object to failed state
        $apiResponse.Result = $false
        $apiResponse.Color = "Green"
        $apiResponse.StatusCode = $_.Exception.Response.StatusCode.value__
        $apiResponse.Content = "Exception:`n" + $_.Exception.Message

        $streamReader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        $errorContent = $streamReader.ReadToEnd() | ConvertFrom-Json
        foreach ($errorMessage in $errorContent.errorMessages) {
            $apiResponse.Content += "`nHTTP Error Response:: $($errorMessage)"
        }
        $streamReader.Close()

        # Set the error message
        if ($null -eq $apiResponse.StatusCode) {
            $msg += "ERROR: [$method] request to URI [$requestUri] encountered an error (probably no http status code)"
        } else {
            $msg += "ERROR: [$method] request to URI [$requestUri] returned error code: [$($apiResponse.StatusCode)]"
        }
    }

    # Add content to the output message if it exists
    if ($null -ne $apiResponse.Content) {
        $msg += "`nINFO: Response Output:`n`n$($apiResponse.Content)`n`n"
    }

    # Set the info message and WebSession
    $apiResponse.Info = $msg
    $apiResponse.Session = $session

    # Print the message and return
    Write-Host $msg -ForegroundColor $apiResponse.Color

    # Print the cookies for DEBUG
    #Show-Cookies -webSession $mainSession -url $script:baseUrl

    return $apiResponse
}

function Show-Cookies() {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$webSession,        # WebSession object either created or output
        [string]$url                                                         # URL to get cookies for
    )
    Write-Host "DEBUG: Printing cookies from user agent: $($webSession.UserAgent)"

    if ($null -eq $websession.Cookies) {
        Write-Host "DEBUG: No cookies found in web session"
    }

    $cookies = $websession.Cookies.GetCookies($url)

    foreach ($cookie in $cookies) {
        Write-Host "DEBUG: $($cookie.Name) = $($cookie.Value)"
   }
}

function Show-Headers() {
    param(
        [Hashtable]$headers         # Hashtable of headers
    )
    Write-Host "DEBUG: Sending request with headers: "
    foreach ($key in $headers.Keys) {
        if ($key -eq "token" -or $key -eq "Authorization") {
            $lastSixTokenChars = $headers[$key][-6..-1] -join ''
            Write-Host "DEBUG: Header: $key = (ends with) $lastSixTokenChars"
        } else {
            Write-Host "DEBUG: Header: $key = $($headers[$key])"
        }
    }
}



##########################################################
# Main
##########################################################

function Main() {
    Write-Host "`nINFO: Running the jira.ps1 script..."

    ###########################################################################
    # Get the Jira Token and Client Auth Certificate
    ###########################################################################

    # Get the Jira Personal Access TOken
    $jiraPersonalAccessToken = Get-Token

    # Ensure jiraPersonalAccessToken is set
    if (($null -eq $jiraPersonalAccessToken) -Or ("" -eq $jiraPersonalAccessToken)) {
        Write-Host "ERROR: Jira Personal Access Token not specified, please type the Jira Jira Personal Access Token when prompted" -foregroundColor Red
        exit 1
    }

    # Get the client authentication certificate, prompt user to select
    $cert = Select-Certificate
    if ($null -eq $cert) {
        Write-Host "ERROR: Problem selecting a client certificate" -foregroundColor Red
        exit 1
    }

    # Prompt the user for a project
    Write-Host "`n#########################################################################`n" -foregroundColor Yellow
    $jiraProject = Read-Host -Prompt "What is your Jira project key? (e.g. TM2PRJ)"
    Write-Host "`n"

    # Ensure jiraProject is set
    if (($null -eq $jiraProject) -Or ("" -eq $jiraProject)) {
        Write-Host "ERROR: Jira project not specified, please type the Jira Project Key when prompted" -foregroundColor Red
        exit 1
    }

    # Prompt the user for a username
    $jiraUsername = Read-Host -Prompt "What is your Jira username?"
    Write-Host "`n"

    # Ensure jiraProject is set
    if (($null -eq $jiraUsername) -Or ("" -eq $jiraUsername)) {
        Write-Host "ERROR: Jira username not specified, please type the Jira username when prompted" -foregroundColor Red
        exit 1
    }

    ###########################################################################
    # Send the initial request to generate a session object
    ###########################################################################

    # Initial Request
    $initialResponse = Send-Initial-Request -apiBaseUrl $script:baseUrl -Token $jiraPersonalAccessToken -clientCertificate $cert
    $mainSession = $initialResponse.Session

    # Check the result
    if ($initialResponse.Result -eq $false) {
        Write-Host "ERROR: Problem getting the initial query and response from: [$script:baseUrl/$script:projectTarget]" -foregroundColor Red
        exit 2
    }

    ###########################################################################
    # Query a list of projects
    ###########################################################################

    Write-Host "`n#########################################################################" -foregroundColor Yellow
    Write-Host "#                 Sample: Listing Projects" -foregroundColor Yellow
    Write-Host "#########################################################################" -foregroundColor Yellow

    # send the project request
    $projectResponse = Send-Request -apiBaseUrl $script:baseUrl -Token $jiraPersonalAccessToken -Method "GET" -Target $script:projectTarget -clientCertificate $cert -session $mainSession
    $mainSession = $projectResponse.Session

    # Check the result
    if ($projectResponse.Result -eq $false) {
        Write-Host "ERROR: Unable to query: [$script:baseUrl/$script:projectTarget]" -foregroundColor Red
        exit 3
    }

    ###########################################################################
    # Query isssues for a specific assignee
    ###########################################################################

    Write-Host "`n#########################################################################" -foregroundColor Yellow
    Write-Host "#             Sample: Query isssues for a specific assignee" -foregroundColor Yellow
    Write-Host "#########################################################################" -foregroundColor Yellow

    # Define the target with parameters
    $targetWithParams = $script:searchTarget + "?jql=assignee=" + $jiraUsername

    # Send the search request
    $searchResponse = Send-Request -apiBaseUrl $script:baseUrl -Token $jiraPersonalAccessToken -Method "GET" -Target $targetWithParams -clientCertificate $cert -session $mainSession
    $mainSession = $searchResponse.Session

    # Check the result
    if ($searchResponse.Result -eq $false) {
        Write-Host "ERROR: Unable to query: [$script:baseUrl/$targetWithParams]" -foregroundColor Red
        exit 3
    }

    ###########################################################################
    # List Issues with Attachments in a Project
    ###########################################################################

    Write-Host "`n#########################################################################" -foregroundColor Yellow
    Write-Host "#           Sample: List Issues with Attachments in a Project" -foregroundColor Yellow
    Write-Host "#########################################################################" -foregroundColor Yellow

    # Define the target with paramers, and URL encode it
    $targetWithParams = $script:searchTarget + "?jql=project%20%3D%20$jiraProject%20AND%20NOT%20attachments%20is%20EMPTY&fields=attachment&maxResults=1000"

    # send the attachment request
    $attachmentResponse = Send-Request -apiBaseUrl $script:baseUrl -Token $jiraPersonalAccessToken -Method "GET" -Target $targetWithParams -clientCertificate $cert -session $mainSession
    $mainSession = $attachmentResponse.Session

    # Check the result
    if ($attachmentResponse.Result -eq $false) {
        Write-Host "ERROR: Unable to query: [$script:baseUrl/$targetWithParams]" -foregroundColor Red
        exit 3
    }

    ###########################################################################
    # Create an issue
    ###########################################################################

    Write-Host "`n#########################################################################" -foregroundColor Yellow
    Write-Host "#                     Sample: Create an issue" -foregroundColor Yellow
    Write-Host "#########################################################################" -foregroundColor Yellow

    $targetWithParams = $script:issueTarget + "/"

    # Create the Issue data
    $issueBodyData = @{
        "fields" = @{
            "description" = "Creating of an issue using project keys and issue type names using the REST API"
            "issuetype" = @{
                "name" = "Bug"
            }
            "project" = @{
                "key" = $jiraProject
            }
            "summary" = "Created a test issue using the ReST API with Powershell."
        }
    }

    # Send the request to create an issue
    $issueResponse = Send-Request -apiBaseUrl $script:baseUrl -Token $jiraPersonalAccessToken -Method "POST" -Target $targetWithParams -bodyObject $issueBodyData -clientCertificate $cert -session $mainSession
    $mainSession = $issueResponse.Session

    # Check the result
    if ($issueResponse.Result -eq $false) {
        Write-Host "ERROR: Unable to create an issue: [$script:baseUrl/$targetWithParams]" -foregroundColor Red
        exit 3
    }

    Write-Host "INFO: Completed running: jira.ps1, exiting with success`n"
}

##########################################################
# Script Execution
#########################################################

# Execute the Main function
Main

# Exit with code 0 if no errors detected
exit 0
