# New-GraphApiJwt PowerShell Function

## Overview

The `New-GraphApiJwt` function is a PowerShell script to authenticate with Microsoft Graph API using a self-signed JWT (JSON Web Token) created from a local certificate. This function allows you to obtain an access token for Microsoft Graph API using the certificate-based client credential authentication flow.

## Prerequisites

1. **PowerShell**: Windows PowerShell 5.0 or higher.
2. **Microsoft Graph API Access**: You must have access to Microsoft Graph API with application permissions. [How to register an app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
3. **Certificate**: The function requires a certificate stored locally. You need to create a self signed certificate as explained in [This section](#create-a-self-signed-certificate).

## Usage

### Parameters

| Parameter       | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| `$TenantID`     | Your Azure AD tenant ID.                                                    |
| `$AppId`        | The Application (client) ID of the Azure AD app registration.               |
| `$CertificatePath` | The path to your certificate file, such as `Cert:\CurrentUser\My\{Thumbprint}`. |

### Function Definition

This function does the following:
- Retrieves a certificate from the specified local path.
- Generates a JWT header and payload for the Graph API using the RS256 algorithm.
- Signs the JWT with the private key from the certificate.
- Sends a POST request to Microsoft Graph to obtain an access token.

### Example

```powershell
# Define the parameters
$TenantID = "your-tenant-id"
$AppId = "your-app-client-id"
$certificateThumbprint ="your-certificate-thumbprint"

$CERT_PATH = [System.IO.Path]::Combine('Cert:\CurrentUser\My', $certificateThumbprint)
$CertificatePath = "Cert:\CurrentUser\My\{Thumbprint}"

# Run the function
$AccessToken = New-GraphApiJwt -TenantID $TenantID -AppId $AppId -CertificatePath $CertificatePath

$url = "https://graph.microsoft.com/v1.0/users/<USER_ID>"
$authorizationHeader = @{Authorization = "Bearer $($accessToken)"}
$getRequest = Invoke-WebRequest -Method GET -Uri $url -headers $authorizationHeader -ContentType "application/json" -UseBasicParsing
```
## Create a self signed certificate
