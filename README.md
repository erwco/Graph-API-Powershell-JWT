# New-GraphApiJwt PowerShell Function

## Overview

The `New-GraphApiJwt` function is a PowerShell script to authenticate with Microsoft Graph API using a self-signed JWT (JSON Web Token) created from a local certificate. This function allows you to obtain an access token for Microsoft Graph API using the certificate-based client credential authentication flow.

## Prerequisites

1. **PowerShell**: Windows PowerShell 5.0 or higher.
2. **Microsoft Graph API Access**: You must have access to Microsoft Graph API with application permissions. [How to register an app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
3. **Certificate**: The function requires a certificate stored locally. You can create a self signed certificate as explained in [This section](#create-a-self-signed-certificate) or use a proper CA and import it in your Azure app as explained [Here](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#option-1-recommended-upload-a-trusted-certificate-issued-by-a-certificate-authority).

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
```powershell
$certName = 'NAME_OF_THE_CERTIFICATE'
$certPassword = 'VERY_STRONG_PASSWORD_FOR_THE_PRIVATE_KEY'
$validFor = 2 # Number of year for the certificate validity


# Create the certificate
$cert = New-SelfSignedCertificate -Subject "CN=$certName" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256  -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter ([datetime]::Now.AddYears($validFor))

# Export public key
Export-Certificate -Cert $cert -FilePath "C:\Users\$env:USERNAME\Downloads\$($certname)_256_public.cer"

# Export private key
$secureStringPassword = ConvertTo-SecureString -String $certPassword -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "C:\Users\$env:USERNAME\Downloads\$($certname)_256_private.pfx" -Password $secureStringPassword -CryptoAlgorithmOption AES256_SHA256

# Optional to delete the key from your computer
Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
```
