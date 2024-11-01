
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates
using namespace System.Text

function New-GraphApiJwt
{
	param
	(
		# Base function to get a token from the Graph API using a certificate from local store
		$TenantID,
		$AppId,
		$CertificatePath
	)
	
	$scope = "https://graph.microsoft.com/.default"

    # Get the certificate from store
    $certificate = Get-Item $certificatePath -ErrorAction Stop

    # Create base64 hash of certificate
    $certificateBase64Hash = [Convert]::ToBase64String($certificate.GetCertHash())

    # Create JWT timestamp for expiration
    $startDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $jWTExpirationTimeSpan = (New-TimeSpan -Start $startDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $jWTExpiration = [math]::Round($jWTExpirationTimeSpan,0)

    # Create JWT validity start timestamp
    $notBeforeExpirationTimeSpan = (New-TimeSpan -Start $startDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $notBefore = [math]::Round($notBeforeExpirationTimeSpan,0)

    # Create JWT header
    $jWTHeader = @{
        alg = "RS256"
        typ = "JWT"
        x5t = $certificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
    }

    # Create JWT payload
    $jWTPayLoad = @{
        aud = "https://login.microsoftonline.com/$tenantID/oauth2/token" # What endpoint is allowed to use this JWT
        exp = $jWTExpiration # Expiration timestamp
        iss = $appId # Issuer
        jti = [guid]::NewGuid() # JWT ID: random guid
        nbf = $notBefore # Not to be used before
        sub = $appId # JWT Subject
    }

    # Convert header and payload to base64
    $jWTHeaderToByte = [Encoding]::UTF8.GetBytes(($jWTHeader | ConvertTo-Json -Compress))
    $encodedHeader = [Convert]::ToBase64String($jWTHeaderToByte)

    $jWTPayLoadToByte =  [Encoding]::UTF8.GetBytes(($jWTPayload | ConvertTo-Json -Compress))
    $encodedPayload = [Convert]::ToBase64String($jWTPayLoadToByte)

    # Join header and Payload with "." to create a valid (unsigned) JWT
    $jWT = $encodedHeader + "." + $encodedPayload

    # Get the private key object of your certificate
    $privateKey = [RSACertificateExtensions]::GetRSAPrivateKey( $certificate )

    # Create a signature of the JWT
    $signature = [Convert]::ToBase64String(
        $privateKey.SignData([Encoding]::UTF8.GetBytes($jWT),[HashAlgorithmName]::SHA256,[RSASignaturePadding]::Pkcs1)
    ) -replace '\+','-' -replace '/','_' -replace '='

    # Join the signature to the JWT with "."
    $jWT = $jWT + "." + $signature

    # Create a hash with body parameters
    $body = @{
        client_id = $appId
        client_assertion = $jWT
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        scope = $scope
        grant_type = "client_credentials"
    }

    # Use the self-generated JWT as Authorization
    $header = @{
        Authorization = "Bearer $jWT"
    }

    # Splat the parameters for Invoke-Restmethod for cleaner code
    $postSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        Body = $body
        Uri = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"
        Headers = $header
    }

    $request = Invoke-RestMethod @postSplat

    # Return the access token
    return $request.access_token
}

Export-ModuleMember -Function New-GraphApiJwt