# =====================[ CONFIGURATION ]=====================
$tenantId     = "TenantId"  # Replace with your actual tenant ID
$clientId     = "ClientId"  # Replace with your actual client ID
$clientSecret = "ClientSecret"  # Replace with your actual client secret
$tagName      = "Tag"  # Change to your desired tag

# =====================[ AUTHENTICATION ]====================
Write-Host "Authenticating to Microsoft Defender for Endpoint API..."

$authBody = @{
    grant_type    = "client_credentials"
    scope         = "https://api.securitycenter.microsoft.com/.default"
    client_id     = $clientId
    client_secret = $clientSecret
}

$tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $authBody
$accessToken = $tokenResponse.access_token

$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# =====================[ QUERY DEVICES BY TAG ]====================
Write-Host "Querying devices with tag '$tagName'..."

# Filter with OData to avoid over-fetching
$filter = "machineTags/any(t: t eq '$tagName')"
$uri = "https://api.securitycenter.microsoft.com/api/machines?`$filter=$filter"

$devicesWithTag = @()
do {
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    $devicesWithTag += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

Write-Host "Found $($devicesWithTag.Count) device(s) with tag '$tagName'."


# =====================[ CREATE GROUP STRUCTURE ]====================
$deviceGroup = @{
    Tag     = $tagName
    Devices = @()
}

foreach ($device in $devicesWithTag) {
    $deviceGroup.Devices += @{
        DeviceName = $device.computerDnsName
        DeviceId   = $device.id
    }
}

# =====================[ FETCH VULNERABILITIES ]====================
foreach ($device in $deviceGroup.Devices) {
    Write-Host "`n==[ Vulnerabilities for: $($device.DeviceName) ]=="

    $vulnUri = "https://api.securitycenter.microsoft.com/api/machines/$($device.DeviceId)/vulnerabilities"

    try {
        $vulnerabilities = Invoke-RestMethod -Uri $vulnUri -Headers $headers -Method Get
        if ($vulnerabilities.value.Count -eq 0) {
            Write-Host " - No vulnerabilities found."
        } else {
            foreach ($vuln in $vulnerabilities.value) {
                Write-Host " - [$($vuln.severity)] $($vuln.name): $($vuln.description)"
            }
        }
    } catch {
        Write-Warning "Failed to get vulnerabilities for $($device.DeviceName): $_"
    }
}
