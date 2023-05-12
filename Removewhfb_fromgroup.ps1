
# Description: This script removes Windows Hello for Business authentication for all users in a group.

# Import the AzureAD module
Import-Module AzureAD
Import-Module -Name Az.Accounts
Import-Module -Name Az.Resources
Import-Module -Name Microsoft.Graph.Authentication

# Define the variables
$clientId = "<your_client_id>"
$clientSecret = "<your_client_secret>"
$tenantId = "<your_tenant_id>"
$groupId = "<your_group_id>"

# Authenticate and get the access token
$authUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$body = @{
    grant_type    = "client_credentials"
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$authResponse = Invoke-RestMethod -Uri $authUrl -Method POST -Body $body
$accessToken = $authResponse.access_token

# Define the function to delete the Windows Hello for Business authentication method
function RemoveWindowsHelloForBusinessMethod($userId, $methodId) {
    $url = "https://graph.microsoft.com/v1.0/users/$userId/authentication/windowsHelloForBusinessMethods/$methodId"
    $headers = @{
        "Authorization" = "Bearer $accessToken"
    }
    Invoke-RestMethod -Uri $url -Method DELETE -Headers $headers
}

# Get the list of users in the group
$usersUrl = "https://graph.microsoft.com/v1.0/groups/$groupId/members?$select=id"
$usersResponse = Invoke-RestMethod -Uri $usersUrl -Method GET -Headers $headers
$users = $usersResponse.value

# Remove Windows Hello for Business authentication for each user
foreach ($user in $users) {
    $userId = $user.id
    $methodsUrl = "https://graph.microsoft.com/v1.0/users/$userId/authentication/windowsHelloForBusinessMethods"
    $methodsResponse = Invoke-RestMethod -Uri $methodsUrl -Method GET -Headers $headers
    $methods = $methodsResponse.value
    
    foreach ($method in $methods) {
        $methodId = $method.id
        RemoveWindowsHelloForBusinessMethod $userId $methodId
    }
}

Write-Host "Windows Hello for Business authentication removed successfully for all users in the group."
