# Function to assign a role to a Managed Identity
function Assign-AppRole {
    param (
        [string]$MIObjectId,
        [string]$MDEServicePrincipalObjectId,
        [string]$PermissionName
    )

    $AppRole = $MDEServicePrincipal.AppRoles | Where-Object {
        $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains 'Application'
    }

    if ($AppRole) {
        New-AzureAdServiceAppRoleAssignment -ObjectId $MIObjectId -PrincipalId $MIObjectId `
            -ResourceId $MDEServicePrincipalObjectId -Id $AppRole.Id
    } else {
        Write-Host "App role '$PermissionName' not found."
    }
}

# Create variables for the Managed Identity and retrieve the Managed Identity object
$MIGuid = '<Insert ObjectID of Managed Identity Here>'
$MI = Get-AzureADServicePrincipal -ObjectId $MIGuid

# Define the MDE App ID and retrieve the MDE Service Principal
$MDEAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$MDEServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$MDEAppId'"

# Assign roles to the Managed Identity
$roles = @('Machine.Scan', 'Machine.Read.All', 'Machine.ReadWrite.All')
foreach ($role in $roles) {
    Assign-AppRole -MIObjectId $MI.ObjectId -MDEServicePrincipalObjectId $MDEServicePrincipal.ObjectId -PermissionName $role
}