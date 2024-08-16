#Connect to Azure AD (feel free to ingore if you wish)
#Connect-AzureAD

#Create variables for the Managed Identity and retrieve the Managed Identity object
$MIGuid = '<Insert ObjectID of Managed Identity Here>'
$MI = Get-AzureADServicePrincipal -ObjectId $MIGuid

#Define the MDE App ID and retrieve the MDE Service Principal
$MDEAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$MDEServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$MDEAppId'" 

#Assign the 'Machine.Scan' Role to the Managed Identity
$PermissionName = 'Machine.Scan'
$AppRole = $MDEServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains 'Application'}
New-AzureAdServiceAppRoleAssignment -ObjectId $MI.ObjectId -PrincipalId $MI.ObjectId -ResourceId $MDEServicePrincipal.ObjectId -Id $AppRole.Id

#Assign the 'Machine.Read.All' Role to the Managed Identity
$PermissionName = 'Machine.Read.All'
$AppRole = $MDEServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains 'Application'}
New-AzureAdServiceAppRoleAssignment -ObjectId $MI.ObjectId -PrincipalId $MI.ObjectId -ResourceId $MDEServicePrincipal.ObjectId -Id $AppRole.Id

#Assign the 'Machine.ReadWrite.All' Role to the Managed Identity
$PermissionName = 'Machine.ReadWrite.All'
$AppRole = $MDEServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains 'Application'}
New-AzureAdServiceAppRoleAssignment -ObjectId $MI.ObjectId -PrincipalId $MI.ObjectId -ResourceId $MDEServicePrincipal.ObjectId -Id $AppRole.Id