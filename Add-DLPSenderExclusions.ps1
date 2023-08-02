
# Install required module if not already installed
if (!(Get-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue)) {
    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
}

Import-Module ExchangeOnlineManagement

# Connect to Security & Compliance Center (You might need to provide credentials)
Connect-IPPSSession

# Function to get the Compliance Policies from DLP
function Get-DLPCompliancePolicies {
    Get-DlpCompliancePolicy
}

# Function to add domain exclusions to a DLP policy
function Add-DLPDomainExclusions {
    param (
        [string]$PolicyId,
        [string[]]$Domains
    )
    foreach ($domain in $Domains) {
        Set-DlpComplianceRule -Identity $PolicyId -ExceptIfSenderDomainIs $domain
        Write-Host "Exclusion added for domain: $domain"
    }
}

# Main script to iterate through Compliance Policies and add domain exclusions
try {
    # Get all Compliance Policies
    $policies = Get-DLPCompliancePolicies

    if ($policies) {
        # Iterate through each policy
        foreach ($policy in $policies) {
            $policyName = $policy.Name
            $policyId = $policy.Id
            $policyState = $policy.IsEnabled

            Write-Host "Policy Name: $policyName"
            Write-Host "Policy ID: $policyId"
            Write-Host "Policy State: $policyState"

            # Add domain exclusions for each policy
            $domainsToAdd = @("uga.edu", "miami.edu", "gatech.edu")
            Add-DLPDomainExclusions -PolicyId $policyId -Domains $domainsToAdd

            Write-Host "Exclusions added for uga.edu, miami.edu, gatech.edu"
            Write-Host "------------------------"
        }
    } else {
        Write-Host "No Compliance Policies found in DLP."
    }
}
catch {
    Write-Host "Error occurred: $_.Exception.Message"
}
finally {
    # Disconnect from Exchange Online
    Disconnect-ExchangeOnline
}

# Pause the script execution to prevent the console window from closing
Read-Host -Prompt "Press Enter to exit."
