# Install required module if not already installed
if (!(Get-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue)) {
    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
}

Import-Module ExchangeOnlineManagement

# Connect to Security & Compliance Center (You might need to provide credentials)
Connect-IPPSSession

# Function to get the Compliance Policies from DLP
function Get-DLPCompliancePolicies {
    $compliancePolicies = Get-DlpCompliancePolicy
    return $compliancePolicies
}

# Main script to iterate through Compliance Policies
try {
    # Get all Compliance Policies
    $policies = Get-DLPCompliancePolicies

    if ($policies) {
        # Iterate through each policy and display information
        foreach ($policy in $policies) {
            $policyName = $policy.Name
            $policyId = $policy.Id
            $policyState = $policy.IsEnabled

            Write-Host "Policy Name: $policyName"
            Write-Host "Policy ID: $policyId"
            Write-Host "Policy State: $policyState"
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
