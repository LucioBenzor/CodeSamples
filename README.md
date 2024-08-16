# CodeSamples
 
*Add-DLPSenerExclusions.ps1* - This script iterates through Microsoft DLP rules and adds an exclusion to policies assigned against Exchange

 *Removewhfb_fromgroup.ps1* -
 This script is meant to iterate over an azure AD group of users to remove the windows hello for business auth method assocaited with their accounts. 

*SummarizeNTLM logins.kql* - This query grabs the last 7 days of logins using the NTLM protocol. (Advanced Hunting and Sentinel)

*GrantAVScanPermission.ps1* - The Microsoft Sentinel playbook *Run MDE Antivirus - Incident Triggered* requires specific MDE permissions to run. The only way to endow permissions to a managed identity is via the CLI. This Powershell script improves on the instructions presented on the Azure portal.

*GrantAVScanPermission-MI.ps1* - This github copilot-generated script is an improvement on my own *GrantAVScanPermission.ps1* script by removing redundant code by creating a loop and adding a function to do the heavy lifting
