# ListVulnsByDeviceGroup

The purpose of this script is to perform a POC of MDE's ability to list device vulnerabilities via Device tags. This script works by

1. Quering the Defender for Endpoint API to get devices with a certain tag
2. Creating a nested group in memory with the results
3. Iterating through those devices in that list and listing the vulnerabilities for each

## Key requirement

In order for this script to run, it requires creating a Service principal. This SP requires the following API permissions from the WindowsDefenderATP APIs
* Machine.Read.All
* Vulnerability.Read.All

Go to Certificates and Secrets and generate a secret

## How to run

Download the ps1 file, add your tenantID, the clientID and Secret of the SP and the deviceTag from MDE you'd like to query.
