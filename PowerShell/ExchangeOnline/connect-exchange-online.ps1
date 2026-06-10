```powershell
<#
.SYNOPSIS
Connects to Exchange Online PowerShell.

.DESCRIPTION
Installs the ExchangeOnlineManagement module if needed, imports the module,
and connects to Exchange Online using an admin account.

.NOTES
Replace placeholder values before running in a real environment.
Do not upload real tenant, admin, or organization details to a public GitHub repo.
#>

# Check if ExchangeOnlineManagement module is installed
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Write-Host "ExchangeOnlineManagement module not found. Installing..." -ForegroundColor Yellow
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}

# Import module
Import-Module ExchangeOnlineManagement

# Prompt for admin account
$AdminUPN = Read-Host "Enter your Exchange Online admin UPN"

# Connect to Exchange Online
Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false
```
