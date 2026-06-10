```powershell
<#
.SYNOPSIS
Inbox rule investigation commands for Exchange Online.

.DESCRIPTION
Use these commands to review inbox rules, identify suspicious/malicious rules,
check rule details, export results, and remove malicious inbox rules.

.NOTES
Run Connect-ExchangeOnline before using these commands.
Replace user@domain.com with the mailbox you are investigating.
Replace "malicious rule name" with the actual inbox rule name.
Do not upload real tenant data, mailbox data, or exported results to GitHub.
#>

# ==========================================================
# Query 1: Find inbox rules for one mailbox
# TYPE THE USER EMAIL BELOW
# Example: user@domain.com
# ==========================================================

$MailboxUPN = "user@domain.com"

Get-InboxRule -Mailbox $MailboxUPN |
Select-Object Name,
              Description,
              Enabled,
              Identity |
Format-Table -AutoSize


# ==========================================================
# Query 2: Get full details of a suspicious or malicious rule
# TYPE THE USER EMAIL AND RULE NAME BELOW
# Example Rule Name: "Forward All Messages"
# ==========================================================

$MailboxUPN = "user@domain.com"
$RuleName = "malicious rule name"

Get-InboxRule -Mailbox $MailboxUPN -Identity $RuleName |
Format-List


# ==========================================================
# Query 3: Find suspicious inbox rules for one mailbox
# Looks for forwarding, redirect, delete, mark-as-read, or move rules
# TYPE THE USER EMAIL BELOW
# ==========================================================

$MailboxUPN = "user@domain.com"

Get-InboxRule -Mailbox $MailboxUPN |
Where-Object {
    $_.ForwardTo -or
    $_.ForwardAsAttachmentTo -or
    $_.RedirectTo -or
    $_.DeleteMessage -eq $true -or
    $_.MarkAsRead -eq $true -or
    $_.MoveToFolder
} |
Select-Object Name,
              Enabled,
              Description,
              ForwardTo,
              ForwardAsAttachmentTo,
              RedirectTo,
              DeleteMessage,
              MarkAsRead,
              MoveToFolder,
              StopProcessingRules |
Format-List


# ==========================================================
# Query 4: Export inbox rules for one mailbox
# TYPE THE USER EMAIL BELOW
# Export will save to your Desktop
# ==========================================================

$MailboxUPN = "user@domain.com"
$ExportPath = "$env:USERPROFILE\Desktop\InboxRules-$($MailboxUPN.Replace('@','_')).csv"

Get-InboxRule -Mailbox $MailboxUPN |
Select-Object MailboxOwnerId,
              Name,
              Enabled,
              Description,
              ForwardTo,
              ForwardAsAttachmentTo,
              RedirectTo,
              DeleteMessage,
              MarkAsRead,
              MoveToFolder,
              StopProcessingRules |
Export-Csv -Path $ExportPath -NoTypeInformation

Write-Host "Export completed: $ExportPath"


# ==========================================================
# Query 5: Remove a malicious inbox rule
# TYPE THE USER EMAIL AND RULE NAME BELOW
# Be careful: this deletes the inbox rule
# ==========================================================

$MailboxUPN = "user@domain.com"
$RuleName = "malicious rule name"

Remove-InboxRule -Mailbox $MailboxUPN -Identity $RuleName


# ==========================================================
# Query 6: Remove a malicious inbox rule without confirmation
# TYPE THE USER EMAIL AND RULE NAME BELOW
# Be careful: this deletes the inbox rule without asking
# ==========================================================

$MailboxUPN = "user@domain.com"
$RuleName = "malicious rule name"

Remove-InboxRule -Mailbox $MailboxUPN -Identity $RuleName -Confirm:$false


# ==========================================================
# Query 7: Search all mailboxes for forwarding or redirect rules
# No user email needed
# Export will save to your Desktop
# ==========================================================

$ExportPath = "$env:USERPROFILE\Desktop\All-Mailbox-Forwarding-InboxRules.csv"

$Results = foreach ($Mailbox in Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox) {
    Write-Host "Checking mailbox: $($Mailbox.UserPrincipalName)"

    Get-InboxRule -Mailbox $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ForwardTo -or
        $_.ForwardAsAttachmentTo -or
        $_.RedirectTo
    } |
    Select-Object @{Name="Mailbox";Expression={$Mailbox.UserPrincipalName}},
                  Name,
                  Enabled,
                  Description,
                  ForwardTo,
                  ForwardAsAttachmentTo,
                  RedirectTo,
                  StopProcessingRules
}

$Results | Export-Csv -Path $ExportPath -NoTypeInformation
Write-Host "Export completed: $ExportPath"


# ==========================================================
# Query 8: Search all mailboxes for external forwarding rules
# TYPE YOUR INTERNAL DOMAINS BELOW
# Example: domain.com and contoso.onmicrosoft.com
# ==========================================================

$InternalDomains = @(
    "domain.com",
    "contoso.onmicrosoft.com"
)

$ExportPath = "$env:USERPROFILE\Desktop\External-Forwarding-InboxRules.csv"

$Results = foreach ($Mailbox in Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox,SharedMailbox) {
    Write-Host "Checking mailbox: $($Mailbox.UserPrincipalName)"

    $Rules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ForwardTo -or
        $_.ForwardAsAttachmentTo -or
        $_.RedirectTo
    }

    foreach ($Rule in $Rules) {
        $Targets = @(
            $Rule.ForwardTo
            $Rule.ForwardAsAttachmentTo
            $Rule.RedirectTo
        ) | Where-Object { $_ }

        $TargetString = ($Targets | ForEach-Object { $_.ToString() }) -join "; "
        $IsExternal = $false

        foreach ($Target in $Targets) {
            $TargetText = $Target.ToString()

            if ($TargetText -match "@") {
                $IsInternal = $false

                foreach ($Domain in $InternalDomains) {
                    if ($TargetText -match "@$([regex]::Escape($Domain))\b") {
                        $IsInternal = $true
                    }
                }

                if (-not $IsInternal) {
                    $IsExternal = $true
                }
            }
        }

        if ($IsExternal) {
            [PSCustomObject]@{
                Mailbox               = $Mailbox.UserPrincipalName
                RuleName              = $Rule.Name
                Enabled               = $Rule.Enabled
                Description           = $Rule.Description
                ForwardTo             = $Rule.ForwardTo -join "; "
                ForwardAsAttachmentTo = $Rule.ForwardAsAttachmentTo -join "; "
                RedirectTo            = $Rule.RedirectTo -join "; "
                TargetString          = $TargetString
                StopProcessingRules   = $Rule.StopProcessingRules
            }
        }
    }
}

$Results | Export-Csv -Path $ExportPath -NoTypeInformation
Write-Host "Export completed: $ExportPath"
```
