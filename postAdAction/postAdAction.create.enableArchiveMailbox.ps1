#####################################################
# HelloID-Conn-Prov-Target-AD-Post-Action-Create
# Enable archive mailbox for an on-premises user with a remote mailbox in Exchange Online
#
# Version: 1.0.0
#####################################################
#Initialize default properties
$p = $person | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json

# The entitlementContext contains the domainController, adUser, configuration, exchangeConfiguration and exportData
# - domainController: The IpAddress and name of the domain controller used to perform the action on the account
# - adUser: Information about the adAccount: objectGuid, samAccountName and distinguishedName
# - configuration: The configuration that is set in the Custom PowerShell configuration
# - exchangeConfiguration: The configuration that was used for exchange if exchange is turned on
# - exportData: All mapping fields where "Store this field in person account data" is turned on
# - mappedData: The output of the mapping script
# - account: The data available in the notification
$eRef = $entitlementContext | ConvertFrom-Json
$success = $false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# logging preferences
$verbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to AD and Exchange
# Use domain controller from eRef if available, otherwise query primary domain controller
if (-NOT([String]::IsNullOrEmpty($eRef.domainController.Name)) -and -Not($dryRun -eq $true)) {
    $domainController = $eRef.domainController.Name
}
else {
    try {
        $domainController = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
    }
    catch {
        Write-Warning ("PDC Lookup Error: {0}" -f $_.Exception.InnerException.Message)
        Write-Warning "Retrying PDC Lookup"
        $domainController = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
    }
}
Write-Verbose "Post Action - Using Domain Controller: $($domainController)"

# Used to query AD account object
# Use objectGuid from aRef if available, otherwise use objectGuid from eRef 
if (-NOT([String]::IsNullOrEmpty($aRef.ObjectGuid))) {
    $adUserIdentity = $aRef.objectGuid
}
else {
    $adUserIdentity = $eRef.adUser.objectGuid
}
Write-Information "Post Action - Using Identity: $($adUserIdentity)"

try {
    #region Enable archive mailbox for an on-premises user with a remote mailbox in Exchange Online
    # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/enable-remotemailbox?view=exchange-ps
    $actionMessage = "enabling archive mailbox for account with Identity: $($adUserIdentity | ConvertTo-Json)"

    $enableArchiveMailboxSplatParams = @{
        Identity         = $adUserIdentity
        Archive          = $true
        DomainController = $domainController
        Verbose          = $false
        ErrorAction      = "Stop"
    }

    Write-Verbose "SplatParams: $($enableArchiveMailboxSplatParams | ConvertTo-Json)"

    if (-Not($dryRun -eq $true)) {
        $enableArchiveMailboxResponse = Enable-RemoteMailbox @enableArchiveMailboxSplatParams

        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Post Action - Enabled archive mailbox for account with Identity: $($adUserIdentity | ConvertTo-Json)."
                IsError = $true
            })

        # Additional Write-Information required as the auditlogs aren't currently shown in the entitlement history log
        Write-Information "Post Action - Enabled archive mailbox for account with Identity: $($adUserIdentity | ConvertTo-Json)."
    }
    else {
        Write-Warning "Post Action - DryRun: Would enable archive mailbox for account with Identity: $($adUserIdentity | ConvertTo-Json)."
    }
    #endregion Enable archive mailbox for an on-premises user with a remote mailbox in Exchange Online

    # If no errors occurred, set success to true
    $success = $true
}
catch {
    $ex = $PSItem

    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

    if ($auditMessage -like "*Recipient $($enableArchiveMailboxSplatParams.Identity) already has an archive*") {
        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Skipped $($actionMessage). Reason: Recipient already has an archive."
                IsError = $true
            })
    
        # Additional Write-Information required as the auditlogs aren't currently shown in the entitlement history log
        Write-Information "Skipped $($actionMessage). Reason: Recipient already has an archive."

        # Treat existing archive as success
        $success = $true
    }
    else {
        Write-Warning "Post Action - $warningMessage"

        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })
        
        # Additional Write-Warning (do not use Write-Error as this will cause the auditlog to not be displayed) required as the auditlogs aren't currently shown in the entitlement history log
        Write-Warning "Post Action - $auditMessage"
    }
}
finally {
    #build up result
    $result = [PSCustomObject]@{
        Success   = $success
        AuditLogs = $auditLogs

        # Return data for use in other systems.
        # If not present or empty the default export data will be used
        # The $eRef.exportData contains the export data from the mapping which is the default
        # When an object is returned the export data will be overwritten with the provided data
        # ExportData = $eRef.exportData

        # Return data for use in notifications.
        # If not present or empty the default account data will be used
        # When an object is returned this data will be available in the notification
        # Account = $eRef.account
    }

    #send result back
    Write-Output $result | ConvertTo-Json -Depth 10
}