#Initialize default properties
$p = $person | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json

# The entitlementContext contains the domainController, adUser, configuration, exchangeConfiguration and exportData
# - domainController: The IpAddress and name of the domain controller used to perform the action on the account
# - adUser: Information about the adAccount: objectGuid, samAccountName and distinguishedName
# - configuration: The configuration that is set in the Custom PowerShell configuration
# - exchangeConfiguration: The configuration that was used for exchange if exchange is turned on
# - exportData: All mapping fields where 'Store this field in person account data' is turned on
$eRef = $entitlementContext | ConvertFrom-Json
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

#region Disable the ActiveSync on Mailbox new user
$Domaincontroller = Get-ADDomain | Select-Object -Property PDCEmulator

$currentUser = Get-ADUser $eRef.adUser.ObjectGuid

if (-Not($dryRun -eq $True)) {
    Try{
        $adUser = $currentUser.samaccountname   
        Set-CASMailbox -Identity $adUSer -ActiveSyncEnabled $false -OWAEnabled $false -OWAforDevicesEnabled $false -DomainController $($Domaincontroller.PDCEmulator)
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
            Action  = "CreateAccount"
            Message = "Successfully disabled ActiveSync and OWA for Devices for user $($p.DisplayName)"
            IsError = $False
                })
    } 
    Catch {
        $success = $False
        $auditLogs.Add([PSCustomObject]@{
            Action  = "CreateAccount"
            Message = "Failed to disabled ActiveSync and OWA for Devices for user $($p.DisplayName). Error: $($_)"
            IsError = $True
                })
            throw $_
    }
}
else {
    # Write dry run logic here
}
#end region Disable the ActiveSync on Mailbox new user


#build up result
$result = [PSCustomObject]@{
    Success   = $success
    AuditLogs = $auditLogs

    # Return data for use in other systems.
    # If not present or empty the default export data will be used
    # ExportData = [PSCustomObject]@{}
}

#send result back
Write-Output $result | ConvertTo-Json -Depth 10