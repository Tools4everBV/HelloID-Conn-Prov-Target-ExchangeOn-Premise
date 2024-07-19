##############################################################################
# HelloID-Conn-Prov-Target-Exchange-OnPremise-SubPermissions-SharedMailboxDynamic
# PowerShell V2
##############################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false

# Set debug logging
switch ($($actionContext.Configuration.config.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

#Get Primary Domain Controller
try {
    $pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
}
catch {
    Write-Warning ("PDC Lookup Error: {0}" -f $_.Exception.InnerException.Message)
    Write-Warning "Retrying PDC Lookup"
    $pdc = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
}

#Exchange
$searchBase = $actionContext.Configuration.exchange.sharedMailboxContainer
$ConnectionUri = $actionContext.Configuration.exchange.ConnectionUri
$Username = $actionContext.Configuration.exchange.username
$Password = $actionContext.Configuration.exchange.password
$AuthenticationMethod = $actionContext.Configuration.exchange.authenticationmode

#region Supporting Functions
function Set-PSSession {    
    [OutputType([System.Management.Automation.Runspaces.PSSession])]  
    param(       
        [Parameter(mandatory)]
        [string]$PSSessionName
    )
    try {                        
        $sessionObject = Get-PSSession -ComputerName $env:computername -Name $PSSessionName -ErrorAction stop
        if ($null -eq $sessionObject) {
            # Due to some inconsistency, the Get-PSSession does not always throw an error  
            throw "The command cannot find a PSSession that has the name '$PSSessionName'."
        }
        # To Avoid using mutliple sessions at the same time.
        if ($sessionObject.length -gt 1) {
            Remove-PSSession -Id ($sessionObject.id | Sort-Object | select-object -first 1)
            $sessionObject = Get-PSSession -ComputerName $env:computername -Name $PSSessionName -ErrorAction stop
        }        
        Write-Verbose -Verbose "Remote Powershell session is found, Name: $($sessionObject.Name), ComputerName: $($sessionObject.ComputerName)"
    }
    catch {
        Write-Verbose -Verbose "Remote Powershell session not found: $($_)"
    }

    if ($null -eq $sessionObject) { 
        try {
            $remotePSSessionOption = New-PSSessionOption -IdleTimeout (New-TimeSpan -Minutes 5).TotalMilliseconds
            $sessionObject = New-PSSession -ComputerName $env:computername -EnableNetworkAccess:$true -Name $PSSessionName -SessionOption $remotePSSessionOption
            Write-Verbose -Verbose "Remote Powershell session is created, Name: $($sessionObject.Name), ComputerName: $($sessionObject.ComputerName)"
        }
        catch {
            throw "Couldn't created a PowerShell Session: $($_.Exception.Message)"
        }
    }
    #Write-Verbose -Verbose "Remote Powershell Session '$($sessionObject.Name)' State: '$($sessionObject.State)' Availability: '$($sessionObject.Availability)'"
    if ($sessionObject.Availability -eq "Busy") {
        throw "Remote session is in Use" 
    }
    Write-Output $sessionObject
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message

        Write-Output $errorMessage
    }
}
#endregion Supporting Functions

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{}
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions.Add($permission.Reference.Id, $permission.DisplayName)    
}
# Write-Verbose -Verbose "CurrentPermissions now: $($currentPermissions | Convertto-Json)"
# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
# $subPermissions = New-Object Collections.Generic.List[PSCustomObject]

try {
    try {
        # Determine sub-permissions in condition
        $desiredPermissions = @{}
        
        if (-Not($actionContext.Operation -eq "revoke")) {
            $departmentList = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($contract in $personContext.Person.Contracts) {
                if ($contract.Context.InConditions -or $actionContext.DryRun -eq $true) {                    
                    if ($contract.department.displayName) {
                        $departmentList.Add($($contract.Department.ExternalId))                               
                    }
                    $departmentList = $departmentList | Select-Object -Unique
            
                    foreach ($departmentItem in $departmentList) {                    
                        $sharedMailboxUser = $null;
                        $sharedMailboxUser = Get-ADUser -Filter "department -eq '$departmentItem'" -server $pdc -SearchBase $searchBase -Property ObjectGUID, mailNickName, distinguishedName, displayName
                        if ($null -ne $sharedMailboxUser) {   
                            foreach ($smb in $sharedMailboxUser) {                                                
                                $desiredPermissions["$($smb.ObjectGUID)"] = $($smb.DisplayName)
                            }
                        }            
                    }                    
                }
            }
        }
    }
    catch {
        $ex = $PSItem
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "$($ex.Exception.Message)"
                IsError = $true
            })
        throw $_
    }
    
    Write-Information ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))
    Write-Information ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))
    
    #$actionContext.DryRun = $false

    # Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        # Uncomment when sub-permissions are enabled
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{
                    Id = $permission.Name
                }
            })    
        
        #if ($currentPermissions.ContainsKey("$($permission.Name)")) {
        if ($currentPermissions.ContainsKey($($permission.Name))) {
            Write-Verbose -Verbose "CurrentPermissions already contains $($permission.Name) - $($permission.Value)"
        }

        #if (-Not $currentPermissions.ContainsKey("$($permission.Name)") ){
        if (-Not $currentPermissions.ContainsKey($($permission.Name)) ) {
            Write-Verbose -Verbose "CurrentPermissions doesn't contain $($permission.Name) - $($permission.Value)"
        }

        #if (-Not $currentPermissions.ContainsKey("$($permission.Name)") ){
        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            try {
                if (-Not($actionContext.DryRun -eq $true)) {
                    # Grant AD Groupmembership
                    Write-Verbose -Verbose ("New permission to grant: $($permission.Name)")

                    #Exchange Session
                    $remoteSession = Set-PSSession -PSSessionName 'HelloID_Prov_Exchange'
                    Connect-PSSession $remoteSession | out-null 
                    
                    # if it does not exist create new session to exchange in remote session
                    $createSessionResult = Invoke-Command -Session $remoteSession -ScriptBlock {
                        # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
                        $verboseLogs = [System.Collections.ArrayList]::new()
                        $informationLogs = [System.Collections.ArrayList]::new()
                        $warningLogs = [System.Collections.ArrayList]::new()
                        $errorLogs = [System.Collections.ArrayList]::new()
    
                        # Check if Exchange Connection already exists
                        try {
                            $null = Get-User -ResultSize 1 -ErrorAction Stop | Out-Null
                            $connectedToExchange = $true
                        }
                        catch {
                            if ($_.Exception.Message -like "The term 'Get-User' is not recognized as the name of a cmdlet, function, script file, or operable program.*") {
                                $connectedToExchange = $false
                            }
                        }
            
                        # Connect to Exchange
                        try {                        
                            if ($connectedToExchange -eq $false) {
                                $connectionUri = $using:ConnectionUri
                                $authenticationMethod = $using:AuthenticationMethod
                                $password = $using:Password
                                $username = $using:Username
    
                                [Void]$verboseLogs.Add("Connecting to Exchange: $connectionUri..")
    
                                # Connect to Exchange in an unattended scripting scenario using user credentials (MFA not supported).
                                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                                $credential = [System.Management.Automation.PSCredential]::new($username, $securePassword)
                                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -IdleTimeout (New-TimeSpan -Minutes 5).TotalMilliseconds # The session does not time out while the session is active. Please enter this value to time out the Exchangesession when the session is removed
                                $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $connectionUri -Credential $credential -Authentication $authenticationMethod -AllowRedirection -SessionOption $sessionOption -EnableNetworkAccess:$false -ErrorAction Stop
                                $null = Import-PSSession $exchangeSession
                                [Void]$informationLogs.Add("Successfully connected to Exchange: $connectionUri")
                            }
                            else {
                                [Void]$verboseLogs.Add("Already connected to Exchange")
                            }
                        }
                        catch {
                            if (-Not [string]::IsNullOrEmpty($_.Exception.InnerExceptions)) {
                                $errorMessage = "$($_.Exception.InnerExceptions)"
                            }
                            else {
                                $errorMessage = "$($_.Exception.Message) $($_.ScriptStackTrace)"
                            }
                            [Void]$warningLogs.Add($errorMessage)
                            throw "Could not connect to Exchange, error: $_"
                        }
                        finally {                        
                            $returnobject = @{
                                verboseLogs     = $verboseLogs
                                informationLogs = $informationLogs
                                warningLogs     = $warningLogs
                                errorLogs       = $errorLogs
                            }
                            Write-Output $returnobject      
                            Remove-Variable ("verboseLogs", "informationLogs", "warningLogs", "errorLogs")                             
                                              
                        }
                    }                
                
                    # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
                    $verboseLogs = $createSessionResult.verboseLogs
                    foreach ($verboseLog in $verboseLogs) { Write-Verbose -Verbose $verboseLog }
                    $informationLogs = $createSessionResult.informationLogs
                    foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
                    $warningLogs = $createSessionResult.warningLogs
                    foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
                    $errorLogs = $createSessionResult.errorLogs
                    foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }
            
            
                    # Grant Exchange Mailbox permission
                    $addExchangeMailboxPermission = Invoke-Command -Session $remoteSession -ScriptBlock {
                        $account = $using:actionContext.References.Account
                        $permission = $using:permission
                        $permissionSuccess = $false
                        $success = $false
                        $auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

                        # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
                        $verboseLogs = [System.Collections.ArrayList]::new()
                        $informationLogs = [System.Collections.ArrayList]::new()
                        $warningLogs = [System.Collections.ArrayList]::new()
                        $errorLogs = [System.Collections.ArrayList]::new()

                        [Void]$verboseLogs.Add($permission.Value)

                        try {                               
                                      
                            
                            [Void]$verboseLogs.Add("Granting permission FullAccess to mailbox $($permission.Name) ($($permission.Value)) for user ($($account.UserPrincipalName))")
                            $null = Add-MailboxPermission -Identity $($permission.Value) -AccessRights FullAccess -InheritanceType All -AutoMapping:$true -User $($account.Guid) -ErrorAction Stop
                            [Void]$verboseLogs.Add("FullAccess set on $($permission.Value) for $($account.UserPrincipalName)")
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = "GrantPermission"
                                    Message = "Successfully set full access permission to mailbox ($($permission.Value)) for user ($($account.UserPrincipalName))"
                                    IsError = $false
                                })
                                    
                            [Void]$verboseLogs.Add("Setting Send As permission on mailbox $($permission.Name) ($($permission.Value)) for user ($($account.UserPrincipalName))")
                            $null = Add-ADPermission -Identity "$($permission.Name)" -AccessRights ExtendedRight -ExtendedRights "Send As" -Confirm:$false -User $($account.Guid) -ErrorAction Stop
                            [Void]$verboseLogs.Add("SendAs set on $($permission.Value) for $($account.UserPrincipalName)")
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = "GrantPermission"
                                    Message = "Successfully set send as permission to mailbox ($($permission.Value)) for user ($($account.UserPrincipalName))"
                                    IsError = $false
                                })
                                    
                            

                            $permissionSuccess = $true
                            $success = $true
                     
                        }
                        catch {                
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = "GrantPermission"
                                    Message = "Error setting permissions on $($permission.Value) for ($($account.UserPrincipalName)). Error: $_"
                                    IsError = $true
                                })
                            [Void]$verboseLogs.Add("Error setting permissions on $($permission.Value) for ($($account.UserPrincipalName))")
                            [Void]$verboseLogs.Add("Error: $_")
                        }  
                        finally {                        
                            $returnobject = @{
                                verboseLogs       = $verboseLogs
                                informationLogs   = $informationLogs
                                warningLogs       = $warningLogs
                                errorLogs         = $errorLogs
                                auditLogs         = $auditLogs
                                permissionSuccess = $permissionSuccess
                                success           = $success
                            }
                            Remove-Variable ("verboseLogs", "informationLogs", "warningLogs", "errorLogs", "permissionSuccess", "success", "auditLogs", "account", "permission")                             
                            Write-Output $returnobject                
                        }                 
                    }
                    $verboseLogs = $addExchangeMailboxPermission.verboseLogs
                    foreach ($verboseLog in $verboseLogs) { Write-Verbose -Verbose $verboseLog }
                    $informationLogs = $addExchangeMailboxPermission.informationLogs
                    foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
                    $warningLogs = $addExchangeMailboxPermission.warningLogs
                    foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
                    $errorLogs = $addExchangeMailboxPermission.errorLogs
                    foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }
        
                    $permissionSuccess = $addExchangeMailboxPermission.permissionSuccess
                    $success = $addExchangeMailboxPermission.success

                    $auditLogs = $addExchangeMailboxPermission.auditLogs
                    foreach ($auditlog in $auditLogs) { 
                        $outputContext.AuditLogs.Add($auditlog)                
                    }

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Granted access to shared mailbox $($permission.Value)"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would grant permission to group '$($permission.Value) ($($permission.Name))' for user '$($actionContext.References.Account.UserPrincipalName)'"
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                Write-Verbose -Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
                    
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Error granting permission to group '$($permission.Value) ($($permission.Name))' for user '$($actionContext.References.Account)'. Error Message: $($errorMessage.AuditErrorMessage)"
                        IsError = $True
                    })
            }
        }
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {
        
        #if (-Not $desiredPermissions.ContainsKey("$($permission.Name)")) {
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -and $permission.name -ne "No Groups Defined") {
            # Revoke AD Groupmembership
            Write-Verbose -Verbose ("Old permission to revoke: $($permission.Name)")
            try {
                if (-Not($actionContext.DryRun -eq $true)) {
                    #Exchange Session
                    $remoteSession = Set-PSSession -PSSessionName 'HelloID_Prov_Exchange'
                    Connect-PSSession $remoteSession | out-null 
                    
                    # if it does not exist create new session to exchange in remote session
                    $createSessionResult = Invoke-Command -Session $remoteSession -ScriptBlock {
                        # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
                        $verboseLogs = [System.Collections.ArrayList]::new()
                        $informationLogs = [System.Collections.ArrayList]::new()
                        $warningLogs = [System.Collections.ArrayList]::new()
                        $errorLogs = [System.Collections.ArrayList]::new()
    
                        # Check if Exchange Connection already exists
                        try {
                            $null = Get-User -ResultSize 1 -ErrorAction Stop | Out-Null
                            $connectedToExchange = $true
                        }
                        catch {
                            if ($_.Exception.Message -like "The term 'Get-User' is not recognized as the name of a cmdlet, function, script file, or operable program.*") {
                                $connectedToExchange = $false
                            }
                        }
            
                        # Connect to Exchange
                        try {                        
                            if ($connectedToExchange -eq $false) {
                                $connectionUri = $using:ConnectionUri
                                $authenticationMethod = $using:AuthenticationMethod
                                $password = $using:Password
                                $username = $using:Username
    
                                [Void]$verboseLogs.Add("Connecting to Exchange: $connectionUri..")
    
                                # Connect to Exchange in an unattended scripting scenario using user credentials (MFA not supported).
                                $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
                                $credential = [System.Management.Automation.PSCredential]::new($username, $securePassword)
                                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -IdleTimeout (New-TimeSpan -Minutes 5).TotalMilliseconds # The session does not time out while the session is active. Please enter this value to time out the Exchangesession when the session is removed
                                $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $connectionUri -Credential $credential -Authentication $authenticationMethod -AllowRedirection -SessionOption $sessionOption -EnableNetworkAccess:$false -ErrorAction Stop
                                $null = Import-PSSession $exchangeSession
                                [Void]$informationLogs.Add("Successfully connected to Exchange: $connectionUri")
                            }
                            else {
                                [Void]$verboseLogs.Add("Already connected to Exchange")
                            }
                        }
                        catch {
                            if (-Not [string]::IsNullOrEmpty($_.Exception.InnerExceptions)) {
                                $errorMessage = "$($_.Exception.InnerExceptions)"
                            }
                            else {
                                $errorMessage = "$($_.Exception.Message) $($_.ScriptStackTrace)"
                            }
                            [Void]$warningLogs.Add($errorMessage)
                            throw "Could not connect to Exchange, error: $_"
                        }
                        finally {                        
                            $returnobject = @{
                                verboseLogs     = $verboseLogs
                                informationLogs = $informationLogs
                                warningLogs     = $warningLogs
                                errorLogs       = $errorLogs
                            }
                            Write-Output $returnobject      
                            Remove-Variable ("verboseLogs", "informationLogs", "warningLogs", "errorLogs")                             
                                              
                        }
                    }                
                
                    # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
                    $verboseLogs = $createSessionResult.verboseLogs
                    foreach ($verboseLog in $verboseLogs) { Write-Verbose -Verbose $verboseLog }
                    $informationLogs = $createSessionResult.informationLogs
                    foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
                    $warningLogs = $createSessionResult.warningLogs
                    foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
                    $errorLogs = $createSessionResult.errorLogs
                    foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }
                    
                    $removeExchangeMailboxPermission = Invoke-Command -Session $remoteSession -ScriptBlock {
                        try {
                            $account = $using:actionContext.References.Account
                            $permission = $using:permission
                        
                            $permissionSuccess = $false
                            $success = $false
                            $auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

                            # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
                            $verboseLogs = [System.Collections.ArrayList]::new()
                            $informationLogs = [System.Collections.ArrayList]::new()
                            $warningLogs = [System.Collections.ArrayList]::new()
                            $errorLogs = [System.Collections.ArrayList]::new()

                            
                            [Void]$verboseLogs.Add("Revoking permission FullAccess frome mailbox $($permission.Name) ($($permission.Value)) for user ($($account.UserPrincipalName))")
                            $null = Remove-MailboxPermission -Identity $permission.Value -AccessRights FullAccess -InheritanceType All -User ($($account.Guid)) -Confirm:$false -ErrorAction Stop
                            [Void]$informationLogs.Add("Successfully revoked permission FullAccess from mailbox $($permission.Name) ($($permission.Value)) for user ($($account.UserPrincipalName))")
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = "RevokePermission"
                                    Message = "Successfully revoked full access permission from mailbox ($($permission.Value)) for user ($($account.UserPrincipalName))"
                                    IsError = $false
                                })
                                    
                                    
                            [Void]$verboseLogs.Add("Revoking permission SendAs from mailbox $($permission.Name) ($($permission.Value)) for user ($($account.UserPrincipalName))")
                            # No error is thrown when user already has permission
                            $null = Remove-AdPermission -Identity "$($permission.Name)" -ExtendedRights "Send As" -User ($($account.Guid)) -Confirm:$false -ErrorAction Stop
                            [Void]$informationLogs.Add("Successfully revoked permission SendAs from mailbox $($permission.Name) ($($permission.Value)) for user ($($account.UserPrincipalName))")
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = "RevokePermission"
                                    Message = "Successfully revoked send as permission from mailbox ($($permission.Value)) for user ($($account.UserPrincipalName))"
                                    IsError = $false
                                })
                                    

                            $permissionSuccess = $true
                            $success = $true
                        }
                        catch {
                            [Void]$verboseLogs.Add("Error revoking permissions from $($permission.Value) for ($($account.UserPrincipalName))")
                            [Void]$verboseLogs.Add("Error: $_")
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = "RevokePermission"
                                    Message = "Failed to revoke permissions from mailbox ($($permission.Value)) for user ($($account.UserPrincipalName))"
                                    IsError = $false
                                })
                        }
                        finally {
                            $returnobject = @{
                                success           = $success
                                auditLogs         = $auditLogs
                                verboseLogs       = $verboseLogs
                                informationLogs   = $informationLogs
                                warningLogs       = $warningLogs
                                errorLogs         = $errorLogs
                                permissionSuccess = $permissionSuccess
                            }
                            Remove-Variable ("success", "auditLogs", "verboseLogs", "informationLogs", "warningLogs", "errorLogs", "permissionSuccess", "account", "permission")     
                            Write-Output $returnobject 
                        }
                    }
                    $permissionSuccess = $removeExchangeMailboxPermission.permissionSuccess
                    $success = $removeExchangeMailboxPermission.success
                    $auditLogs = $removeExchangeMailboxPermission.auditLogs
            
                    $auditLogs = $removeExchangeMailboxPermission.auditLogs
                    foreach ($auditlog in $auditLogs) { 
                        $outputContext.AuditLogs.Add($auditlog)                
                    }

                    # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
                    $verboseLogs = $removeExchangeMailboxPermission.verboseLogs
                    foreach ($verboseLog in $verboseLogs) { Write-Verbose -Verbose $verboseLog }
                    $informationLogs = $removeExchangeMailboxPermission.informationLogs
                    foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
                    $warningLogs = $removeExchangeMailboxPermission.warningLogs
                    foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
                    $errorLogs = $removeExchangeMailboxPermission.errorLogs
                    foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }
                }
                else {
                    $newCurrentPermissions[$permission.Name] = $permission.Value
                }
            }
            # Handle issue of AD Account or Group having been deleted.  Handle gracefully.
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
                Write-Verbose -Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

                $auditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Failed to revoke permissions from shared mailbox '$($permission.Value) ($($permission.Name))' for user '$($actionContext.References.Account.UserPrincipalName).' (Identity not found. skipped action)"
                        IsError = $false
                    })
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
                Write-Verbose -Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

                $auditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Failed to revoke permissions from shared mailbox '$($permission.Value) ($($permission.Name))' for user '$($actionContext.References.Account.UserPrincipalName)'. Error Message: $($errorMessage.AuditErrorMessage)"
                        IsError = $True
                    })
            }
            
        }
        
    }    
}
catch {
    Write-Verbose -Verbose $_
}
finally { 
    if ($null -ne $remoteSession) {           
        Disconnect-PSSession $remoteSession -WarningAction SilentlyContinue | out-null   # Suppress Warning: PSSession Connection was created using the EnableNetworkAccess parameter and can only be reconnected from the local computer. # to fix the warning the session must be created with a elevated prompt
        Write-Verbose -Verbose "Remote Powershell Session '$($remoteSession.Name)' State: '$($remoteSession.State)' Availability: '$($remoteSession.Availability)'"
    } 
    
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }

    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No Groups Defined"
                Reference   = [PSCustomObject]@{ Id = "No Groups Defined" }
            })
    }    
}

