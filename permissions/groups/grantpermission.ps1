############################################################################
# HelloID-Conn-Prov-Target-Exchange-Server-On-Premises-GrantPermission-Group
# PowerShell V2
############################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$outputContext.Success = $true

# Set debug logging
switch ($($actionContext.Configuration.config.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

#Exchange configuration
$ConnectionUri = $actionContext.Configuration.exchange.ConnectionUri
$Username = $actionContext.Configuration.exchange.username
$Password = $actionContext.Configuration.exchange.password
$AuthenticationMethod = $actionContext.Configuration.exchange.authenticationmode

#region functions
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
#endregion

# Begin
try {
    # Verify if [accountReference] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference for Exchange Server On Premises for person [$($personContext.Person.DisplayName)] could not be found"        
    }
    
    if (![string]::IsNullOrEmpty($($actionContext.References.Account))) {        
        $dryRunMessage = "Grant Exchange Server On Premises permission [$($actionContext.References.Permission.DisplayName)] will be executed during enforcement"
    }

    # Add a message and the result of each of the validations showing what will happen during enforcement
    if ($actionContext.DryRun -eq $true) {        
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Message = "[DryRun] $dryRunMessage"
                Action  = "GrantPermission"
                IsError = $false
            })  
    }

    # Process
    if (-not($actionContext.DryRun -eq $true)) {
        
        $remoteSession = Set-PSSession -PSSessionName 'HelloID_Prov_Exchange'
        Connect-PSSession $remoteSession | out-null 

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
                Remove-Variable ("verboseLogs", "informationLogs", "warningLogs", "errorLogs")     
                Write-Output $returnobject 
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

        Write-Information "Granting Exchange Server On Premises permission: [$($actionContext.References.Permission.DisplayName)] - [$($actionContext.References.Permission.Reference)]"
        # Make sure to test with special characters and if needed; add utf8 encoding.
        # Grant Exchange Groupmembership
        $addExchangeGroupMembership = Invoke-Command -Session $remoteSession -ScriptBlock {
            try {
                $account = $using:actionContext.References.Account
                $permission = $using:actionContext.References.Permission

                $success = $false
                $auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

                # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
                $verboseLogs = [System.Collections.ArrayList]::new()
                $informationLogs = [System.Collections.ArrayList]::new()
                $warningLogs = [System.Collections.ArrayList]::new()
                $errorLogs = [System.Collections.ArrayList]::new()

                [Void]$verboseLogs.Add("Granting permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid))")
                $null = Add-DistributionGroupMember -Identity $permission.Reference -Member $account.Guid -BypassSecurityGroupManagerCheck:$true -Confirm:$false -ErrorAction Stop
                [Void]$informationLogs.Add("Successfully granted permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid))")

                $success = $true
                $auditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Successfully granted permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid))"
                        IsError = $false
                    }
                )      
            }
            catch {
                if ($_ -like "*already present in the collection*") {
                    [Void]$warningLogs.Add("The recipient $($account.UserPrincipalName) ($($account.Guid)) is already a member of the group $($permission.DisplayName) ($($permission.Reference))")
                    $success = $true
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Successfully granted permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid))"
                            IsError = $false
                        }
                    )
                }
                elseif ($_ -like "*object '$($permission.Reference)' couldn't be found*") {
                    [Void]$warningLogs.Add("Group $($permission.DisplayName) ($($permission.Reference)) couldn't be found. Possibly no longer exists. Skipping action")
                    $success = $true
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Successfully granted permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid))"
                            IsError = $false
                        }
                    )
                }
                elseif ($_ -like "*Couldn't find object ""$($account.Guid)""*") {
                    [Void]$warningLogs.Add("User $($account.UserPrincipalName) ($($account.Guid)) couldn't be found. Possibly no longer exists. Skipping action")
                    $success = $true
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Successfully granted permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid))"
                            IsError = $false
                        }
                    )
                }
                else {
                    # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot
                    [Void]$warningLogs.Add("Error granting permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid)). Error: $_")
                    $success = $false
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Failed to grant permission $($permission.DisplayName) ($($permission.Reference)) to $($account.UserPrincipalName) ($($account.Guid))"
                            IsError = $true
                        }
                    )
                }
            }
            finally {
                $returnobject = @{
                    success         = $success
                    auditLogs       = $auditLogs
                    verboseLogs     = $verboseLogs
                    informationLogs = $informationLogs
                    warningLogs     = $warningLogs
                    errorLogs       = $errorLogs
                }
                Remove-Variable ("account", "permission", "success", "auditLogs", "verboseLogs", "informationLogs", "warningLogs", "errorLogs") 
                Write-Output $returnobject 
            }
        }
        $success = $addExchangeGroupMembership.success
        $auditLogs = $addExchangeGroupMembership.auditLogs

        # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
        $verboseLogs = $addExchangeGroupMembership.verboseLogs
        foreach ($verboseLog in $verboseLogs) { Write-Verbose -Verbose $verboseLog }
        $informationLogs = $addExchangeGroupMembership.informationLogs
        foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
        $warningLogs = $addExchangeGroupMembership.warningLogs
        foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
        $errorLogs = $addExchangeGroupMembership.errorLogs
        foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }

        foreach ($auditlog in $auditLogs) { 
            $outputContext.AuditLogs.Add($auditlog)                
        }
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-Exchange Server On PremisesError -ErrorObject $ex
        $auditMessage = "Could not grant Exchange Server On Premises permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not grant Exchange Server On Premises permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            Action  = "GrantPermission"
            IsError = $true
        })
}
finally { 
    if ($null -ne $remoteSession) {           
        Disconnect-PSSession $remoteSession -WarningAction SilentlyContinue | out-null   # Suppress Warning: PSSession Connection was created using the EnableNetworkAccess parameter and can only be reconnected from the local computer. # to fix the warning the session must be created with a elevated prompt
        Write-Verbose -Verbose "Remote Powershell Session '$($remoteSession.Name)' State: '$($remoteSession.State)' Availability: '$($remoteSession.Availability)'"
    }      
}