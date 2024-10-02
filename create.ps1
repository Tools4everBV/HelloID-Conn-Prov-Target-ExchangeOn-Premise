#################################################
# HelloID-Conn-Prov-Target-Exchange-On-Premise-Create
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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
    if ($sessionObject.Availability -eq "Busy") {
        throw "Remote session is in Use" 
    }
    Write-Output $sessionObject
}
#endregion

try {
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'
    
    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.accountField
        $correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

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
                $checkCmd = Get-User -ResultSize 1 -ErrorAction Stop | Out-Null
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
        foreach ($verboseLog in $verboseLogs) { Write-Verbose $verboseLog }
        $informationLogs = $createSessionResult.informationLogs
        foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
        $warningLogs = $createSessionResult.warningLogs
        foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
        $errorLogs = $createSessionResult.errorLogs
        foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }
        
        # Determine if a user needs to be [created] or [correlated]                
        try {
                
            $getExchangeUser = Invoke-Command -Session $remoteSession -ScriptBlock {
                $account = $using:actionContext.Data
                $correlatedMailbox = Get-Mailbox -Identity $account.userPrincipalName                                    
                Write-Output $correlatedMailbox                    
            } -ErrorAction Stop                  

            if ($getExchangeUser.Name.Count -eq 0) {
                Write-Information "Could not find mailbox with identity [$($actionContext.Data.userPrincipalName)]"                
                $action = 'CreateAccount'
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "$action mailbox for: [$($actionContext.Data.userPrincipalName)] will be executed."
                        IsError = $false
                    })
            }
            if ($getExchangeUser.Name.Count -gt 0) {            
                Write-Information "Correlation found mailbox for: [$($actionContext.Data.userPrincipalName)]"
                $action = 'CorrelateAccount'
                $correlatedAccount = $getExchangeUser
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "$action mailbox for: [$($actionContext.Data.userPrincipalName)] will be executed."
                        IsError = $false
                    })
            }   
        } 
        catch { 
            if ($_.Exception.ErrorRecord.CategoryInfo.Reason -eq "ManagementObjectNotFoundException") {
                Write-Warning "Could not find mailbox with identity [$($actionContext.Data.userPrincipalName)]"
                $action = 'CreateAccount'
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Message = "Could not find mailbox with identity [$($actionContext.Data.userPrincipalName)]"
                        IsError = $false
                    })                    
            }
            else {
                if (-Not [string]::IsNullOrEmpty($_.Exception.InnerExceptions)) {
                    $errorMessage = "$($_.Exception.InnerExceptions)"
                }
                else {
                    $errorMessage = "$($_.Exception.Message) $($_.ScriptStackTrace)"
                }
                Write-Warning $errorMessage
                throw "Regular Error, error: $_"
            }
        }
    }
     
    # Process    
    switch ($action) {
        'CreateAccount' {
            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating and correlating Exchange On-Premise account'                
                try {
                    $setExchangeUser = Invoke-Command -Session $remoteSession -ScriptBlock {
                        $account = $using:actionContext.Data
                            
                        $createdAccount = Enable-Mailbox -Identity $account.userPrincipalName -PrimarySMTPAddress $account.mail
                        Set-Mailbox -Identity $account.userPrincipalName -EmailAddressPolicyEnabled $False -HiddenFromAddressListsEnabled $True

                        Write-Output $createdAccount
                    } -ErrorAction Stop
                    Write-Information ($setExchangeUser | ConvertTo-Json)
                    $outputContext.Data = $setExchangeUser
                    $outputContext.AccountReference = $setExchangeUser.ExchangeGuid
                    $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]"                   
                }
                catch { 
                    throw $_                        
                }                    
            }
            else {
                $auditLogMessage = "[DryRun] Create and correlate Exchange On-Premise account, will be executed during enforcement"
                Write-Information '[DryRun] Create and correlate Exchange On-Premise account, will be executed during enforcement'
            }            
            break
        }

        'CorrelateAccount' {
            Write-Information 'Correlating Exchange On-Premise account'            
            $outputContext.Data = $correlatedAccount
            $outputContext.AccountReference = $correlatedAccount.ExchangeGuid
            $outputContext.AccountCorrelated = $true
            $auditLogMessage = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
            break
        }
    }
    $outputContext.Success = $true    
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = $action
            Message = $auditLogMessage
            IsError = $false
        })
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}
finally {        
    Start-Sleep 1
    if ($null -ne $remoteSession) {           
        Disconnect-PSSession $remoteSession -WarningAction SilentlyContinue | out-null   # Suppress Warning: PSSession Connection was created using the EnableNetworkAccess parameter and can only be reconnected from the local computer. # to fix the warning the session must be created with a elevated prompt
        Write-Verbose "Remote Powershell Session '$($remoteSession.Name)' State: '$($remoteSession.State)' Availability: '$($remoteSession.Availability)'"
    }      
}
