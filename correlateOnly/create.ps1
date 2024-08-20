##############################################################
# HelloID-Conn-Prov-Target-Exchange-OnPremise-Create-Correlate
# PowerShell V2
##############################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false

# Set debug logging
switch ($($actionContext.Configuration.config.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}


#Exchange
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

# Check if we should try to correlate the account
# Get current AD account
try {
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationProperty = $actionContext.CorrelationConfiguration.accountField
        $correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue
    
        if ([string]::IsNullOrEmpty($correlationProperty)) {
            Write-Warning "Correlation is enabled but not configured correctly."
            throw "Correlation is enabled but not configured correctly."
        }
    
        if ([string]::IsNullOrEmpty($correlationValue)) {
            Write-Warning "The correlation value for [$correlationProperty] is empty. This is likely a scripting issue."
            throw "The correlation value for [$correlationProperty] is empty. This is likely a scripting issue."
        }
    }
    else {
        Write-Warning "Correlation is enabled but not configured correctly."
        throw "Configuration of correlation is madatory."
    }

    try {
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

        # Get Exchange User
        $getExchangeUser = Invoke-Command -Session $remoteSession -ScriptBlock {
            try {                
                $account = $using:outputContext.Data

                $success = $false
                $auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

                # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
                $verboseLogs = [System.Collections.ArrayList]::new()
                $informationLogs = [System.Collections.ArrayList]::new()
                $warningLogs = [System.Collections.ArrayList]::new()
                $errorLogs = [System.Collections.ArrayList]::new()

                if ([string]::IsNullOrEmpty($account.userPrincipalName)) { throw "No UserPrincipalName provided" }  
            
                [Void]$verboseLogs.Add("Identity: $($account.userPrincipalName)")
                $user = Get-User -Identity $account.userPrincipalName -ErrorAction Stop

                if ($user -eq $null) { throw "Failed to return a user" }

                $aRef = @{
                    Guid              = $user.Guid
                    UserPrincipalName = $user.UserPrincipalName
                }

                [Void]$informationLogs.Add("Account correlated to $($aRef.userPrincipalName) ($($aRef.Guid))")

                $success = $true;
                $auditLogs.Add([PSCustomObject]@{
                        Action  = "CreateAccount"
                        Message = "Account correlated to $($aRef.userPrincipalName) ($($aRef.Guid))";
                        IsError = $false;
                    });
            }
            catch { 
                throw $_
            }
            finally {
                $returnobject = @{
                    user            = $user
                    aRef            = $aRef
                    success         = $success
                    auditLogs       = $auditLogs
                    verboseLogs     = $verboseLogs
                    informationLogs = $informationLogs
                    warningLogs     = $warningLogs
                    errorLogs       = $errorLogs
                }
                Remove-Variable ("account", "user", "success", "auditLogs", "verboseLogs", "informationLogs", "warningLogs", "errorLogs")     
                Write-Output $returnobject 
            }
        }
        $aRef = $getExchangeUser.aRef
        $success = $getExchangeUser.success
        $auditLogs = $getExchangeUser.auditLogs

        # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
        $verboseLogs = $getExchangeUser.verboseLogs
        foreach ($verboseLog in $verboseLogs) { Write-Verbose $verboseLog }
        $informationLogs = $getExchangeUser.informationLogs
        foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
        $warningLogs = $getExchangeUser.warningLogs
        foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
        $errorLogs = $getExchangeUser.errorLogs
        foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }

        foreach ($auditlog in $auditLogs) { 
            $outputContext.AuditLogs.Add($auditlog)                
        }
    }
    catch {
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                Action  = "CreateAccount"
                Message = "Account failed to correlate:  $_"
                IsError = $True
            });    
        Write-Warning $_;
    }

    $outputContext.AccountReference = $getExchangeUser.aRef
    $actionContext.Data.exchGuid = $getExchangeUser.aRef.Guid
    

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = "CreateAccount"
            Message = "Successfully correlated to mailuser $($outputContext.Data.userPrincipalName) ($($outputContext.Data.employeeNumber))"
            IsError = $false
        })
}
catch {
    # Clean up error variables
    $verboseErrorMessage = $null
    $auditErrorMessage = $null

    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObject = Resolve-HTTPError -Error $ex

        $verboseErrorMessage = $errorObject.ErrorMessage

        $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
    }

    # If error message empty, fall back on $ex.Exception.Message
    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
        $verboseErrorMessage = $ex.Exception.Message
    }
    if ([String]::IsNullOrEmpty($auditErrorMessage)) {
        $auditErrorMessage = $ex.Exception.Message
    }

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = "CreateAccount"
            Message = "Error querying mailuser [$correlationValue]. Error Message: $auditErrorMessage"
            IsError = $True
        })
}
finally {
    if ($null -ne $remoteSession) {           
        Disconnect-PSSession $remoteSession -WarningAction SilentlyContinue | out-null   # Suppress Warning: PSSession Connection was created using the EnableNetworkAccess parameter and can only be reconnected from the local computer. # to fix the warning the session must be created with a elevated prompt
        Write-Verbose "Remote Powershell Session '$($remoteSession.Name)' State: '$($remoteSession.State)' Availability: '$($remoteSession.Availability)'"
    } 
    
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
    
    $outputContext.Data = $actionContext.Data
}


