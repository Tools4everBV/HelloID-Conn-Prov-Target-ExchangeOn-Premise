#################################################
# HelloID-Conn-Prov-Target-Microsoft-Exchange-On-Premises-Create
# Correlate to account
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

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
        Write-Verbose "Remote Powershell session is found, Name: $($sessionObject.Name), ComputerName: $($sessionObject.ComputerName)"
    }
    catch {
        Write-Verbose "Remote Powershell session not found: $($_)"
    }

    if ($null -eq $sessionObject) { 
        try {
            $remotePSSessionOption = New-PSSessionOption -IdleTimeout (New-TimeSpan -Minutes 5).TotalMilliseconds
            $sessionObject = New-PSSession -ComputerName $env:computername -EnableNetworkAccess:$true -Name $PSSessionName -SessionOption $remotePSSessionOption
            Write-Verbose "Remote Powershell session is created, Name: $($sessionObject.Name), ComputerName: $($sessionObject.ComputerName)"
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
#endregion functions

try {
    #region Create or connect to existing Remote Powershell session, required to manage the sessions
    $actionMessage = "connecting to Powershell session [HelloID_Prov_Exchange]"

    $settPsSessionSplatParams = @{
        PSSessionName = "HelloID_Prov_Exchange"
        Verbose       = $false
        ErrorAction   = "Stop"
    }

    $setPsSessionResponse = Set-PSSession @settPsSessionSplatParams
    $remoteSession = $setPsSessionResponse

    $connectPsSessionSplatParams = @{
        Session     = $remoteSession
        Verbose     = $false
        ErrorAction = "Stop"
    }

    $connectPsSessionResponse = Connect-PSSession @connectPsSessionSplatParams

    Write-Verbose "Connected to Powershell session [HelloID_Prov_Exchange]"
    #endregion Create or connect to existing Remote Powershell session, required to manage the sessions

    #region Invoke command at remote session where the exchange session resides
    $actionMessage = "invoking command at remote session with ID [$($remoteSession.id)]"
    $invokeCommandResponse = Invoke-Command -Session $remoteSession -ScriptBlock {
        try {
            # Pass the local variables to the remote session
            $actionContext = $using:actionContext
            $personContext = $using:personContext
            $outputContext = $using:outputContext

            # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
            $logs = @{
                Verbose     = [System.Collections.ArrayList]::new()
                Information = [System.Collections.ArrayList]::new()
                Warning     = [System.Collections.ArrayList]::new()
            }

            #region account
            # Define correlation
            $correlationField = $actionContext.CorrelationConfiguration.accountField
            $correlationValue = $actionContext.CorrelationConfiguration.personFieldValue

            # Define account object
            $account = [PSCustomObject]$actionContext.Data.PsObject.Copy()

            # Define properties to query
            $accountPropertiesToQuery = @("guid") + $account.PsObject.Properties.Name | Select-Object -Unique
            #endRegion account

            #region Verify correlation configuration and properties
            $actionMessage = "verifying correlation configuration and properties"

            if ($actionContext.CorrelationConfiguration.Enabled -eq $true) {
                if ([string]::IsNullOrEmpty($correlationField)) {
                    throw "Correlation is enabled but not configured correctly."
                }

                if ([string]::IsNullOrEmpty($correlationValue)) {
                    throw "The correlation value for [$correlationField] is empty. This is likely a mapping issue."
                }
            }
            else {
                throw "Correlation is disabled while this connector only supports correlation."
            }
            #endregion Verify correlation configuration and properties

            #region Check if Exchange Connection already exists
            try {
                $actionMessage = "checking if Exchange Connection already exists"

                $null = Get-User -ResultSize 1 -ErrorAction Stop | Out-Null
                $connectedToExchange = $true
            }
            catch {
                if ($_.Exception.Message -like "The term 'Get-User' is not recognized as the name of a cmdlet, function, script file, or operable program.*") {
                    $connectedToExchange = $false
                }
            }
            #endregion Check if Exchange Connection already exists

            if ($connectedToExchange -eq $false) {
                #region Connect to Exchange On-Premises
                $actionMessage = "connecting to Exchange with ConnectionUri: $($actionContext.Configuration.connectionUri)"

                # Connect to Exchange On-Premises in an unattended scripting scenario using user credentials (MFA not supported).
                $securePassword = ConvertTo-SecureString $($actionContext.Configuration.password) -AsPlainText -Force
                $credential = [System.Management.Automation.PSCredential]::new($($actionContext.Configuration.username), $securePassword)
                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -IdleTimeout (New-TimeSpan -Minutes 5).TotalMilliseconds # The session does not time out while the session is active. Please enter this value to time out the Exchangesession when the session is removed
                $exchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $($actionContext.Configuration.connectionUri) -Credential $credential -Authentication $($actionContext.Configuration.authenticationmode) -AllowRedirection -SessionOption $sessionOption -EnableNetworkAccess:$false -ErrorAction Stop
                $null = Import-PSSession $exchangeSession

                [Void]$logs.Information.Add("Connected to Exchange with ConnectionUri: $($actionContext.Configuration.connectionUri)")
                #endregion Connect to Exchange On-Premises
            }
            else {
                [Void]$logs.Verbose.Add("Already connected to Exchange")
            }

            #region Get account
            # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/get-user?view=exchange-ps
            $actionMessage = "querying account where [$($correlationField)] = [$($correlationValue)]"

            $getMicrosoftExchangeOnPremisesAccountSplatParams = @{
                Filter      = "$($correlationField) -eq '$($correlationValue)'"
                Verbose     = $false
                ErrorAction = "Stop"
            }

            $getMicrosoftExchangeOnPremisesAccountResponse = $null
            $getMicrosoftExchangeOnPremisesAccountResponse = Get-User @getMicrosoftExchangeOnPremisesAccountSplatParams
            $correlatedAccount = $getMicrosoftExchangeOnPremisesAccountResponse | Select-Object $accountPropertiesToQuery

            [Void]$logs.Verbose.Add("Queried account where [$($correlationField)] = [$($correlationValue)]. Result: $($correlatedAccount| ConvertTo-Json)")
            #endregion Get account

            #region Calulate action
            $actionMessage = "calculating action"
            if (($correlatedAccount | Measure-Object).count -eq 1) {
                $actionAccount = "Correlate"
            }
            elseif (($correlatedAccount | Measure-Object).count -eq 0) {
                $actionAccount = "NotFound"
            }
            elseif (($correlatedAccount | Measure-Object).count -gt 1) {
                $actionAccount = "MultipleFound"
            }
            #endregion Calulate action

            #region Process
            switch ($actionAccount) {
                "Correlate" {
                    #region Correlate account
                    $actionMessage = "correlating to account"

                    $outputContext.AccountReference = "$($correlatedAccount.Guid)"
                    $outputContext.Data = $correlatedAccount.PsObject.Copy()

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                            Message = "Correlated to account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json) on [$($correlationField)] = [$($correlationValue)]."
                            IsError = $false
                        })

                    $outputContext.AccountCorrelated = $true
                    #endregion Correlate account

                    break
                }

                "MultipleFound" {
                    #region Multiple accounts found
                    $actionMessage = "correlating to account"

                    # Throw terminal error
                    throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the persons are unique."
                    #endregion Multiple accounts found

                    break
                }

                "NotFound" {
                    #region No account found
                    $actionMessage = "correlating to account"

                    # Throw terminal error
                    throw "No account found where [$($correlationField)] = [$($correlationValue)] while this connector only supports correlation."
                    #endregion No account found

                    break
                }
            }
            #endregion Process
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
            $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
 
            [Void]$logs.Warning.Add($warningMessage)

            throw $auditMessage
        }
        finally {
            $returnobject = @{
                logs          = $logs
                outputContext = $outputContext
            }

            Write-Output $returnobject

            # Cleanup all variables
            Get-Variable | Remove-Variable -ErrorAction SilentlyContinue
        }
        #endregion Connect to Exchange On-Premises
    }
    #endregion Invoke command at remote session where the exchange session resides

    # Set ouputContext with the outputContext from the remote command
    $outputContext = $invokeCommandResponse.outputContext

    # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
    # Log Verbose messages
    foreach ($verboseLog in $invokeCommandResponse.logs.Verbose) { 
        Write-Verbose $verboseLog 
    }

    # Log Information messages
    foreach ($informationLog in $invokeCommandResponse.logs.Information) { 
        Write-Information $informationLog 
    }

    # Log Warning messages
    foreach ($warningLog in $invokeCommandResponse.logs.Warning) { 
        Write-Warning $warningLog 
    }
}
catch {
    $ex = $PSItem

    $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
    $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"

    Write-Warning $warningMessage

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            # Action= "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    #region Disconnect from Remote Powershell session
    if ($null -ne $remoteSession) { 
        Disconnect-PSSession $remoteSession -WarningAction SilentlyContinue | out-null # Suppress Warning: PSSession Connection was created using the EnableNetworkAccess parameter and can only be reconnected from the local computer. # to fix the warning the session must be created with a elevated prompt
        Write-Verbose "Remote Powershell Session '$($remoteSession.Name)' State: '$($remoteSession.State)' Availability: '$($remoteSession.Availability)'"
    }
    #endregion Disconnect from Remote Powershell session

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }

    # Check if accountreference is set, if not set, set this with default value as this must contain a value
    if ([String]::IsNullOrEmpty($outputContext.AccountReference) -and $actionContext.DryRun -eq $true) {
        $outputContext.AccountReference = "DryRun: Currently not available"
    }
}