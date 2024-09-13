#####################################################
# HelloID-Conn-Prov-Target-Microsoft-Exchange-On-Premises-Permissions-RemoteMailbox-Archive-Grant
# Enable archive mailbox for an on-premises user with a remote mailbox in Exchange Online
# PowerShell V2
#####################################################

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

            #region Verify account reference
            $actionMessage = "verifying account reference"
    
            if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
                throw "The account reference could not be found"
            }
            #endregion Verify account reference

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
 
            #region Enable archive mailbox for remote mailbox
            # Docs: https://learn.microsoft.com/en-us/powershell/module/exchange/enable-remotemailbox?view=exchange-ps
            $actionMessage = "enabling remotemailbox archive on mailbox [$($actionContext.References.Account)]"

            $enableArchiveSplatParams = @{
                Identity         = $actionContext.References.Account
                Archive          = $true
                DomainController = $domainController
                Verbose          = $false
                ErrorAction      = "Stop"
            }

            [Void]$logs.Verbose.Add("SplatParams: $($enableArchiveSplatParams | ConvertTo-Json)")

            if (-Not($actionContext.DryRun -eq $true)) {
                $enableArchiveResponse = Enable-RemoteMailbox @enableArchiveSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action= "" # Optional
                        Message = "Enabled remotemailbox archive on mailbox [$($actionContext.References.Account)]."
                        IsError = $false
                    })
            }
            else {
                [Void]$logs.Warning.Add("DryRun: Would enabled remotemailbox archive on mailbox [$($actionContext.References.Account)].")
            }
            #endregion Enable archive mailbox for remote mailbox
        }
        catch {
            $ex = $PSItem

            $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
            $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
 
            if ($auditMessage -like "*already has an archive*") {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action= "" # Optional
                        Message = "Skipped $($actionMessage). Reason: Recipient already has an archive."
                        IsError = $false
                    })
            }
            else {
                [Void]$logs.Warning.Add($warningMessage)

                throw $auditMessage
            }
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
}