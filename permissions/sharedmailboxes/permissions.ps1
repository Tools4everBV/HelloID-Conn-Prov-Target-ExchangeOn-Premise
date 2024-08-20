##################################################################################
# HelloID-Conn-Prov-Target-Exchange-Server-On-Premises-Permissions-SharedMailboxes
# PowerShell V2
##################################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Exchange using user credentials (MFA not supported).
$ConnectionUri = $actionContext.Configuration.exchange.ConnectionUri
$Username = $actionContext.Configuration.exchange.username
$Password = $actionContext.Configuration.exchange.password
$AuthenticationMethod = $actionContext.Configuration.exchange.authenticationmode

#region functions
# Write functions logic here
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
            remove-pssession -Id ($sessionObject.id | Sort-Object | select-object -first 1)
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
    Write-Verbose "Remote Powershell Session '$($sessionObject.Name)' State: '$($sessionObject.State)' Availability: '$($sessionObject.Availability)'"
    if ($sessionObject.Availability -eq "Busy") {
        throw "Remote session is in Use" 
    }
    Write-Output $sessionObject
}
#endregion functions

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
                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck -IdleTimeout (New-TimeSpan -Minutes 5).TotalMilliseconds # The session does not time out while the session is active. Please enter this value to time out the EXOsession when the session is removed
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

    # Get Exchange Shared Mailboxes
    $getExoMailboxes = Invoke-Command -Session $remoteSession -ScriptBlock {
        try {
            # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
            $verboseLogs = [System.Collections.ArrayList]::new()
            $informationLogs = [System.Collections.ArrayList]::new()
            $warningLogs = [System.Collections.ArrayList]::new()
            $errorLogs = [System.Collections.ArrayList]::new()

            [Void]$verboseLogs.Add("Searching for Exchange Shared Mailboxes..")
            # Only get Exchange Shared Mailboxes (can be changed easily to get all mailboxes)
            $mailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -resultSize unlimited
            [Void]$informationLogs.Add("Finished searching for Exchange Shared Mailboxes. Found [$($mailboxes.id.Count) Shared Mailboxes]")
        }
        catch {
            throw "Could not gather Exchange Shared Mailboxes. Error: $_"
        }
        finally {
            $returnobject = @{
                mailboxes       = $mailboxes
                verboseLogs     = $verboseLogs
                informationLogs = $informationLogs
                warningLogs     = $warningLogs
                errorLogs       = $errorLogs
            }
            Remove-Variable ("mailboxes", "verboseLogs", "informationLogs", "warningLogs", "errorLogs")     
            Write-Output $returnobject 
        }
    }

    # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
    $verboseLogs = $getExoMailboxes.verboseLogs
    foreach ($verboseLog in $verboseLogs) { Write-Verbose $verboseLog }
    $informationLogs = $getExoMailboxes.informationLogs
    foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
    $warningLogs = $getExoMailboxes.warningLogs
    foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
    $errorLogs = $getExoMailboxes.errorLogs
    foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }    
}
catch {
    throw "Could not gather Exchange Shared Mailboxes. Error: $_"
}
finally {
    Start-Sleep 1
    if ($null -ne $remoteSession) {           
        Disconnect-PSSession $remoteSession -WarningAction SilentlyContinue | out-null   # Suppress Warning: PSSession Connection was created using the EnableNetworkAccess parameter and can only be reconnected from the local computer. # to fix the warning the session must be created with a elevated prompt
        Write-Verbose "Remote Powershell Session '$($remoteSession.Name)' State: '$($remoteSession.State)' Availability: '$($remoteSession.Availability)'"
    }      
}


# Send results
$mailboxes = $getExoMailboxes.mailboxes
foreach ($mailbox in $mailboxes) {
    $outputContext.Permissions.Add(
        @{
            DisplayName    = "Shared Mailbox - $($mailbox.DisplayName)";
            Identification = @{
                Reference   = $mailbox.Guid;
                DisplayName = "Shared Mailbox - $($mailbox.DisplayName)";
                Permissions = @("Full Access", "Send As"); # Options:  Full Access,Send As, Send on Behalf
            }
        }
    )
}