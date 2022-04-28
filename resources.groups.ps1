$c = $configuration | ConvertFrom-Json

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Exchange using user credentials (MFA not supported).
$ConnectionUri = $c.ConnectionUri
$Username = $c.Username
$Password = $c.Password
$AuthenticationMethod = $c.AuthenticationMethod

# The resourceData used in this default script uses resources based on Title
$rRef = $resourceContext | ConvertFrom-Json
$success = $true

$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# Troubleshooting
# $dryRun = $false
$debug = $false

$path = "OU=Mailgroepen,OU=Enyoi,DC=enyoi,DC=local"
$exchangeGroupNamePrefix = "distributiongroup_"
$exchangeGroupNameSuffix = ""

#region functions
# Write functions logic here
function Set-PSSession {
    <#
    .SYNOPSIS
        Get or create a "remote" Powershell session
    .DESCRIPTION
        Get or create a "remote" Powershell session at the local computer
    .EXAMPLE
        PS C:\> $remoteSession = Set-PSSession -PSSessionName ($psSessionName + $mutex.Number) # Test1
       Get or Create a "remote" Powershell session at the local computer with computername and number: Test1 And assign to a $varaible which can be used to make remote calls.
    .OUTPUTS
        $remoteSession [System.Management.Automation.Runspaces.PSSession]
    .NOTES
        Make sure you always disconnect the PSSession, otherwise the PSSession is blocked to reconnect. 
        Place the following code in the finally block to make sure the session will be disconnected
        if ($null -ne $remoteSession) {  
            Disconnect-PSSession $remoteSession 
        }
    #>
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

    # Create Exchange groups
    $createExchangeGroups = Invoke-Command -Session $remoteSession -ScriptBlock {
        $dryRun = $using:dryRun
        $debug = $using:debug

        #region Supporting Functions
        function Remove-StringLatinCharacters {
            PARAM ([string]$String)
            [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
        }

        function Get-ADSanitizeGroupName {
            param(
                [parameter(Mandatory = $true)][String]$Name
            )
            $newName = $name.trim();
            $newName = $newName -replace ' - ', '_'
            $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",;,:,\,|,},{,.]', ''
            $newName = $newName -replace '\[', '';
            $newName = $newName -replace ']', '';
            $newName = $newName -replace ' ', '_';
            $newName = $newName -replace '\.\.\.\.\.', '.';
            $newName = $newName -replace '\.\.\.\.', '.';
            $newName = $newName -replace '\.\.\.', '.';
            $newName = $newName -replace '\.\.', '.';

            # Remove diacritics
            $newName = Remove-StringLatinCharacters $newName
            
            return $newName;
        }
        #endregion Supporting Functions
        try {
            $auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

            # Create array for logging since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands
            $verboseLogs = [System.Collections.ArrayList]::new()
            $informationLogs = [System.Collections.ArrayList]::new()
            $warningLogs = [System.Collections.ArrayList]::new()
            $errorLogs = [System.Collections.ArrayList]::new()

            $rRef = $using:rRef
            foreach ($resource in $rRef.SourceData) {
                $exchangeGroupNamePrefix = $using:exchangeGroupNamePrefix
                $exchangeGroupNameSuffix = $using:exchangeGroupNameSuffix
                $path = $using:path

                try {
                    # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
                    # This list of special characters includes: a leading space; a trailing space; and any of the following characters: # , + " \ < > ;
                    # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
                    # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
                    # https://www.ietf.org/rfc/rfc2253.txt
                
                    #Custom fields consists of only one attribute, no object with multiple attributes present!
                    $ExchangeGroupName = ("$exchangeGroupNamePrefix" + "$($resource.DisplayName)" + "$exchangeGroupNameSuffix")
                    $ExchangeGroupName = Get-ADSanitizeGroupName -Name $ExchangeGroupName

                    $ExchangeGroupParams = @{
                        Name               = $ExchangeGroupName
                        SamAccountName     = $ExchangeGroupName
                        DisplayName        = $ExchangeGroupName
                        OrganizationalUnit = $path
                    }
               
                    $distinguishedName = "CN=$($ExchangeGroupParams.Name),$($ExchangeGroupParams.OrganizationalUnit)"
                    $groupExists = $false
                    $groupExists = [bool](Get-DistributionGroup -Identity $distinguishedName -ErrorAction SilentlyContinue)
                    # If resource does not exist
                    if ($groupExists -eq $false) {
                        <# Resource creation preview uses a timeout of 30 seconds
                    while actual run has timeout of 10 minutes #>

                        $adGroupExists = $false
                        $adGroupExists = [bool](Get-ADGroup -Filter { DistinguishedName -eq $distinguishedName })
                        if ($adGroupExists -eq $true) {
                            # Enable existing AD Group for mail
                            [Void]$warningLogs.Add("Group $($distinguishedName) already exists in AD. Enabling ths group for mail.")
                        
                            if (-Not($dryRun -eq $True)) {
                                $EnableExchangeGroup = Enable-DistributionGroup $distinguishedName -ErrorAction Stop
            
                                $success = $True
                                $auditLogs.Add([PSCustomObject]@{
                                        Message = "Created resource for $($resource) - Enabled AD group $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit) for mail"
                                        Action  = "CreateResource"
                                        IsError = $false
                                    })
                            }
                        }
                        else {
                            # Create Exchange Group
                            [Void]$informationLogs.Add("Creating $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit)")
            
                            if (-Not($dryRun -eq $True)) {
                                # $NewExchangeGroup = New-DistributionGroup @ExchangeGroupParams -ErrorAction Stop
            
                                $success = $True
                                $auditLogs.Add([PSCustomObject]@{
                                        Message = "Created resource for $($resource) - Created Exchange group $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit)"
                                        Action  = "CreateResource"
                                        IsError = $false
                                    })
                            }
                        }
                    }
                    else {
                        if ($debug -eq $true) { [Void]$warningLogs.Add("Exchange Group $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit) already exists") }
                        $success = $True
                        # $auditLogs.Add([PSCustomObject]@{
                        #     Message = "Skipped resource for $($resource.name) - $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit)"
                        #     Action  = "CreateResource"
                        #     IsError = $false
                        # })
                    }
                }
                catch {
                    [Void]$warningLogs.Add("Failed to Create $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit). Error: $_")
                    $success = $false
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Failed to create resource for $($resource) - $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit). Error: $_"
                            # Message = "Failed to create resource for $($resource.name) - $($ExchangeGroupParams.Name) at $($ExchangeGroupParams.OrganizationalUnit). Error: $_"
                            Action  = "CreateResource"
                            IsError = $true
                        })
                }
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
            # Remove-Variable ("success","auditLogs","verboseLogs", "informationLogs", "warningLogs", "errorLogs")
            Write-Output $returnobject 
        }
    }

    $success = $createExchangeGroups.success
    $auditLogs = $createExchangeGroups.auditLogs

    # Log the data from logging arrarys (since the "normal" Write-Information isn't sent to HelloID as another PS session performs the commands)
    $verboseLogs = $createExchangeGroups.verboseLogs
    foreach ($verboseLog in $verboseLogs) { Write-Verbose $verboseLog }
    $informationLogs = $createExchangeGroups.informationLogs
    foreach ($informationLog in $informationLogs) { Write-Information $informationLog }
    $warningLogs = $createExchangeGroups.warningLogs
    foreach ($warningLog in $warningLogs) { Write-Warning $warningLog }
    $errorLogs = $createExchangeGroups.errorLogs
    foreach ($errorLog in $errorLogs) { Write-Warning $errorLog }
}
catch {
    throw "Could not create Exchange groups. Error: $_"
}
finally {
    Start-Sleep 1
    if ($null -ne $remoteSession) {           
        Disconnect-PSSession $remoteSession -WarningAction SilentlyContinue | out-null   # Suppress Warning: PSSession Connection was created using the EnableNetworkAccess parameter and can only be reconnected from the local computer. # to fix the warning the session must be created with a elevated prompt
        Write-Verbose "Remote Powershell Session '$($remoteSession.Name)' State: '$($remoteSession.State)' Availability: '$($remoteSession.Availability)'"
    }      
}


# Send results
$result = [PSCustomObject]@{
    Success   = $success
    AuditLogs = $auditLogs
}

Write-Output $result | ConvertTo-Json -Depth 10