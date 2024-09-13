#################################################
# HelloID-Conn-Prov-Target-Microsoft-Exchange-On-Premises-Permissions-RemoteMailbox-Archive
# List Litigation Hold options as permissions
# PowerShell V2
#################################################

$outputContext.Permissions.Add(
    @{
        DisplayName    = "RemoteMailbox Archive"
        Identification = @{
            Id = "RemoteMailbox-Archive"
        }
    }
)