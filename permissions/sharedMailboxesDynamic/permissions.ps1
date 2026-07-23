##############################################################################
# HelloID-Conn-Prov-Target-Exchange-OnPremise-Permissions-SharedMailboxDynamic
# PowerShell V2
##############################################################################

$outputContext.Permissions.Add(
    @{
        DisplayName    = "Department Mailbox"
        Identification = @{
            DisplayName = "Department Mailbox"
            Reference   = "DMBX"
        }
    }
);
