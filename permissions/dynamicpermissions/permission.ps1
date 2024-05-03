$outputContext.Permissions.Add(
    @{
        DisplayName    = "Department Mailbox"
        Identification = @{
            DisplayName    = "Department Mailbox"
            Reference = "DMBX"
            Permissions = @("Full Access","Send As"); # Options:  Full Access,Send As, Send on Behalf
        }
    }
);
