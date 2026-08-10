# HelloID-Conn-Prov-Target-Exchange Server On Premises

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-ExchangeOn-Premise/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Exchange Server On Premises](#helloid-conn-prov-target-exchange-server-on-premises)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
    - [Account Reference](#account-reference)
  - [Remarks](#remarks)
    - [Available lifecycle actions](#available-lifecycle-actions)
    - [Exchange Management Shell](#exchange-management-shell)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Exchange Server On Premises_ is a _target_ connector.
_Exchange Server On Premises_ provides the option to correlate to existing Exchange users and provision Exchange group memberships and shared mailbox permissions.

> [!NOTE]
> Only Exchange groups are supported by this connector. If a group can be managed directly by Active Directory, managing it in AD is advised.

If you want to create Exchange On-Premises users, use the built-in Microsoft Active Directory target system with Exchange integration.

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                 | Remarks           |
| ----------------------------------------- | --------- | ----------------------- | ----------------- |
| **Account Lifecycle**                     | ✅         | Create, Enable, Disable |                   |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke | Static or Dynamic |
| **Resources**                             | ✅         | Retrieve                |                   |
| **Entitlement Import: Accounts**          | ❌         | -                       |                   |
| **Entitlement Import: Permissions**       | ❌         | -                       |                   |
| **Governance Reconciliation Resolutions** | ❌         | -                       |                   |

## Getting started

### HelloID Icon URL

URL of the icon used for the HelloID Provisioning target system:

```txt
https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-ExchangeOn-Premise/refs/heads/main/Icon.png
```

### Requirements

- Run **Enable-PSRemoting** on the Exchange server you want to connect to.
- In **IIS**, under **Exchange Back End** for the **PowerShell** virtual directory, verify **Windows Authentication** is enabled.
- Use a service account with permissions to manage Exchange objects. The default AD group **Organization Management** should generally suffice.
- This connector is intended for **on-premises** Exchange environments.
- Set **Concurrent sessions** in HelloID to a **maximum of 1**. Higher values can cause errors because Exchange supports a limited number of remote sessions.

### Connection settings

The following settings are required to connect.

| Setting                         | Description                                                        | Mandatory |
| ------------------------------- | ------------------------------------------------------------------ | --------- |
| exchange.connectionUri          | The connection URL of the on-premises Exchange PowerShell endpoint | Yes       |
| exchange.username               | The username of the Exchange service account                       | Yes       |
| exchange.password               | The password of the Exchange service account                       | Yes       |
| exchange.authenticationmode     | The authentication method used to authenticate the credentials     | Yes       |
| exchange.sharedMailboxContainer | The OU where shared mailbox user objects are located               | Yes       |
| config.IsDebug                  | Enables verbose logging for troubleshooting                        | No        |

### Correlation configuration

The correlation configuration is used to specify which properties are used to match an existing account within _Exchange Server On Premises_ to a person in _HelloID_.

| Setting                   | Value                       |
| ------------------------- | --------------------------- |
| Enable correlation        | `True`                      |
| Person correlation field  | ``                          |
| Account correlation field | `Account.UserPrincipalName` |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

### Account Reference

The account reference is populated with the Exchange mailbox **ExchangeGuid** value.

## Remarks

### Available lifecycle actions

| Action                                                             | Description                                                                     |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| create.ps1                                                         | PowerShell _create_ lifecycle action                                            |
| enable.ps1                                                         | PowerShell _enable_ lifecycle action                                            |
| disable.ps1                                                        | PowerShell _disable_ lifecycle action                                           |
| permissions/groups/grantpermission.ps1                             | PowerShell _grant_ lifecycle action for groups                                  |
| permissions/groups/revokepermission.ps1                            | PowerShell _revoke_ lifecycle action for groups                                 |
| permissions/groups/permissions.ps1                                 | PowerShell _permissions_ lifecycle action for groups                            |
| permissions/sharedmailboxes/grantpermissions.ps1                   | PowerShell _grant_ lifecycle action for shared mailboxes                        |
| permissions/sharedmailboxes/revokepermission.ps1                   | PowerShell _revoke_ lifecycle action for shared mailboxes                       |
| permissions/sharedmailboxes/permissions.ps1                        | PowerShell _permissions_ lifecycle action for shared mailboxes                  |
| permissions/sharedMailboxesDynamic/subPermissions.ps1              | PowerShell _grant_, _update_ and _revoke_ lifecycle action for shared mailboxes |
| permissions/sharedMailboxesDynamic/permissions.ps1                 | PowerShell _permissions_ lifecycle action for shared mailboxes                  |
| resources/groups/resources.ps1                                     | PowerShell _resources_ lifecycle action for groups                              |
| resources/sharedMailboxes/resources.ps1                            | PowerShell _resources_ lifecycle action for shared mailboxes                    |
| correlateOnly/create.ps1                                           | PowerShell _create_ lifecycle action for correlation only                       |
| postAdAction/postAdAction.create.DisableExchangeActiveSync_OWA.ps1 | Post-AD action used in the built-in AD connector _create_ lifecycle action      |

### Exchange Management Shell

This connector uses cmdlets from the Exchange Management Shell for permissions and mailbox operations. Ensure remoting and authentication are configured correctly before onboarding.

## Development resources

### API endpoints

The connector uses Exchange Remote PowerShell cmdlets instead of REST API endpoints.

| Endpoint / Interface           | Method(s)          | Description                                            |
| ------------------------------ | ------------------ | ------------------------------------------------------ |
| Exchange Remote PowerShell     | New-PSSession      | Creates a remote session to Exchange                   |
| Exchange cmdlets (for example) | Get/Set/Add/Remove | Retrieves and manages Exchange objects and permissions |

### API documentation

- Microsoft documentation for remote Exchange PowerShell access: https://learn.microsoft.com/en-us/powershell/exchange/control-remote-powershell-access-to-exchange-servers

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
