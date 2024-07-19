# HelloID-Conn-Prov-Target-Exchange Server On Premises
> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-ExchangeOn-Premise/blob/main/Logo.png?raw=true">
</p>

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-Prov-Target-Exchange Server On Premises](#helloid-conn-prov-target-exchange-server-on-premises)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
  - [Getting started](#getting-started)
    - [Provisioning PowerShell V2 connector](#provisioning-powershell-v2-connector)
      - [Correlation configuration](#correlation-configuration)
      - [Field mapping](#field-mapping)
      - [Configuring Exchange Management Shell](#configuring-exchange-management-shell)
      - [Connection settings](#connection-settings)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Exchange Server On Premises_ is a _target_ connector. _Exchange Server On Premises_ provides  the option to correlate to existing Exchange On-Premise users and provision groupmemberships and sharedmailbox permissions.
  >__Only Exchange groups are supported, if the group can be managed via AD, we advise to do so__

If you want to create Exchange On-Premise users, please use the **built-in Microsoft Active Directory target system** and make use of the **Exchange Integration**.

The following lifecycle actions are available:


| Action                                                | Description                                                           |
| ----------------------------------------------------- | --------------------------------------------------------------------- |
| create.ps1                                            | PowerShell _create_ lifecycle action                                  |
| permissions/groups/grantPermission.ps1                | PowerShell _grant_ lifecycle action                                   |
| permissions/groups/revokePermission.ps1               | PowerShell _revoke_ lifecycle action                                  |
| permissions/groups/permissions.ps1                    | PowerShell _permissions_ lifecycle action                             |
| permissions/sharedmailboxes/grantPermission.ps1       | PowerShell _grant_ lifecycle action                                   |
| permissions/sharedmailboxes/revokePermission.ps1      | PowerShell _revoke_ lifecycle action                                  |
| permissions/sharedmailboxes/permissions.ps1           | PowerShell _permissions_ lifecycle action                             |
| permissions/dynamicpermissions/dynamicpermissions.ps1 | PowerShell _grant_, _update_ & _revoke_ lifecycle action              |
| permissions/dynamicpermissions/permissions.ps1        | PowerShell _permissions_ lifecycle action                             |
| resources/groups.ps1                                  | PowerShell _resources_ lifecycle action                               |
| resources/sharedmailboxes.ps1                         | PowerShell _resources_ lifecycle action                               |
| configuration.json                                    | Default _configuration.json_                                          |
| fieldMapping.json                                     | Default _fieldMapping.json_                                           |
| postAdAction.create.DisableExchangeActiveSync_OWA.ps1 | Post-AD-action used in builtin AD-connector _create_ lifecycle action |

## Requirements
- Execute the cmdlet **Enable-PsRemoting** on the **Exchange server** to which you want to connect.
- Within **IIS**, under the **Exchange Back End site** for the **Powershell sub-site**, check that the authentication method **Windows Authentication** is **enabled**.
- Permissions to manage the Exchange objects, the default AD group **Organization Management** should suffice, but please change this accordingly.
- Required to run **On-Premises**.
- **Concurrent sessions** in HelloID set to a **maximum of 1**! If this is any higher than 1, this may cause errors, since Exchange only support a maximum of 3 sessions per minute.

## Getting started

### Provisioning PowerShell V2 connector

#### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _Exchange Server On Premises_ to a person in _HelloID_.

To properly setup the correlation:

1. Open the `Correlation` tab.

2. Specify the following configuration:

    | Setting                   | Value                           |
    | ------------------------- | ------------------------------- |
    | Enable correlation        | `True`                          |
    | Person correlation field  | `PersonContext.Person.UserName` |
    | Account correlation field | `Account.UserPrincipalName`     |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

#### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

#### Configuring Exchange Management Shell
By using this connector you will have the ability to manage groupmemberships.
Since we use the cmdlets from the Exchange Management Shell, it is required to Enable-PsRemoting on the Exchange Server, allow Windows Authentication for the IIS site and assign permissions to the service account.
For more information, please check out the [Microsoft docs](https://docs.microsoft.com/en-us/powershell/exchange/control-remote-powershell-access-to-exchange-servers?view=exchange-ps).

#### Connection settings
The following settings are required to connect.

| Setting               | Description                                                                   |
| --------------------- | ----------------------------------------------------------------------------- |
| Connection Uri        | The connection uri of the on-prem Exchange                                    |
| Username              | The username of the service account in Exchange                               |
| Password              | The password of the service account in Exchange                               |
| Authentication Method | The authentication method that is used to authenticate the user's credentials |

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012518799-How-to-add-a-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/828-helloid-provisioning-helloid-conn-prov-target-exchange-on-premise)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
