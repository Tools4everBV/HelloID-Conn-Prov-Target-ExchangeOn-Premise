| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |
<br />

<p align="center">
  <img src="https://user-images.githubusercontent.com/69046642/160915847-b8a72368-931c-45d1-8f93-9cc7bb974ca8.png">
</p>

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2022/03/30  |
| 1.1.0   |Added permissions to shared mailboxes as entitlements | 2022/04/13  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Table of Contents](#table-of-contents)
- [Requirements](#requirements)
- [Introduction](#introduction)
- [Configuring Exchange](#configuring-exchange-management-shell)
- [Connection settings](#connection-settings)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)

## Requirements
- Execute the cmdlet **Enable-PsRemoting** on the **Exchange server** to which you want to connect.
- Within **IIS**, under the **Exchange Back End site** for the **Powershell sub-site**, check that the authentication method **Windows Authentication** is **enabled**.
- Permissions to manage the Exchange objects, the default AD group **Organization Management** should suffice, but please change this accordingly.
- Required to run **On-Premises**.
- **Concurrent sessions** in HelloID set to a **maximum of 1**! If this is any higher than 1, this may cause errors, since Exchange only support a maximum of 3 sessions per minute.

## Introduction
For this connector we have the option to correlate to existing Exchange On-Premise users and provision groupmemberships.
  >__Only Exchange groups are supported, if the group can be managed via AD, we advise to do so__

If you want to create Exchange On-Premise users, please use the **built-in Microsoft Active Directory target system** and make use of the **Exchange Integration**.

<!-- GETTING STARTED -->
## Configuring Exchange Management Shell
By using this connector you will have the ability to manage groupmemberships.
Since we use the cmdlets from the Exchange Management Shell, it is required to Enable-PsRemoting on the Exchange Server, allow Windows Authentication for the IIS site and assign permissions to the service account.
For more information, please check out the [Microsoft docs](https://docs.microsoft.com/en-us/powershell/exchange/control-remote-powershell-access-to-exchange-servers?view=exchange-ps).

### Connection settings
The following settings are required to connect.

| Setting     | Description |
| ------------ | ----------- |
| Connection Uri | The connection uri of the on-prem Exchange |
| Username | The username of the service account in Exchange |
| Password | The password of the service account in Exchange |
| Authentication Method | The authentication method that is used to authenticate the user's credentials |

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012518799-How-to-add-a-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/provisioning/828-helloid-provisioning-helloid-conn-prov-target-exchange-on-premise)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
