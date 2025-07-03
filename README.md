# OZ AD Windows Enable BitLocker Deployment, Installation, and Usage
Enables BitLocker on all local fixed volumes after verifying that the endpoint meets the BitLocker prerequisites and has successfully recorded a recovery password in Active Directory. This script is executed on the endpoint either manually or with an endpoint management tool like Intune or Tanium.

For guidance on understanding, configuring, and managing BitLocker in an Active Directory environment, please see [GUIDE.md](.\GUIDE.md).

## Prerequisites
This script requires the _BitLocker_ and _TrustedPlatformModule_ PowerShell modules which should be present on all recent Windows Education, Enterprise, and Pro editions.

## Deployment
To use this script with an Endpoint Management (software deployment) tool, download the [latest release](https://github.com/onezeroone-dev/OZO-Windows-Enable-BitLocker/releases) and deploy according to the requirements of your chosen endpoint management tool. Alternatively, you could issue a command to your endpoints to install the script (as detailed in Installation, below) and then reference the script installation location in your endpoint management tool deployment command.

## Installation
This script is published to [PowerShell Gallery](https://learn.microsoft.com/en-us/powershell/scripting/gallery/overview?view=powershell-5.1). Ensure your system is configured for this repository then execute the following in an _Administrator_ PowerShell:

```powershell
Install-Script ozo-ad-windows-enable-bitlocker
```

## Usage
```
ozo-ad-windows-enable-bitlocker
     -GPOName <String>
    [-Restart]
    [-SkipSecureBootCheck]
```

| Parameter | Description |
| ------ | ------ |
|`GPOName`|The name of the group policy containing the BitLocker settings. The script will proceed only if this GPO is applied.|
|`Restart`|Restarts the computer after enabling BitLocker to perform the hardware test and begin encrypting.|
|`SkipSecureBootCheck`|By default, the script will proceed only if Secure Boot is enabled, however, Secure Boot is not a strict requirement for enabling BitLocker. Specifying this parameter will allow the script to continue even if Secure Boot if `off`.|

## Examples
### Example 1 - Endpoint Management Tool Deployment Command
```cmd
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -NoProfile -File ozo-ad-windows-enable-bitlocker.ps1 -GPOName "OZO BitLocker Settings Policy" -SkipSecureBootCheck
```
### Example 2 - Manual Execution in an _Administrator_ PowerShell
```powershell
ozo-ad-windows-enable-bitlocker -GPOName "All Workstations Settings" -Restart
```

## Logging
Messages are written to the Windows Event Viewer _One Zero One_ provider. When this provider is not available, messages are written to the _Microsoft-Windows-PowerShell_ provider with Event ID 4100.
