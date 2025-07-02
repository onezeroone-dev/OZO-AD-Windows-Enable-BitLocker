# OZO PowerShell Script Template
## Description
Reads a JSON configuration file and produces an Excel report.

## Installation
This script is published to [PowerShell Gallery](https://learn.microsoft.com/en-us/powershell/scripting/gallery/overview?view=powershell-5.1). Ensure your system is configured for this repository then execute the following in an _Administrator_ PowerShell:

```powershell
Install-Script ozo-powershell-script-template
```

## Usage
```powershell
ozo-powershell-script-template
```

## Parameters
|Parameter|Description|
|---------|-----------|
|`Configuration`|Path to the JSON configuration file. Defaults to `ozo-powershell-script-template.json` in the same directory as the script.|
|`OutDir`|Directory for the Excel report. Defaults to the current directory.|

## Outputs
None.

## Notes
None.

## Acknowledgements
Special thanks to my employer, [Sonic Healthcare USA](https://sonichealthcareusa.com), who supports the growth of my PowerShell skillset and enables me to contribute portions of my work product to the PowerShell community.
