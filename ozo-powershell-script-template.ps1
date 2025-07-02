#Requires -Modules ImportExcel,@{ModuleName="OZO";ModuleVersion="1.5.1"},OZOLogger -Version 5.1

<#PSScriptInfo
    .VERSION 0.0.1
    .GUID *** Generate a new GUID with New-GUID ***
    .AUTHOR Andy Lievertz <alievertz@onezeroone.dev>
    .COMPANYNAME One Zero One
    .COPYRIGHT This script is released under the terms of the GNU General Public License ("GPL") version 2.0.
    .TAGS 
    .LICENSEURI https://github.com/onezeroone-dev/OZO-PowerShell-Script-Template/blob/main/LICENSE
    .PROJECTURI https://github.com/onezeroone-dev/OZO-PowerShell-Script-Template
    .ICONURI 
    .EXTERNALMODULEDEPENDENCIES ImportExcel
    .REQUIREDSCRIPTS 
    .EXTERNALSCRIPTDEPENDENCIES 
    .RELEASENOTES https://github.com/onezeroone-dev/OZO-PowerShell-Script-Template/blob/main/CHANGELOG.md
#>

<# 
    .SYNOPSIS
    See description.
    .DESCRIPTION 
    Reads a JSON configuration file and produces an Excel report.
    .PARAMETER Configuration
    Path to the JSON configuration file. Defaults to "ozo-powershell-script-template.json" in the same directory as the script.
    .PARAMETER OutDir
    Directory for the Excel report. Defaults to the current directory.
    .LINK
    https://github.com/onezeroone-dev/OZO-PowerShell-Script-Template/blob/main/README.md
#>

# PARAMETERS
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory=$false,HelpMessage="Path to the JSON configuration file")][String]$Configuration = (Join-Path -Path $PSScriptRoot -ChildPath "ozo-powershell-script-template.json"),
    [Parameter(Mandatory=$false,HelpMessage="Path for the Excel report")][String]$OutDir = (Get-Location)
)

# CLASSES
Class OZOMain {
    # PROPERTIES: Booleans, Strings
    [Boolean] $Success   = $true
    [String]  $jsonPath  = $null
    [String]  $outDir    = $null
    [String]  $excelPath = $null
    # PROPERTIES: PSCustomObjects
    [PSCustomObject] $Json   = $null
    [PSCustomObject] $Logger = $null
    # PROPERTIES: Lists
    [System.Collections.Generic.List[PSCustomObject]] $Items = @()
    # METHODS
    # Constructor method
    OZOMain($Configuration,$OutDir) {
        # Set properties
        $this.Logger   = (New-OZOLogger)
        $this.jsonPath = $Configuration
        $this.outDir   = $OutDir
        # Log a process start message
        $this.Logger.Write("Starting process.","Information")
        # Determine if the configuation is valid
        If (($this.ValidateConfiguration() -And $this.ValidateEnvironment()) -eq $true) {
            # Call GetItems to generate OZOItem objects from the JSON definition and set Success
            $this.Success = $this.GetItems()
        }
        # Report
        $this.Report()
        # Log a process end message
        $this.Logger.Write(("Process complete."),"Information")
    }
    # JSON validation method
    Hidden [Boolean] ValidateConfiguration() {
        # Control variable
        [Boolean] $Return = $true
        # Check that the jsonPath is valid
        If ((Test-Path -Path $this.jsonPath) -eq $true) {
            # Attempt to read the JSON
            Try {
                $this.Json = (Get-Content $this.jsonPath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
                # Success
            } Catch {
                # Failure
                $this.Logger.Write(("Invalid JSON in " + $this.jsonPath + "."),"Error")
                $Return = $false
            }
        } Else {
            # JSON path is invalid
            $this.Logger.Write(("Could not read configuration file " + $this.jsonPath + "."),"Error")
            $Return = $false
        }
        # Return
        return $Return
    }
    # Environment validation method
    Hidden [Boolean] ValidateEnvironment() {
        # Control variable
        [Boolean] $Return = $true
        # Determine if the outDir exists
        If ([Boolean](Test-Path -Path $this.outDir) -eq $true) {
            # Output directory exists; set the Excel path
            $this.excelPath = (Join-Path -Path $this.outDir -ChildPath ((Get-OZO8601Date -Time) + "-" + $this.Json.ExcelFileName))
        } Else {
            # Output directory does not exist; report
            $this.Logger.Write(("Output directory is invalid or inaccessible."),"Error")
            $Return = $false
        }
        # Return
        return $Return
    }
    # GetItems method
    Hidden [Boolean] GetItems() {
        # Control variable
        [Boolean] $Return = $true
        # Iterate through the items in the JSON
        ForEach ($Item in $this.Json.Items) {
            # Create an instance of the OZOItem class (an object)
            $this.Items.Add(([OZOItem]::new($Item)))
        }
        # Determine that if the Item object count is not equal to the configuration item count
        If ($this.Items.Count -ne $this.Json.Items.Count) {
            # Item object count does not match configuration item count
            $this.Success = $false
        }
        # Return
        return $Return
    }
    # Report method
    Hidden [Void] Report() {
        # Determine if any Items were created
        If ($this.Items.Count -gt 0) {
            # At least one Item was processed; output selected object properties to Excel
            $this.Items | Select-Object -Property itemName,Validates,@{Name="Messages";Expression={$_.Messages -Join "; "}} | Export-Excel -WorksheetName $this.Json.ExcelWorksheetName -Path $this.excelPath
            $this.Logger.Write(("See " + $this.excelPath + " for results."),"Information")
        }
    }
}

Class OZOItem {
    # PROPERTIES: Booleans, Strings
    [Boolean] $Validates = $true
    [String]  $itemName  = $null
    # PROPERTIES: Lists
    [System.Collections.Generic.List[String]] $Messages = @()
    # METHODS
    # Constructor method
    OZOItem($Item) {
        # Set properties
        $this.itemName = $Item
        # Log
        $this.Messages.Add("Created new object of the OZOItem class called " + $Item)
    }
}

# Create a Main object
[OZOMain]::new($Configuration,$OutDir) | Out-Null
