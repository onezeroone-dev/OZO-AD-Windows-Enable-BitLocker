#Requires -Version 5.1 -RunAsAdministrator

<#PSScriptInfo
    .VERSION 1.0.0
    .GUID c253d6ab-fb10-4d07-b03c-f2b630a39fa1
    .AUTHOR Andy Lievertz <alievertz@onezeroone.dev>
    .COMPANYNAME One Zero One
    .COPYRIGHT This script is released under the terms of the GNU General Public License ("GPL") version 2.0.
    .TAGS 
    .LICENSEURI https://github.com/onezeroone-dev/OZO-AD-Windows-Enable-BitLocker/blob/main/LICENSE
    .PROJECTURI https://github.com/onezeroone-dev/OZO-AD-Windows-Enable-BitLocker
    .ICONURI 
    .EXTERNALMODULEDEPENDENCIES
    .REQUIREDSCRIPTS 
    .EXTERNALSCRIPTDEPENDENCIES 
    .RELEASENOTES https://github.com/onezeroone-dev/OZO-AD-Windows-Enable-BitLocker/blob/main/CHANGELOG.md
#>

<#
    .DESCRIPTION 
    Enables BitLocker on all local fixed volumes after verifying that the endpoint meets the BitLocker prerequisites and has successfully recorded a recovery password in Active Directory.
    .PARAMETER GPOName
    The name of the group policy containing the BitLocker settings. The script will proceed only if this GPO is applied.
    .PARAMETER Restart
    Restarts the computer after enabling BitLocker to perform the hardware test and begin encrypting.
    .PARAMETER SkipSecureBootCheck
    By default, the script will proceed only if Secure Boot is enabled, however, Secure Boot is not a strict requirement for enabling BitLocker. Specifying this parameter will allow the script to continue even if Secure Boot if off.
    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NonInteractive -NoProfile -File ozo-ad-windows-enable-bitlocker.ps1 -GPOName "OZO BitLocker Settings Policy" -SkipSecureBootCheck
    .EXAMPLE
    ozo-ad-windows-enable-bitlocker -GPOName "All Workstations Settings" -Restart
    .LINK
    https://github.com/onezeroone-dev/OZO-AD-Windows-Enable-BitLocker/blob/main/README.md
    .NOTES
    Messages are written to the Windows Event Viewer "One Zero One" provider. When this provider is not available, messages are written to the Microsoft-Windows-PowerShell provider with Event ID 4100.
#>

# PARAMETERS
[CmdletBinding(SupportsShouldProcess = $true)] Param (
    [Parameter(Mandatory=$true,HelpMessage="BitLocker settings GPO name")][String]$GPOName,
    [Parameter(Mandatory=$false,HelpMessage="Restarts the computer after enabling BitLocker")][Switch]$Restart,
    [Parameter(Mandatory=$false,HelpMessage="Disables checking if Secure Boot is on")][Switch]$SkipSecureBootCheck
)

# CLASSES
Class OZOMain {
    # PROPERTIES: Booleans, Strings
    [Boolean] $Restart     = $false
    [Boolean] $skipSBCheck = $false
    [XML]     $rsopXml     = $null
    # PROPERTIES: Lists
    [System.Collections.Generic.List[PSCustomObject]] $blVolumes = @()
    # METHODS: Constructor method
    OZOMain($GPOName,$Restart,$SkipSecureBootCheck) {
        # Set properties
        $this.Restart = $Restart
        # Letting skipSBCheck = $true for now - once we work out how to relaunch in 64-bit with parameters passed, this can be uncommented
        $this.skipSBCheck = $SkipSecureBootCheck
        # Declare ourselves to the world
        Write-OZOProvider -Message "Starting process." -Level "Information"
        # Determine if the environment validates, the GPO is refreshed, the required GPO is adopted, [Secure Boot is enabled], and the TPM is good
        If (($this.ValidateEnvironment() -And $this.GenerateRSoP() -And $this.EvaluateGPOSettings($GPOName) -And $this.EvaluateSecureBoot() -And $this.EvaluateTPM()) -eq $true) {
            # The environment validates, the GPO is refreshed, the required GPO is adopted, [Secure Boot is enabled], and the TPM is good; iterate on the BitLocker volume mount points
            ForEach ($mountPoint in (Get-BitLockerVolume).MountPoint) {
                # Determine if mount point is a letter
                If (($mountPoint -Split(":"))[0] -CMatch "^[A-Z]") {
                    # Create an OZOBLVolume object for this mount point
                    $this.blVolumes.Add(([OZOBLVolume]::new($mountPoint)))
                }
            }
            # Call RestartComputer to determine if a restart is requested and (if yes) execute it
            $this.RestartComputer()
        }
        # Declare ourselves to the world
        Write-OZOProvider -Message "Process complete." -Level "Information"
    }
    # METHODS: Environment validation method
    Hidden [Boolean] ValidateEnvironment() {
        # Control variable
        [Boolean] $Return = $true
        # Try to quietly import the BitLocker module
        Try {
            Import-Module -Name "BitLocker" -ErrorAction Stop *> $null
            # Success
        } Catch {
            # Failure
            Write-OZOProvider -Message "Error importing the BitLocker module." -Level "Error"
            $Return = $false
        }
        # Try to quietly import the TrustedPlatformModule module
        Try {
            Import-Module -Name "TrustedPlatformModule" -ErrorAction Stop *> $null
            # Success
        } Catch {
            # Failure
            Write-OZOProvider -Message "Error importing the TrustedPlatformModule module." -Level "Error"
            $Return = $false
        }
        # Return
        return $Return
    }
    # METHODS: Generate RSoP  method
    Hidden [Boolean] GenerateRSoP() {
        # Control variable
        [Boolean] $Return = $true
        # Local variables
        [String]$rsopXmlPath = (Join-Path -Path $Env:windir -ChildPath ("Temp\" + (New-Guid).Guid + "-RSoP.xml"))
        # Try to generate an RSoP
        Try {
            Start-Process -FilePath (Join-Path -Path $Env:windir -ChildPath "System32\gpresult.exe") -ArgumentList "/scope","computer","/X",$rsopXmlPath -NoNewWindow -Wait -ErrorAction Stop
            # Success; try to read in XML
            Try {
                $this.rsopXml = [Xml](Get-Content -Path $rsopXmlPath -ErrorAction Stop)
                # Success; try to remove the file
                Try {
                    Remove-Item -Force -Path $rsopXmlPath -ErrorAction Stop
                    # Success
                } Catch {
                    Write-OZOProvider -Message ("Failed to remove temporary RSoP XML results file, " + $rsopXmlPath + ".") -Level "Warning"
                }
            } Catch {
                # Failure
                Write-OZOProvider -Message ("Failed to read RSoP XML results file, " + $rsopXmlPath + ".") -Level "Warning"
            }
        } Catch {
            # Failure
            Write-OZOProvider -Message ("Failed to generate RSoP XML results file. Error message is: " + $_) -Level "Warning"
            $Return = $false
        }
        # Return
        return $Return
    }
    # METHODS: Evaluate GPO settings method
    Hidden [Boolean] EvaluateGPOSettings($GPOName) {
        # Control variable
        [Boolean] $Return = $true
        # Determine if the GPO name appears in the RSoP XML
        If ($this.rsopXml.Rsop.ComputerResults.GPO.Name -Contains $GPOName) {
            # GPO Name appears in the XML; determine if it is access denied
            If (($this.rsopXml.Rsop.ComputerResults.GPO | Where-Object {$_.Name -eq $GPOName}).AccessDenied -eq $true) {
                # Access is denied
                Write-OZOProvider -Message ("Access is denied to " + $GPOName + ".") -Level "Error"
                $Return = $false
            }
        } Else {
            # GPO Name does not appear in the XML
            Write-OZOProvider -Message ($GPOName + " not found.") -Level "Error"
            $Return = $false
        }
        # Return
        return $Return
    }
    # METHODS: Evaluate SecureBoot method
    Hidden [Boolean] EvaluateSecureBoot() {
        # Control variable
        [Boolean] $Return = $true
        # Determine if we are not skipping Secure Boot check
        If ($this.skipSBCheck -eq $false) {
            # We are not skipping Secure Boot check; determine if SecureBoot is present and enabled
            Try {
                Confirm-SecureBootUEFI -ErrorAction Stop
                # Success
            } Catch {
                # Failure
                Write-OZOProvider -Message "UEFI Secure Boot is present and disabled or not present." -Level "Error"
                $Return = $false
            }
        }
        # Return
        return $return
    }
    # METHODS: Evaluate TPM method
    Hidden [Boolean] EvaluateTPM() {
        # Control variable
        [Boolean] $Return = $true
        # Local variable
        [PSCustomObject] $Tpm = $null
        # Try to get the TPM
        Try {
            $Tpm = (Get-Tpm -ErrorAction Stop)
            # Success; determine if TPM
            If (((Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm).SpecVersion -Split(",")) -Contains "2.0") {
                # TPM 2.0; determine if it does not meet requirements
                If (($Tpm.TpmPresent -And $Tpm.TpmReady -And $Tpm.TpmEnabled -And $Tpm.TpmActivated) -eq $false) {
                    # One or more requirements not met
                    Write-OZOProvider -Message "TPM 2.0 is not present and ready and enabled and activated." -Level "Error"
                    $Return = $false
                }
            } Else {
                # TPM 1.2; determine if it does not meet requirements
                If (($Tpm.TpmPresent -And $Tpm.TpmReady) -eq $false) {
                    # One or more requirements not met
                    Write-OZOProvider -Message "TPM 1.2 is not present and ready." -Level "Error"
                    $Return = $false
                }
            }
        } Catch {
            # Failure
            Write-OZOProvider -Message "TPM not found." -Level "Error"
            $Return = $false
        }
        # Return
        return $Return
    }
    # METHODS: RestartComputer method
    Hidden [Void] RestartComputer() {
        # Determine if the operator requested restart
        If ($this.Restart -eq $true) {
            # Operator requested restart
            Write-OZOProvider -Message "Computer will restart in 30 seconds." -Level "Warning"
            # Sleep for 30 seconds
            Start-Sleep -Seconds 30
            # Force restart
            Restart-Computer -Force
        }
    }
}

Class OZOBLVolume {
    # PROPERTIES: Booleans and Strings
    [Boolean] $Validates  = $false
    [String]  $mountPoint = $null
    # PROPERTIES: System Objects
    [System.Object] $blVolume  = $null
    [System.Object] $phyVolume = $null
    # METHODS: Constructor Method
    OZOBLVolume([String]$MountPoint) {
        # Set properties
        $this.mountPoint = $MountPoint
        # Read the volume
        $this.ReadVolume()
        # Switch on DriveType + VolumeStatus + ProtectionStatus
        Switch -Wildcard ($this.phyVolume.DriveType + " " + $this.blVolume.VolumeStatus + " " + $this.blVolume.ProtectionStatus) {
            ("Removable*") {
                # Removable disk; do nothing
                Write-OZOProvider -Message ($this.blVolume.MountPoint + " is a removable disk; skipping") -Level "Warning"
            }
            ("Fixed FullyEncrypted On") {
                # Fixed disk with BitLocker enabled and Protectionstatus on; determine if protection is not TPM + RecoveryPassword
                If ($this.blVolume.KeyProtector.KeyProtectorType -NotContains "Tpm" -And $this.blVolume.KeyProtector.KeyProtectorType -NotContains "RecoveryPassword") {
                    # Volume does not have the correct protectors; decrypt then encrypt with proper protectors
                    Write-OZOProvider -Message ($this.blVolume.MountPoint + " is encrypted but does not have the correct protectors; decrypting then re-encrypting.") -Level "Warning"
                    $this.DisableBitLocker()
                    $this.EnableBitLocker()
                } Else {
                    # Volume has correct protectors
                    Write-OZOProvider -Message ($this.blVolume.MountPoint + " is encrypted and already has the correct protectors; skipping") -Level "Information"
                }
            }
            ("Fixed FullyEncrypted Off") {
                # Fixed disk with BitLocker enabled but no key protectors; decrypt and encrypt
                Write-OZOProvider -Message ($this.blVolume.MountPoint + " is encrypted but has no protectors; decrypting then re-encrypting.") -Level "Warning"
                $this.DisableBitLocker()
                $this.EnableBitLocker()
            }
            ("Fixed FullyDecrypted Off") {
                # Determine if there are NOT Tpm and RecoveryPassword protectors (Fixed FullyDecrypted Off but with Tpm and RecoveryPassword protectors indicates that BitLocker has been enabled but is pending reboot)
                If ($this.blVolume.KeyProtector.KeyProtectorType -NotContains "Tpm" -And $this.blVolume.KeyProtector.KeyProtectorType -NotContains "RecoveryPassword") {
                    # Fixed disk with no encryption and not pending reboot; encrypt
                    Write-OZOProvider -Message ($this.blVolume.MountPoint + " is not encrypted; encrypting.") -Level "Warning"
                    $this.EnableBitLocker()
                } Else {
                    # Fixed disk with no encryption and pending reboot; skip
                    Write-OZOProvider -Message ($this.blVolume.MountPoint + " is pending reboot; skipping.") -Level "Warning"
                }
            }
            default {
                # Nothing to do
                Write-OZOProvider -Message ($this.blVolume.MountPoint + " meets no criteria (likely already encrypted with correct protectors)") -Level "Information"
            }
        }
        # Reread the volume
        $this.ReadVolume()
    }
    # METHODS: Read volume method
    Hidden [Void] ReadVolume() {
        # Store the BitLocker volume object
        $this.blVolume = (Get-BitLockerVolume -MountPoint $this.mountPoint)
        # Store the physical volume object
        $this.phyVolume = (Get-Volume -DriveLetter ($this.mountPoint -Split(":"))[0])
    }
    # METHODS:
    [Void] EnableBitLocker() {
        # Call ManageTpmProtector, ManageRecoveryPasswordProtector, and BackupKeyProtector to determine if we can enable BitLocker
        If (($this.ManageTpmProtector() -And $this.ManageRecoveryPasswordProtector() -And $this.BackupKeyProtector()) -eq $true) {
            # TPM Protector is managed, RecoveryPassword protector is managed and keys are backed up to AD; enable BitLocker
            Try {
                Enable-BitLocker -MountPoint $this.blVolume.MountPoint -TpmProtector -ErrorAction Stop
                # Success
                Write-OZOProvider -Message ("Enabled Bitlocker on " + $this.blVolume.MountPoint + ".") -Level "Information"
                # Determine if this volume is *not* the OS volume
                If ($this.blVolume.VolumeType -ne "OperatingSystem") {
                    # Volume is not the OS volume; try to enable automagic unlock
                    Try {
                        Enable-BitLockerAutoUnlock -MountPoint $this.blVolume.MountPoint -ErrorAction Stop
                        # Success
                        Write-OZOProvider -Message ("Set auto-unlock for " + $this.blVolume.MountPoint + ".") -Level "Information"
                    } Catch {
                        # Failure
                        Write-OZOProvider -Message ("Error setting auto-unlock on " + $this.blVolume.MountPoint + ". Error message is: " + $_) -Level "Error"
                    }
                }
            } Catch {
                # Failure
                Write-OZOProvider -Message ("Error enabling BitLocker on " + $this.blVolume.MountPoint + ". Error message is: " + $_) -Level "Error"
            }
        }
        # Re-read the volume
        $this.ReadVolume()
    }
    # METHODS: Disable BitLocker method
    Hidden [Boolean] DisableBitLocker() {
        # Control variable
        [Boolean] $Return = $true
        # Try to decrypt
        Try {
            Disable-BitLocker -MountPoint $this.blVolume.MountPoint -ErrorAction Stop
            # Success; wait until decryption is complete
            Do {
                Start-Sleep -Seconds 60
                Write-OZOProvider -Message ("Waiting for decryption to complete on " + $this.blVolume.MountPoint + ".") -Level "Warning"
            } Until ((Get-BitLockerVolume -MountPoint $this.blVolume.MountPoint).VolumeStatus -eq "FullyDecrypted")
            # Decryption complete; log
            Write-OZOProvider -Message ("Decryption of " + $this.blVolume.MountPoint + " is complete.") -Level "Information"
        } Catch {
            # Failure
            Write-OZOProvider -Message ("Decryption of " + $this.blVolume.MountPoint + " failed.") -Level "Error"
            $Return = $false
        }
        # Re-read the volume
        $this.ReadVolume()
        # Return
        return $Return
    }
    # METHODS: Manage TPM Protector method
    Hidden [Boolean] ManageTpmProtector() {
        # Control variable
        $Return = $true
        # Determine if a TPM Protector is defined
        If (($this.blVolume.KeyProtector | Where-Object {$_.KeyprotectorType -eq "Tpm"}).Count -gt 0) {
            # Found existing TPM protector (dealbreaker)
            Write-OZOProvider -Message ("TPM protector for " + $this.blVolume.MountPoint + " already exists; attempting to remove.") -Level "Warning"
            # Try to remove
            ForEach ($keyProtectorID in ($this.blVolume.KeyProtector.KeyProtectorID)) {
                Try {
                    Remove-BitLockerKeyProtector -MountPoint $this.blVolume.MountPoint -KeyProtectorId $keyProtectorID -ErrorAction Stop
                    # Success
                    Write-OZOProvider -Message ("Removed Key Protector ID " + $keyProtectorID + " from " + $this.blVolume.MountPoint + ".") -Level "Information"
                } Catch {
                    # Failure
                    Write-OZOProvider -Message ("Unable to remove Key Protector ID " + $keyProtectorID + " from " + $this.blVolume.MountPoint + "; aborting.") -Level "Error"
                    $Return = $false
                }
            }
        }
        # Re-read the volume
        $this.ReadVolume()
        # Return
        return $Return
    }
    # METHODS: Manage RecoveryPassword Protector method
    Hidden [Boolean] ManageRecoveryPasswordProtector() {
        # Control variable
        $Return = $true
        # Determine if a RecoveryPassword protector exists
        If (($this.blVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}).Count -eq 0) {
            # None found; log
            Write-OZOProvider -Message ("No Recovery Password protector found for " + $this.blVolume.MountPoint + "; attempting to add.") -Level "Information"
            # Try to add a RecoveryPassword protector
            Try {
                Add-BitLockerKeyProtector -MountPoint $this.blVolume.MountPoint -RecoveryPasswordProtector -ErrorAction Stop
                # Success
                Write-OZOProvider -Message ("Added Recovery Password protector for " + $this.blVolume.MountPoint + ".") -Level "Information"
            } Catch {
                # Failure
                Write-OZOProvider -Message ("Error adding Recovery Password protector for " + $this.blVolume.MountPoint + ". Error message is: " + $_) -Level "Error"
                $Return = $false
            }
        }
        # Re-read volume
        $this.ReadVolume()
        # Return
        return $Return
    }
    # METHODS: Backup Key Protector method
    Hidden [Boolean] BackupKeyProtector() {
        # Control variable
        [Boolean] $Return = $true
        # Iterate through all RecoveryPassword protectors and back them up to AD
        ForEach ($keyProtector in ($this.blVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"})) {
            # Try to back up the key protector
            Try {
                Backup-BitLockerKeyProtector -MountPoint $this.blVolume.MountPoint -KeyProtectorId $keyProtector.KeyProtectorID -ErrorAction Stop
                # Success
                Write-OZOProvider -Message ("Recovery Password protector for " + $this.blVolume.MountPoint + " backed up to AD.") -Level "Information"
            } Catch {
                # Failure
                Write-OZOProvider -Message ("Error backing up Recovery Password protector for " + $this.blVolume.MountPoint + " to AD. Error message is: " + $_) -Level "Error"
                $Return = $false
            }
        }
        # Re-read volume
        $this.ReadVolume()
        # Return
        return $Return
    }
}

# FUNCTIONS
Function Write-OZOProvider {
    [CmdLetBinding()] Param(
        [Parameter(Mandatory=$true)] [String] $Message,
        [Parameter(Mandatory=$false)][String] $Level = "Information"
    )
    # Initialize variables
    [String] $Source = $null
    [Int32]  $Id     = 1000
    # Switch on level to set Id
    Switch($Level.ToLower()) {
        "information" { $Id = 1000 }
        "warning"     { $Id = 1001 }
        "error"       { $Id = 1002 }
        default       { $Id = 1000 }
    }
    # Set the script name
    If ([String]::IsNullOrEmpty($MyInvocation.ScriptName)) {
        $Source = "Command-line input:"
    } Else {
        $Source = ((Split-Path -Path $MyInvocation.ScriptName -Leaf) + ":")
    }
    # Try to write to the One Zero One log
    Try {
        # Write to One Zero One and suppress output
        New-WinEvent -ProviderName "One Zero One" -Id $Id -Payload $Source,$Message -ErrorAction Stop
        # Success
    } Catch {
        # Failure; write to Microsoft-Windows-PowerShell and suppress output
        New-WinEvent -ProviderName "Microsoft-Windows-PowerShell" -Id 4100 -Payload $Source,"Script output.",$Message
    }
}

# MAIN
# Determine if this is a 64 bit process
If ([Environment]::Is64BitOperatingSystem -eq $true -And [Environment]::Is64BitProcess -eq $false) {
    # Process is not 64-bit; log
    Write-OZOProvider -Message ("Running in 32-bit PowerShell; attempting to re-launch " + $MyInvocation.InvocationName + " in 64-bit PowerShell") -Level "Warning"
    # Re-launch using 64-bit PowerShell
    Invoke-Expression -Command ((Join-Path -Path $Env:Windir -ChildPath "SysNative\WindowsPowerShell\v1.0\powershell.exe") + " -ExecutionPolicy ByPass -WindowStyle Hidden -NonInteractive -File `"" + $MyInvocation.InvocationName + "`"") -ErrorAction Stop
} Else {
    # OS is 64-bit and PowerShell is 64-bit; log
    Write-OZOProvider -Message "Running in 64-bit PowerShell." -Level "Information"
    # Create a OZOMain object
    [OZOMain]::new($GPOName,$Restart,$SkipSecureBootCheck) | Out-Null
}
