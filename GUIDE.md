# OZO AD Windows Enable BitLocker Guide
All screenshots and examples in this guide were produced in an instance of the [OZO Active Directory Lab](https://onezeroone.dev/active-directory-lab-part-i-introduction/).

## Contents
* [Overview of BitLocker in an Active Directory Environment](#overview-of-bitlocker-in-an-active-directory-environment)
* [Defining BitLocker Settings with Group Policy](#defining-bitlocker-settings-with-group-policy)
* [Delegating Access to BitLocker Recovery Information in Active Directory](#delegating-access-to-bitlocker-recovery-information-in-active-directory)

## Overview of BitLocker in an Active Directory Environment
To use BitLocker in a Microsoft Windows Active Directory environment:

* BitLocker settings are configured using Group Policy.
* BitLocker recovery information can be backed up to the corresponding computer object to aid with recovery operations and meet with compliance requirements.

## Defining BitLocker Settings with Group Policy
BitLocker settings are found in Group Policy Management Editor by navigating to _Computer Configuration > Policies > Administrative Templates > Windows Components > BitLocker Drive Encryption_:

<img src=".\BitLocker-GPME.png" width=800>

See Microsoft's [Configure BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure?tabs=common) article for guidance on configuring BitLocker. Among other settings, you can define the encryption type and ensure that recovery information is stored on the corresponding Active Directory computer object before encrypting, e.g:

<img src=".\BitLocker-Settings-GPResults.jpeg" width=800>

## Delegating Access to BitLocker Recovery Information in Active Directory
BitLocker recovery information is stored in the corresponding AD computer object on the _BitLocker Recovery_ tab:

<img src=".\BitLocker-Computer-Object-Recovery-Information.png" width=400>

The _tab_ will appear for all _Active Directory Users and Computers_ users, however the _information on this tab_ will appear--by default--for only the members of the _Domain Admins_ group. You can delegate read access to this information to other users and groups to enable them to perform recovery operations. To perform the delegation:

1. Open _Active Directory Users and Computers_.
1. Locate and right-click the OU containing computer objects and select _Delegate Control..._

    <img src=".\BitLocker-Delegation-01.png" width=400>

1. Add the desired users or groups and click _Next_.

    <img src=".\BitLocker-Delegation-02.png" width=400>

1. Select _Create a custom task to delegate_ and click _Next_.

    <img src=".\BitLocker-Delegation-03.png" width=400>

1. Select _Only the following objects in the folder_, check _msFVE-RecoveryInformation objects_, and click _Next_.

    <img src=".\BitLocker-Delegation-04.png" width=400>

1. Check _Read_ and click _Next_.

    <img src=".\BitLocker-Delegation-05.png" width=400>

1. Click _Finish_.
