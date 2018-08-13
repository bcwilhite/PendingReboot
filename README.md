# PendingReboot

Module to detect Windows OS pending reboots.

This module leverages WMI in order to query the Registry for various pending reboot detections.

## How to use

Deploy the root folder to you PSModulePath, i.e. PendingReboot and PowerShelll will automatically find/load the module.

## Functions

* **Test-PendingReboot** Test the pending reboot status on a local and/or remote computer.

### Test-PendingReboot

* **ComputerName**: A single computer name or an array of computer names.  The default is localhost ($env:COMPUTERNAME).
* **Credential**: Specifies a user account that has permission to perform this action. The default is the current user. Type a username, such as User01, Domain01\User01, or User@Contoso.com. Or, enter a PSCredential object, such as an object that is returned by the Get-Credential cmdlet. When you type a user name, you are prompted for a password.
* **Detailed**: Indicates that this function returns a detailed result of pending reboot information, why the system is pending a reboot, not just a true/false response.
* **SkipConfigurationManagerClientCheck**: Indicates that this function will not test the Client SDK WMI class that is provided by the System Center Configuration Manager Client.  This parameter is useful when SCCM is not used/installed on the targeted systems.
* **SkipPendingFileRenameOperationsCheck**: Indicates that this function will not test the PendingFileRenameOperations MultiString Value property of the Session Manager registry key.  This parameter is useful for eliminating possible false positives. Many Anti-Virus packages will use the PendingFileRenameOperations MultiString Value in order to remove stale definitions and/or .dat files.

## Versions

### 0.9.0.0

* Initial Release with major changes from the TechNet Gallery
  * The function/module received a major overhaul since coming over from the technet gallary.
  * The function is no longer called "Get-PendingReboot", instead "Test-PendingReboot" is more appropriate.
  * **Breaking Change** Test-PendingReboot has all new property names to be more inline with what it is testing.
  * New Parameters were introduced:
    * SkipConfigurationManagerClientCheck - Allows users to skip the CCM Client SDK WMI query, since not all systems will have an SCCM Agent installed.
    * SkipPendingFileRenameOperations - Allows users to skip the PendingFileRenameOperations check, since this MultiString Value generates false-positives.
    * Credential - By popular demand, this parameter will allow the user to connect with alternate credentials.

## Examples

### Test the pending reboot status of the local computer

```PowerShell
PS C:\> Test-PendingReboot

ComputerName IsRebootPending
------------ ---------------
WKS01                   True
```

### Test the pending reboot status of a local computer, returning only a bool value

```PowerShell
PS C:\> (Test-PendingReboot).IsRebootPending
True
```

### Test the pending reboot status of a remote computer called 'DC01' and return detailed information

```PowerShell
PS C:\> Test-PendingReboot -ComputerName DC01 -Detailed

ComputerName                     : dc01
ComponentBasedServicing          : True
PendingComputerRenameDomainJoin  : False
PendingFileRenameOperations      : False
PendingFileRenameOperationsValue :
SystemCenterConfigManager        : False
WindowsUpdateAutoUpdate          : True
IsRebootPending                  : True
```

### Test the pending reboot status of a remote computer called 'DC01', with detialed information, skipping System Center Configuration Manager Agent and PendingFileRenameOperation Checks

```PowerShell
PS C:\> Test-PendingReboot -ComputerName DC01 -SkipConfigurationManagerClientCheck -SkipPendingFileRenameOperationsCheck -Detailed

CommputerName                    : dc01
ComponentBasedServicing          : True
PendingComputerRenameDomainJoin  : False
PendingFileRenameOperations      : False
PendingFileRenameOperationsValue :
SystemCenterConfigManager        :
WindowsUpdateAutoUpdate          : True
IsRebootPending                  : True
```
