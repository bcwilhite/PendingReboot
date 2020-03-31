# Versions

## [Unreleased]

* Migration to Azure DevOps

## 0.9.0.6

* Fixed a bug when querying multiple computers with different values returned unexpected results.
  * Updated Pester test to account for this type of issue.

## 0.9.0.5

* Added appveyor, build script and psdeploy

## 0.9.0.0

* Initial Release with major changes from the TechNet Gallery
  * The function/module received a major overhaul since coming over from the technet gallary.
  * The function is no longer called "Get-PendingReboot", instead "Test-PendingReboot" is more appropriate.
  * **Breaking Change** Test-PendingReboot has all new property names to be more inline with what it is testing.
  * New Parameters were introduced:
    * SkipConfigurationManagerClientCheck - Allows users to skip the CCM Client SDK WMI query, since not all systems will have an SCCM Agent installed.
    * SkipPendingFileRenameOperations - Allows users to skip the PendingFileRenameOperations check, since this MultiString Value generates false-positives.
    * Credential - By popular demand, this parameter will allow the user to connect with alternate credentials.
