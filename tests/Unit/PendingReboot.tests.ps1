#region HEADER
$script:projectPath = "$PSScriptRoot\..\.." | Convert-Path
$script:projectName = (Get-ChildItem -Path "$script:projectPath\*\*.psd1" | Where-Object -FilterScript {
        ($_.Directory.Name -match 'source|src' -or $_.Directory.Name -eq $_.BaseName) -and
        $(try { Test-ModuleManifest -Path $_.FullName -ErrorAction Stop } catch { $false })
    }).BaseName

$script:parentModule = Get-Module -Name $script:projectName -ListAvailable | Select-Object -First 1
$script:subModuleName = (Split-Path -Path $PSCommandPath -Leaf) -replace '\.Tests.ps1'

Remove-Module -Name $script:parentModule -Force -ErrorAction 'SilentlyContinue'
Import-Module $script:parentModule -Force -ErrorAction 'Stop'
#endregion HEADER

InModuleScope $script:parentModule {
    Describe 'Test-PendingReboot' {
        Context 'CMM Client Utilities error handling' {
            It 'Attempts to query CCM Client Utilities but fails with a warning' {
                Mock -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' } -MockWith {
                    throw 'this is a test (CCM)'
                }
                Test-PendingReboot -ErrorVariable err
                $err.Count | Should -Not -Be 0
            }
        }

        Context 'Generic error handling' {
            It 'Attempts to query the registry via WMI but fails with error' {
                Mock -CommandName Invoke-WmiMethod -MockWith { throw 'this is a test' }
                Test-PendingReboot -ErrorVariable err
                $err.Count | Should -Not -Be 0
            }
        }

        Context 'Testing specific number of Invoke-WmiMethod cmdlet calls' {
            Mock -Verifiable -CommandName Invoke-WmiMethod -MockWith {}

            It 'Queries the registry/CCM via Invoke-WmiMethod, seven times' {
                Test-PendingReboot
                Assert-MockCalled -CommandName Invoke-WmiMethod -Times 7 -Exactly -Scope It
            }

            It 'Queries the registry/CCM via Invoke-WmiMethod, skipping PendingFileRenameOperations, six times' {
                Test-PendingReboot -SkipPendingFileRenameOperationsCheck
                Assert-MockCalled -CommandName Invoke-WmiMethod -Times 6 -Exactly -Scope It
            }

            It 'Queries the registry via Invoke-WmiMethod, skipping CCM Client Utilities, six times' {
                Test-PendingReboot -SkipConfigurationManagerClientCheck
                Assert-MockCalled -CommandName Invoke-WmiMethod -Times 6 -Exactly -Scope It
            }

            It 'Queries the registry via Invoke-WmiMethod, skipping both PFRO and CCM, five times' {
                Test-PendingReboot -SkipConfigurationManagerClientCheck -SkipPendingFileRenameOperationsCheck
                Assert-MockCalled -CommandName Invoke-WmiMethod -Times 5 -Exactly -Scope It
            }

            It 'Queries the registry/CCM via Invoke-WmiMethod with Alternate Credentials, seven times' {
                $password = ConvertTo-SecureString -String 'superSecretPassword' -AsPlainText -Force
                $psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @('userName', $password)
                Test-PendingReboot -Credential $psCredential
                Assert-MockCalled -CommandName Invoke-WmiMethod -Times 7 -Exactly -ParameterFilter { $Credential }
            }
        }

        Context 'PSCustomObject Output all true' {
            Mock -Verifiable -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Component Based Servicing\" } -MockWith {
                return @{
                    sNames = @('CapabilityIndex', 'RebootPending', 'ComponentDetect', 'DelayedPackages', 'Features on Demand')
                }
            }

            Mock -Verifiable -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Auto Update\" } -MockWith {
                return @{
                    sNames = @('CommitRequired', 'LastOnlineScanTimeForAppCategory', 'Power', 'RebootRequired', 'RequestedAppCategories')
                }
            }

            Mock -Verifiable -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Netlogon" } -MockWith {
                return @{
                    sNames = @('JoinDomain', 'AvoidSpnSet')
                }
            }

            Mock -Verifiable -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*ActiveComputerName\" } -MockWith {
                return 'ActiveComputerName'
            }

            Mock -Verifiable -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*\ComputerName\" } -MockWith {
                return 'NewComputerName'
            }

            Mock -Verifiable -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Session Manager\" } -MockWith {
                return @{
                    sValue = "OldName, NewName"
                }
            }

            Mock -Verifiable -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' } -MockWith {
                return @{
                    ReturnValue         = 0
                    IsHardRebootPending = $true
                    RebootPending       = $true
                }
            }

            It 'Queries registry and returns a PSCustomObject (ComputerName & IsRebootPending)' {
                $result = Test-PendingReboot
                $result.ComputerName    | Should -Be $env:COMPUTERNAME
                $result.IsRebootPending | Should -Be $true
            }

            It 'Queries registry and returns a PSCustomObject (Detailed)' {
                $result = Test-PendingReboot -Detailed
                $result.ComputerName                     | Should -Be $env:COMPUTERNAME
                $result.ComponentBasedServicing          | Should -Be $true
                $result.PendingComputerRenameDomainJoin  | Should -Be $true
                $result.PendingFileRenameOperations      | Should -Be $true
                $result.PendingFileRenameOperationsValue | Should -Be "OldName, NewName"
                $result.SystemCenterConfigManager        | Should -Be $true
                $result.WindowsUpdateAutoUpdate          | Should -Be $true
                $result.IsRebootPending                  | Should -Be $true
            }
        }

        Context 'PSCustomObject Output all false' {
            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Component Based Servicing\" } -MockWith {
                return @{
                    sNames = @('CapabilityIndex', 'ComponentDetect', 'DelayedPackages', 'Features on Demand')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Auto Update\" } -MockWith {
                return @{
                    sNames = @('CommitRequired', 'LastOnlineScanTimeForAppCategory', 'Power', 'RequestedAppCategories')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Netlogon" } -MockWith {
                return @{
                    sNames = @('Parameters')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*ActiveComputerName\" } -MockWith {
                return 'ActiveComputerName'
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*\ComputerName\" } -MockWith {
                return 'ActiveComputerName'
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Session Manager\" } -MockWith {
                return @{
                    sValue = $null
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' } -MockWith {
                return @{
                    ReturnValue         = 0
                    IsHardRebootPending = $false
                    RebootPending       = $false
                }
            }

            It 'Queries registry and returns a PSCustomObject (ComputerName & IsRebootPending)' {
                $result = Test-PendingReboot
                $result.ComputerName    | Should -Be $env:COMPUTERNAME
                $result.IsRebootPending | Should -Be $false
            }

            It 'Queries registry and returns a PSCustomObject (Detailed)' {
                $result = Test-PendingReboot -Detailed
                $result.ComputerName                     | Should -Be $env:COMPUTERNAME
                $result.ComponentBasedServicing          | Should -Be $false
                $result.PendingComputerRenameDomainJoin  | Should -Be $false
                $result.PendingFileRenameOperations      | Should -Be $false
                $result.PendingFileRenameOperationsValue | Should -Be $null
                $result.SystemCenterConfigManager        | Should -Be $false
                $result.WindowsUpdateAutoUpdate          | Should -Be $false
                $result.IsRebootPending                  | Should -Be $false
            }
        }

        Context 'Different output values from multiple ComputerName parameter values' {
            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Component Based Servicing\" -and $ComputerName -eq 'WKS01'} -MockWith {
                return @{
                    sNames = @('CapabilityIndex', 'ComponentDetect', 'DelayedPackages', 'Features on Demand')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Component Based Servicing\" -and $ComputerName -eq 'WKS02'} -MockWith {
                return @{
                    sNames = @('CapabilityIndex', 'ComponentDetect', 'DelayedPackages', 'Features on Demand', 'RebootPending')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Auto Update\" -and $ComputerName -eq 'WKS01' } -MockWith {
                return @{
                    sNames = @('CommitRequired', 'LastOnlineScanTimeForAppCategory', 'Power', 'RequestedAppCategories')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Auto Update\" -and $ComputerName -eq 'WKS02' } -MockWith {
                return @{
                    sNames = @('CommitRequired', 'LastOnlineScanTimeForAppCategory', 'Power', 'RebootRequired', 'RequestedAppCategories')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Netlogon" -and $ComputerName -eq 'WKS01' } -MockWith {
                return @{
                    sNames = @('Parameters')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Netlogon" -and $ComputerName -eq 'WKS02' } -MockWith {
                return @{
                    sNames = @('AvoidSpnSet', 'JoinDomain', 'Parameters')
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*ActiveComputerName\" -and $ComputerName -eq 'WKS01' } -MockWith {
                return 'ActiveComputerName'
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*ActiveComputerName\" -and $ComputerName -eq 'WKS02' } -MockWith {
                return 'ActiveComputerName'
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*\ComputerName\" -and $ComputerName -eq 'WKS01' } -MockWith {
                return 'ActiveComputerName'
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*\ComputerName\" -and $ComputerName -eq 'WKS02' } -MockWith {
                return 'NewComputerName'
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Session Manager\" -and $ComputerName -eq 'WKS01' } -MockWith {
                return @{
                    sValue = $null
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Session Manager\" -and $ComputerName -eq 'WKS02' } -MockWith {
                return @{
                    sValue = 'NewName, OldName'
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' -and $ComputerName -eq 'WKS01' } -MockWith {
                return @{
                    ReturnValue         = 0
                    IsHardRebootPending = $false
                    RebootPending       = $false
                }
            }

            Mock -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' -and $ComputerName -eq 'WKS02' } -MockWith {
                throw 'CCM is not present on WKS02'
            }

            It 'Queries registry and returns a PSCustomObject (ComputerName & IsRebootPending)' {
                $result = Test-PendingReboot -ComputerName 'WKS01', 'WKS02'
                $result[0].ComputerName    | Should -Be 'WKS01'
                $result[0].IsRebootPending | Should -Be $false

                $result[1].ComputerName    | Should -Be 'WKS02'
                $result[1].IsRebootPending | Should -Be $true
            }

            It 'Queries registry and returns a PSCustomObject (Detailed)' {
                $result = Test-PendingReboot -ComputerName 'WKS01', 'WKS02' -Detailed
                $result[0].ComputerName                     | Should -Be 'WKS01'
                $result[0].ComponentBasedServicing          | Should -Be $false
                $result[0].PendingComputerRenameDomainJoin  | Should -Be $false
                $result[0].PendingFileRenameOperations      | Should -Be $false
                $result[0].PendingFileRenameOperationsValue | Should -Be $null
                $result[0].SystemCenterConfigManager        | Should -Be $false
                $result[0].WindowsUpdateAutoUpdate          | Should -Be $false
                $result[0].IsRebootPending                  | Should -Be $false

                $result[1].ComputerName                     | Should -Be 'WKS02'
                $result[1].ComponentBasedServicing          | Should -Be $true
                $result[1].PendingComputerRenameDomainJoin  | Should -Be $true
                $result[1].PendingFileRenameOperations      | Should -Be $true
                $result[1].PendingFileRenameOperationsValue | Should -Be 'NewName, OldName'
                $result[1].SystemCenterConfigManager        | Should -Be $null
                $result[1].WindowsUpdateAutoUpdate          | Should -Be $true
                $result[1].IsRebootPending                  | Should -Be $true
            }
        }
    }
}
