$modulePath = Resolve-Path -Path "$PSScriptRoot\..\..\Public\Test-PendingReboot.ps1"
Import-Module -Name $modulePath.Path

Describe 'Test-PendingReboot' {
    It 'Attempts to query CCM Client Utilities but fails with error' {
        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' } -MockWith {
            throw 'this is a test (CCM)'
        }
        Test-PendingReboot -ErrorVariable err
        $err.Count | Should -Not -Be 0
    }

    It 'Attempts to query the registry via WMI but fails with error' {
        Mock -CommandName Invoke-WmiMethod -MockWith { throw 'this is a test' }
        Test-PendingReboot -ErrorVariable err
        $err.Count | Should -Not -Be 0
    }

    It 'Queries the registry/CCM via Invoke-WmiMethod, seven times' {
        Mock -CommandName Invoke-WmiMethod -MockWith {}
        Test-PendingReboot
        Assert-MockCalled -CommandName Invoke-WmiMethod -Times 7 -Exactly -Scope It
    }

    It 'Queries the registry/CCM via Invoke-WmiMethod, skipping PendingFileRenameOperations, six times' {
        Mock -CommandName Invoke-WmiMethod -MockWith {}
        Test-PendingReboot -SkipPendingFileRenameOperationsCheck
        Assert-MockCalled -CommandName Invoke-WmiMethod -Times 6 -Exactly -Scope It
    }

    It 'Queries the registry via Invoke-WmiMethod, skipping CCM Client Utilities, six times' {
        Mock -CommandName Invoke-WmiMethod -MockWith {}
        Test-PendingReboot -SkipConfigurationManagerClientCheck
        Assert-MockCalled -CommandName Invoke-WmiMethod -Times 6 -Exactly -Scope It
    }

    It 'Queries the registry via Invoke-WmiMethod, skipping both PFRO and CCM, five times' {
        Mock -CommandName Invoke-WmiMethod -MockWith {}
        Test-PendingReboot -SkipConfigurationManagerClientCheck -SkipPendingFileRenameOperationsCheck
        Assert-MockCalled -CommandName Invoke-WmiMethod -Times 5 -Exactly -Scope It
    }

    It 'Queries the registry/CCM via Invoke-WmiMethod with Alternate Credentials' {
        Mock -CommandName Invoke-WmiMethod -MockWith {}
        $password = ConvertTo-SecureString -String 'superSecretPassword' -AsPlainText -Force
        $psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @('userName', $password)
        Test-PendingReboot -Credential $psCredential
        Assert-MockCalled -CommandName Invoke-WmiMethod -Times 7 -Exactly -ParameterFilter { $Credential }
    }

    It 'Queries registry and returns a PSCustomObject (ComputerName & IsRebootPending)' {
        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Component Based Servicing\" } -MockWith {
            return @{
                sNames = @('RebootPending')
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Auto Update\" } -MockWith {
            return @{
                sNames = @('RebootRequired')
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Netlogon" } -MockWith {
            return @{
                sNames = @('JoinDomain', 'AvoidSpnSet')
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*ActiveComputerName\" } -MockWith {
            return 'ActiveComputerName'
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*\ComputerName\" } -MockWith {
            return 'NewComputerName'
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Session Manager\" } -MockWith {
            return @{
                sValue = "OldName, NewName"
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' } -MockWith {
            return @{
                ReturnValue = 0
                IsHardRebootPending = $true
                RebootPending = $true
            }
        }

        $result = Test-PendingReboot
        $result.ComputerName | Should -Be $env:COMPUTERNAME
        $result.IsRebootPending | Should -Be $true
    }

    It 'Queries registry and returns a PSCustomObject (Detailed)' {
        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Component Based Servicing\" } -MockWith {
            return @{
                sNames = @('RebootPending')
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Auto Update\" } -MockWith {
            return @{
                sNames = @('RebootRequired')
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Netlogon" } -MockWith {
            return @{
                sNames = @('JoinDomain', 'AvoidSpnSet')
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*ActiveComputerName\" } -MockWith {
            return 'ActiveComputerName'
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*\ComputerName\" } -MockWith {
            return 'NewComputerName'
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $ArgumentList[1] -like "*Session Manager\" } -MockWith {
            return @{
                sValue = "OldName, NewName"
            }
        }

        Mock -CommandName Invoke-WmiMethod -ParameterFilter { $Name -eq 'DetermineifRebootPending' } -MockWith {
            return @{
                ReturnValue = 0
                IsHardRebootPending = $true
                RebootPending = $true
            }
        }

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
