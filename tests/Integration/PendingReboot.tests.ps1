#region HEADER
$script:projectPath = "$PSScriptRoot\..\.." | Convert-Path
$script:projectName = (Get-ChildItem -Path "$script:projectPath\*\*.psd1" | Where-Object -FilterScript {
        ($_.Directory.Name -match 'source|src' -or $_.Directory.Name -eq $_.BaseName) -and
        $(try { Test-ModuleManifest -Path $_.FullName -ErrorAction Stop } catch { $false })
    }).BaseName

$script:parentModule = Get-Module -Name $script:projectName -ListAvailable | Select-Object -First 1

Remove-Module -Name $script:parentModule -Force -ErrorAction 'SilentlyContinue'
Import-Module $script:parentModule -Force -ErrorAction 'Stop'
#endregion HEADER

Describe 'Module Manifest Tests' {
    It 'Passes Test-ModuleManifest' {
        Test-ModuleManifest -Path $script:parentModule.Path | Should Not BeNullOrEmpty
        $? | Should Be $true
    }
}

Describe "General project validation: $($script:projectName)" {

    $scripts = Get-ChildItem -Path $script:parentModule.ModuleBase -Include *.ps1, *.psm1, *.psd1 -Recurse

    # TestCases are splatted to the script so we will need hashtables
    $testCase = $scripts | Foreach-Object {@{file = $_}}
    It "Script <file> should be valid powershell" -TestCases $testCase {
        param($file)

        $file.fullname | Should Exist

        $contents = Get-Content -Path $file.fullname -ErrorAction Stop
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
        $errors.Count | Should Be 0
    }
}
