task . Clean, Build, Tests, Stats, DeployToGallery
task Tests ImportCompipledModule, Pester
task CreateManifest CopyPSD
task Build Compile, CreateManifest, UpdatePublicFunctionsToExport, CopyLocalization
task Stats RemoveStats, WriteStats

$script:moduleName = Split-Path -Path $PSScriptRoot -Leaf
$script:moduleRoot = $PSScriptRoot
$script:outPutFolder = "$PSScriptRoot\Release"
$script:releaseModulePath = Join-Path -Path $script:outPutFolder  -ChildPath $script:moduleName
$script:importFolders = @('Public','Private','Classes')
$script:psmPath = Join-Path -Path $PSScriptRoot -ChildPath "Release\$($script:moduleName)\$($script:moduleName).psm1"
$script:psdPath = Join-Path -Path $PSScriptRoot -ChildPath "Release\$($script:moduleName)\$($script:moduleName).psd1"
$script:ps1XmlPath  = Join-Path -Path $PSScriptRoot -ChildPath "Release\$($script:moduleName)\$($script:moduleName).Format.ps1xml"
$script:localizationPath = Join-Path -Path $PSScriptRoot -ChildPath "Release\$($script:moduleName)\Docs\en-US"
$script:publicFolder = 'Public'

task Clean {
    if (-not(Test-Path $script:outPutFolder))
    {
        New-Item -ItemType Directory -Path $script:outPutFolder > $null
    }

    Remove-Item -Path "$($script:outPutFolder)\*" -Force -Recurse
}

$compileParams = @{
    Inputs = {
        foreach ($folder in $script:importFolders)
        {
            Get-ChildItem -Path $folder -Recurse -File -Filter '*.ps1'
        }
    }

    Output = {
        $script:psmPath
    }
}

task Compile @compileParams {
    if (Test-Path -Path $script:psmPath)
    {
        Remove-Item -Path $script:psmPath -Recurse -Force
    }

    New-Item -Path $script:psmPath -Force > $null

    $addContentParams = @{
        Value    = '$script:localizedData = Import-LocalizedData -BaseDirectory "$PSScriptRoot\Docs\en-US" -FileName ' + $script:moduleName + '.strings.psd1'
        Encoding = 'utf8'
        Path     = $script:psmPath
    }
    Add-Content @addContentParams

    foreach ($folder in $script:importFolders)
    {
        $currentFolder = Join-Path -Path $script:moduleRoot -ChildPath $folder
        Write-Verbose -Message "Checking folder [$currentFolder]"

        if (Test-Path -Path $currentFolder)
        {
            $files = Get-ChildItem -Path $currentFolder -File -Filter '*.ps1'
            foreach ($file in $files)
            {
                Write-Verbose -Message "Adding $($file.FullName)"
                Get-Content -Path $file.FullName -Raw | Out-File -FilePath $script:psmPath -Append -Encoding utf8
            }
        }
    }
}

task CopyPSD {
    New-Item -Path (Split-Path $script:psdPath) -ItemType Directory -ErrorAction 0
    $copy = @{
        Path        = "$($script:moduleName).psd1"
        Destination = $script:psdPath
        Force       = $true
        Verbose     = $true
    }
    Copy-Item @copy
}

task CopyFormatXml {
    $copy = @{
        Path        = "$($script:moduleName).Format.ps1xml"
        Destination = $script:ps1XmlPath
        Force       = $true
        Verbose     = $true
    }
    Copy-Item @copy
}

task CopyLocalization {
    $copy = @{
        Path        = "Docs\en-US"
        Destination = $script:localizationPath
        Force       = $true
        Verbose     = $true
        Container   = $true
        Recurse     = $true
    }
    Copy-Item @copy
}

task UpdatePublicFunctionsToExport -if (Test-Path -Path $script:publicFolder) {
    $publicFunctions = (Get-ChildItem -Path $script:publicFolder).BaseName
    Set-ModuleFunctions -Name $script:releaseModulePath -FunctionsToExport $publicFunctions
}

task ImportCompipledModule -if (Test-Path -Path $script:psmPath) {
    Get-Module -Name $script:moduleName | Remove-Module -Force
    Import-Module -Name $script:psdPath -Force
}

task Pester {
    $resultFile = "{0}\testResults{1}.xml" -f $script:outPutFolder, (Get-date -Format 'yyyyMMdd_hhmmss')
    $testFolder = Join-Path -Path $PSScriptRoot -ChildPath 'Tests\*'
    Invoke-Pester -Path $testFolder -OutputFile $resultFile -OutputFormat NUnitxml
}

task RemoveStats -if (Test-Path -Path "$($script:outPutFolder)\stats.json") {
    Remove-Item -Force -Verbose -Path "$($script:outPutFolder)\stats.json" -ErrorAction 0
}

task WriteStats {
    $folders = Get-ChildItem -Directory |
        Where-Object {$PSItem.Name -ne 'Output'}

    $stats = foreach ($folder in $folders)
    {
        $files = Get-ChildItem "$($folder.FullName)\*" -File
        if($files)
        {
            Get-Content -Path $files |
            Measure-Object -Word -Line -Character |
            Select-Object -Property @{N = "FolderName"; E = {$folder.Name}}, Words, Lines, Characters
        }
    }
    $stats | ConvertTo-Json > "$script:outPutFolder\stats.json"
}

task DeployToGallery {
    Set-BuildEnvironment
    # Gate deployment
    if (
        $env:BHBuildSystem -ne 'Unknown' -and
        $env:BHBranchName -eq "master" -and
        $env:BHCommitMessage -match '!deploy'
    )
    {

        Install-Module psdeploy -Force

        $Params = @{
            Path  = $PSScriptRoot
            Force = $true
        }

        Invoke-PSDeploy @Verbose @Params
    }
    else
    {
        "Skipping deployment: To deploy, ensure that...`n" +
        "`t* You are in a known build system (Current: $env:BHBuildSystem)`n" +
        "`t* You are committing to the master branch (Current: $env:BHBranchName) `n" +
        "`t* Your commit message includes !deploy (Current: $env:BHCommitMessage)"
    }
}
