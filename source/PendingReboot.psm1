$script:localizedData = Import-LocalizedData -BaseDirectory "$PSScriptRoot\Docs\en-US" -FileName 'PendingReboot.strings.psd1'

# Import everything in these folders
foreach ($folder in @('Private', 'Public', 'Classes'))
{
    $root = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if(Test-Path -Path $root)
    {
        Write-Verbose "processing folder $root"
        $files = Get-ChildItem -Path $root -Filter *.ps1

        # Dot source each file
        $nonTestps1Files = $files | Where-Object -FilterScript {$_.name -NotLike '*.Tests.ps1'}
        foreach ($ps1 in $nonTestps1Files)
        {
            Write-Verbose -Message $ps1.Name
            . $ps1.FullName
        }
    }
}

Export-ModuleMember -Function (Get-ChildItem -Path "$PSScriptRoot\public\*.ps1").BaseName
