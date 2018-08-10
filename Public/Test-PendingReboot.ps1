<#
.SYNOPSIS
    Gets the pending reboot status on a local or remote computer.

.DESCRIPTION
    This function will query the registry on a local or remote computer and determine if the
    system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer
    Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the
    CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations"
    and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.

    CBServicing = Component Based Servicing (Windows 2008+)
    WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
    CCMClientSDK = SCCM 2012 Clients only (DetermineifRebootPending method) otherwise $null value
    PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
    PendFileRename = PendingFileRenameOperations (Windows 2003+)
    PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                     Virus leverage this key for def/dat removal, giving a false positive PendingReboot

.PARAMETER ComputerName
    A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER ErrorLog
    A single path to send error data to a log file.

.EXAMPLE
    PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize

    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
    -------- ----------- ------------- ------------ -------------- -------------- -------------
    DC01           False         False                       False                        False
    DC02           False         False                       False                        False
    FS01           False         False                       False                        False

    This example will capture the contents of C:\ServerList.txt and query the pending reboot
    information from the systems contained in the file and display the output in a table. The
    null values are by design, since these systems do not have the SCCM 2012 client installed,
    nor was the PendingFileRenameOperations value populated.

.EXAMPLE
    PS C:\> Get-PendingReboot

    Computer           : WKS01
    CBServicing        : False
    WindowsUpdate      : True
    CCMClient          : False
    PendComputerRename : False
    PendFileRename     : False
    PendFileRenVal     :
    RebootPending      : True

    This example will query the local machine for pending reboot information.

.EXAMPLE
    PS C:\> $Servers = Get-Content C:\Servers.txt
    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation

    This example will create a report that contains pending reboot information.

.LINK
    Component-Based Servicing:
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

    PendingFileRename/Auto Update:
    http://support.microsoft.com/kb/2723674
    http://technet.microsoft.com/en-us/library/cc960241.aspx
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

    SCCM 2012/CCM_ClientSDK:
    http://msdn.microsoft.com/en-us/library/jj902723.aspx

.NOTES
    Author:  Brian Wilhite
    Email:   bcwilhite (at) live.com
    Date:    29AUG2012
    PSVer:   2.0/3.0/4.0/5.0
    Updated: 27JUL2015
    UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
             Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
             Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
             Added CCMClient property - Used with SCCM 2012 Clients only
             Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
             Removed $Data variable from the PSObject - it is not needed
             Bug with the way CCMClientSDK returned null value if it was false
             Removed unneeded variables
             Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
             Removed .Net Registry connection, replaced with WMI StdRegProv
             Added ComputerPendingRename
#>

function Test-PendingReboot
{
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("CN", "Computer")]
        [String[]]
        $ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [Switch]
        $Detailed
    )

    process
    {
        foreach ($Computer in $ComputerName)
        {
            try
            {
                ## Setting pending values to false to cut down on the number of else statements
                $pendingComputerRenameOrDomainJoin = $false
                $pendingFileRenameOperation        = $false
                $systemCenterConfigManager         = $false

                ## Making registry connection to the local/remote computer
                $hklm = [UInt32] "0x80000002"
                $wmiStdRegProv = [WMIClass] "\\$Computer\root\default:StdRegProv"

                ## Query the Component Based Servicing Reg Key
                $registyComponentBasedServicing = $wmiStdRegProv.EnumKey($hklm, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")

                ## Query WUAU from the registry
                $registryWindowsUpdateAutoUpdate = $wmiStdRegProv.EnumKey($hklm, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")

                ## Query PendingFileRenameOperations from the registry
                $registryPendingFileRenameOperations = $wmiStdRegProv.GetMultiStringValue($hklm, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
                if ($registryPendingFileRenameOperations.sValue)
                {
                    $pendingFileRenameOperation = $true
                }

                ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
                $registryNetlogon  = $wmiStdRegProv.EnumKey($hklm, "SYSTEM\CurrentControlSet\Services\Netlogon").sNames
                $pendingDomainJoin = ($registryNetlogon -contains 'JoinDomain') -or ($registryNetlogon -contains 'AvoidSpnSet')

                ## Query ComputerName and ActiveComputerName from the registry
                $registryActiveComputerName = $wmiStdRegProv.GetStringValue($hklm, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")
                $registryComputerName       = $wmiStdRegProv.GetStringValue($hklm, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")

                if (($registryActiveComputerName -ne $registryComputerName) -or $pendingDomainJoin)
                {
                    $pendingComputerRenameOrDomainJoin = $true
                }

                $sccmClientSDK = $null
                $CCMSplat = @{
                    NameSpace    = 'ROOT\ccm\ClientSDK'
                    Class        = 'CCM_ClientUtilities'
                    Name         = 'DetermineifRebootPending'
                    ComputerName = $Computer
                    ErrorAction  = 'Stop'
                }
                ## try CCMClientSDK
                try
                {
                    $sccmClientSDK = Invoke-WmiMethod @CCMSplat
                }
                catch [System.UnauthorizedAccessException]
                {
                    $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
                    if ($CcmStatus.Status -ne 'Running')
                    {
                        Write-Warning "$Computer`: Error - CcmExec service is not running."
                        $sccmClientSDK = $null
                    }
                }
                catch
                {
                    $sccmClientSDK = $null
                }

                if ($sccmClientSDK)
                {
                    if ($sccmClientSDK.ReturnValue -ne 0)
                    {
                        Write-Warning "Error: DetermineifRebootPending returned error code $($sccmClientSDK.ReturnValue)"
                    }
                    if ($sccmClientSDK.IsHardRebootPending -or $sccmClientSDK.RebootPending)
                    {
                        $systemCenterConfigManager = $true
                    }
                }
                else
                {
                    $systemCenterConfigManager = $null
                }

                if ($PSBoundParameters.ContainsKey('Detailed'))
                {
                    [PSCustomObject]@{
                        ComputerName                      = $Computer
                        ComponentBasedServicing           = $registyComponentBasedServicing.sNames -contains "RebootPending"
                        WindowsUpdateAutoUpdate           = $registryWindowsUpdateAutoUpdate.sNames -contains "RebootRequired"
                        SystemCenterConfigManager         = $systemCenterConfigManager
                        PendingComputerRenameOrDomainJoin = $pendingComputerRenameOrDomainJoin
                        PendingFileRenameOperations       = $pendingFileRenameOperation
                        PendingFileRenameOperationsValue  = $registryPendingFileRenameOperations.sValue
                        IsRebootPending                   = ($pendingComputerRenameOrDomainJoin -or $componentBasedServicing -or $WUAURebootReq -or $systemCenterConfigManager -or $pendingFileRenameOperation)
                    }
                }
                else
                {
                    [bool]($pendingComputerRenameOrDomainJoin -or $componentBasedServicing -or $WUAURebootReq -or $systemCenterConfigManager -or $pendingFileRenameOperation)
                }
            }

            catch
            {
                Write-Warning "$Computer`: $_"
            }
        }
    }
}
