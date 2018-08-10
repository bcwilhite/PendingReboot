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
        $Detailed,

        [Parameter()]
        [Switch]
        $SkipConfigurationManagerClientCheck,

        [Parameter()]
        [Switch]
        $IgnorePendingFileRenameOperations
    )

    process
    {
        foreach ($Computer in $ComputerName)
        {
            try
            {
                ## Making registry connection to the local/remote computer
                $hklm = [UInt32] "0x80000002"
                $wmiStdRegProv = [WMIClass] "\\$Computer\root\default:StdRegProv"

                ## Query the Component Based Servicing Reg Key
                $registryCBSKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\'
                $registryComponentBasedServicing = $wmiStdRegProv.EnumKey($hklm, $registryCBSKeyPath).sNames -contains "RebootPending"

                ## Query WUAU from the registry
                $registryAutoUpdateKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\'
                $registryWindowsUpdateAutoUpdate = $wmiStdRegProv.EnumKey($hklm, $registryAutoUpdateKeyPath).sNames -contains "RebootRequired"

                ## Query PendingFileRenameOperations from the registry
                $registrySessionManagerKeyPath = 'SYSTEM\CurrentControlSet\Control\Session Manager\'
                $registryPendingFileRenameOperations = $wmiStdRegProv.GetMultiStringValue($hklm, $registrySessionManagerKeyPath, "PendingFileRenameOperations").sValue

                ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
                $registryNetlogonKeyPath = 'SYSTEM\CurrentControlSet\Services\Netlogon'
                $registryNetlogon = $wmiStdRegProv.EnumKey($hklm, $registryNetlogonKeyPath).sNames
                $pendingDomainJoin = ($registryNetlogon -contains 'JoinDomain') -or ($registryNetlogon -contains 'AvoidSpnSet')

                ## Query ComputerName and ActiveComputerName from the registry
                $registryActiveComputerNameKeyPath = 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\'
                $registryComputerNameKeyPath = 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\'
                $registryActiveComputerName = $wmiStdRegProv.GetStringValue($hklm, $registryActiveComputerNameKeyPath, 'ComputerName')
                $registryComputerName = $wmiStdRegProv.GetStringValue($hklm, $registryComputerNameKeyPath, 'ComputerName')
                $pendingComputerRename = $registryActiveComputerName -ne $registryComputerName

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

                $isRebootPending = $registryComponentBasedServicing -or `
                    $pendingComputerRename -or `
                    $pendingDomainJoin -or `
                    [bool]$registryPendingFileRenameOperations -or `
                    $systemCenterConfigManager -or `
                    $registryWindowsUpdateAutoUpdate

                if ($PSBoundParameters.ContainsKey('Detailed'))
                {
                    [PSCustomObject]@{
                        ComputerName                     = $Computer
                        ComponentBasedServicing          = $registryComponentBasedServicing
                        PendingComputerRename            = $pendingComputerRename
                        PendingDomainJoin                = $pendingDomainJoin
                        PendingFileRenameOperations      = [bool]$registryPendingFileRenameOperations
                        PendingFileRenameOperationsValue = $registryPendingFileRenameOperations
                        SystemCenterConfigManager        = $systemCenterConfigManager
                        WindowsUpdateAutoUpdate          = $registryWindowsUpdateAutoUpdate
                        IsRebootPending                  = $isRebootPending
                    }
                }
                else
                {
                    return $isRebootPending
                }
            }

            catch
            {
                Write-Warning "$Computer`: $_"
            }
        }
    }
}
