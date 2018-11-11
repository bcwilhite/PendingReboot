<#
.SYNOPSIS
    Test the pending reboot status on a local and/or remote computer.

.DESCRIPTION
    This function will query the registry on a local and/or remote computer and determine if the
    system is pending a reboot, from Microsoft/Windows updates, Configuration Manager Client SDK, Pending
    Computer Rename, Domain Join, Pending File Rename Operations and Component Based Servicing.

    ComponentBasedServicing = Component Based Servicing
    WindowsUpdate = Windows Update / Auto Update
    CCMClientSDK = SCCM 2012 Clients only (DetermineifRebootPending method) otherwise $null value
    PendingComputerRenameDomainJoin = Detects a pending computer rename and/or pending domain join
    PendingFileRenameOperations = PendingFileRenameOperations, when this property returns true,
                                  it can be a false positive
    PendingFileRenameOperationsValue = PendingFilerenameOperations registry value; used to filter if need be,
                                       Anti-Virus will leverage this key property for def/dat removal,
                                       giving a false positive

.PARAMETER ComputerName
    A single computer name or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER Credential
    Specifies a user account that has permission to perform this action. The default is the current user.
    Type a username, such as User01, Domain01\User01, or User@Contoso.com. Or, enter a PSCredential object,
    such as an object that is returned by the Get-Credential cmdlet. When you type a user name, you are
    prompted for a password.

.PARAMETER Detailed
    Indicates that this function returns a detailed result of pending reboot information, why the system is
    pending a reboot, not just a true/false response.

.PARAMETER SkipConfigurationManagerClientCheck
    Indicates that this function will not test the Client SDK WMI class that is provided by the System
    Center Configuration Manager Client.  This parameter is useful when SCCM is not used/installed on
    the targeted systems.

.PARAMETER SkipPendingFileRenameOperationsCheck
    Indicates that this function will not test the PendingFileRenameOperations MultiValue String property
    of the Session Manager registry key.  This parameter is useful for eliminating possible false positives.
    Many Anti-Virus packages will use the PendingFileRenameOperations MultiString Value in order to remove
    stale definitions and/or .dat files.

.EXAMPLE
    PS C:\> Test-PendingReboot

    ComputerName IsRebootPending
    ------------ ---------------
    WKS01                   True

    This example returns the ComputerName and IsRebootPending properties.

.EXAMPLE
    PS C:\> (Test-PendingReboot).IsRebootPending
    True

    This example will return a bool value based on the pending reboot test for the local computer.

.EXAMPLE
    PS C:\> Test-PendingReboot -ComputerName DC01 -Detailed

    ComputerName                     : dc01
    ComponentBasedServicing          : True
    PendingComputerRenameDomainJoin  : False
    PendingFileRenameOperations      : False
    PendingFileRenameOperationsValue :
    SystemCenterConfigManager        : False
    WindowsUpdateAutoUpdate          : True
    IsRebootPending                  : True

    This example will test the pending reboot status for dc01, providing detailed information

.EXAMPLE
    PS C:\> Test-PendingReboot -ComputerName DC01 -SkipConfigurationManagerClientCheck -SkipPendingFileRenameOperationsCheck -Detailed

    CommputerName                    : dc01
    ComponentBasedServicing          : True
    PendingComputerRenameDomainJoin  : False
    PendingFileRenameOperations      : False
    PendingFileRenameOperationsValue :
    SystemCenterConfigManager        :
    WindowsUpdateAutoUpdate          : True
    IsRebootPending                  : True

.LINK
    Background:
    https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/10/determine-pending-reboot-statuspowershell-style-part-1/
    https://blogs.technet.microsoft.com/heyscriptingguy/2013/06/11/determine-pending-reboot-statuspowershell-style-part-2/

    Component-Based Servicing:
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

    PendingFileRename/Auto Update:
    http://support.microsoft.com/kb/2723674
    http://technet.microsoft.com/en-us/library/cc960241.aspx
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

    CCM_ClientSDK:
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
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter()]
        [Switch]
        $Detailed,

        [Parameter()]
        [Switch]
        $SkipConfigurationManagerClientCheck,

        [Parameter()]
        [Switch]
        $SkipPendingFileRenameOperationsCheck
    )

    process
    {
        foreach ($computer in $ComputerName)
        {
            try
            {
                $invokeCimMethodParameters = @{
                    Namespace    = 'root/default'
                    Class        = 'StdRegProv'
                    Name         = 'EnumKey'
                    ErrorAction  = 'Stop'
                    Verbose      = $false
                }

                if ($PSBoundParameters.ContainsKey('ComputerName'))
                {
                    $invokeCimMethodParameters.ComputerName = $computer
                }

                $hklm = [UInt32] "0x80000002"

                if ($PSBoundParameters.ContainsKey('Credential'))
                {
                    $invokeCimMethodParameters.Credential = $Credential
                }

                ## Query the Component Based Servicing Reg Key
                $argumentsEnumKey = @{
                    hDefKey     = $hklm
                    sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\'
                }
                $invokeCimMethodParameters.Arguments = $argumentsEnumKey
                $registryComponentBasedServicing = (Invoke-CimMethod @invokeCimMethodParameters).sNames -contains 'RebootPending'

                ## Query WUAU from the registry
                $argumentsEnumKey.sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\'
                $invokeCimMethodParameters.Arguments = $argumentsEnumKey
                $registryWindowsUpdateAutoUpdate = (Invoke-CimMethod @invokeCimMethodParameters).sNames -contains 'RebootRequired'

                ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
                $argumentsEnumKey.sSubKeyName = 'SYSTEM\CurrentControlSet\Services\Netlogon'
                $invokeCimMethodParameters.Arguments = $argumentsEnumKey
                $registryNetlogon = (Invoke-CimMethod @invokeCimMethodParameters).sNames
                $pendingDomainJoin = ($registryNetlogon -contains 'JoinDomain') -or ($registryNetlogon -contains 'AvoidSpnSet')

                ## Query ComputerName and ActiveComputerName from the registry and setting the MethodName to GetMultiStringValue
                $argumentsGetMultiStringValue = @{
                    hDefKey     = $hklm
                    sSubKeyName = 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\'
                    sValueName  = 'ComputerName'
                }
                $invokeCimMethodParameters.Name = 'GetMultiStringValue'
                $invokeCimMethodParameters.Arguments = $argumentsGetMultiStringValue
                $registryActiveComputerName = Invoke-CimMethod @invokeCimMethodParameters

                $argumentsGetMultiStringValue.sSubKeyName = 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\'
                $invokeCimMethodParameters.Arguments = $argumentsGetMultiStringValue
                $registryComputerName = Invoke-CimMethod @invokeCimMethodParameters

                $pendingComputerRename = $registryActiveComputerName -ne $registryComputerName -or $pendingDomainJoin

                ## Query PendingFileRenameOperations from the registry
                if (-not $PSBoundParameters.ContainsKey('SkipPendingFileRenameOperationsCheck'))
                {
                    $argumentsGetMultiStringValue.sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager\'
                    $argumentsGetMultiStringValue.sValueName  = 'PendingFileRenameOperations'
                    $invokeCimMethodParameters.Arguments = $argumentsGetMultiStringValue
                    $registryPendingFileRenameOperations = (Invoke-CimMethod @invokeCimMethodParameters).sValue
                    $registryPendingFileRenameOperationsBool = [bool]$registryPendingFileRenameOperations
                }

                ## Query ClientSDK for pending reboot status, unless SkipConfigurationManagerClientCheck is present
                if (-not $PSBoundParameters.ContainsKey('SkipConfigurationManagerClientCheck'))
                {
                    $invokeCimMethodParameters.NameSpace = 'ROOT\ccm\ClientSDK'
                    $invokeCimMethodParameters.Class = 'CCM_ClientUtilities'
                    $invokeCimMethodParameters.Name = 'DetermineifRebootPending'
                    $invokeCimMethodParameters.Remove('Arguments')

                    try
                    {
                        $sccmClientSDK = Invoke-CimMethod @invokeCimMethodParameters
                        $sccmRebootPending = $sccmClientSDK.IsHardRebootPending -or $sccmClientSDK.RebootPending
                        $systemCenterConfigManager = $sccmClientSDK.ReturnValue -eq 0 -and $sccmRebootPending
                    }
                    catch
                    {
                        $systemCenterConfigManager = $null
                        Write-Verbose -Message ($script:localizedData.invokeWmiClientSDKError -f $computer)
                    }
                }

                $isRebootPending = $registryComponentBasedServicing -or `
                    $pendingComputerRename -or `
                    $pendingDomainJoin -or `
                    $registryPendingFileRenameOperationsBool -or `
                    $systemCenterConfigManager -or `
                    $registryWindowsUpdateAutoUpdate

                if ($PSBoundParameters.ContainsKey('Detailed'))
                {
                    [PSCustomObject]@{
                        ComputerName                     = $computer
                        ComponentBasedServicing          = $registryComponentBasedServicing
                        PendingComputerRenameDomainJoin  = $pendingComputerRename
                        PendingFileRenameOperations      = $registryPendingFileRenameOperationsBool
                        PendingFileRenameOperationsValue = $registryPendingFileRenameOperations
                        SystemCenterConfigManager        = $systemCenterConfigManager
                        WindowsUpdateAutoUpdate          = $registryWindowsUpdateAutoUpdate
                        IsRebootPending                  = $isRebootPending
                    }
                }
                else
                {
                    [PSCustomObject]@{
                        ComputerName    = $computer
                        IsRebootPending = $isRebootPending
                    }
                }
            }

            catch
            {
                Write-Verbose "$Computer`: $_"
            }
        }
    }
}
