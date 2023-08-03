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
    param
    (
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
        foreach ($ComputerNameItem in $ComputerName)
        {
            try
            {
                ## Establish a CimSession
                $CredentialSplat = @{}
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $CredentialSplat.Credential = $Credential
                }
                $CimSession = New-CimSession -ComputerName $ComputerNameItem @CredentialSplat -ErrorAction Stop

                $InvokeCimMethodSplat = @{
                    CimSession = $CimSession
                    Namespace  = 'root\CIMv2'
                    ClassName  = 'StdRegProv'
                    Name       = 'EnumKey'
                    Arguments  = @{
                        hDefKey     = [UInt32] "0x80000002" # HKLM
                        sSubKeyName = $null
                    }
                }

                ## Query the Component Based Servicing Reg Key
                $InvokeCimMethodSplat.Arguments.sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
                $RegistryComponentBasedServicing = (Invoke-CimMethod @InvokeCimMethodSplat).sNames -contains 'RebootPending'

                ## Query WUAU from the registry
                $InvokeCimMethodSplat.Arguments.sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
                $RegistryWindowsUpdateAutoUpdate = (Invoke-CimMethod @InvokeCimMethodSplat).sNames -contains 'RebootRequired'

                ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
                $InvokeCimMethodSplat.Arguments.sSubKeyName = 'SYSTEM\CurrentControlSet\Services\Netlogon'
                $RegistryNetlogon = (Invoke-CimMethod @InvokeCimMethodSplat).sNames
                $PendingDomainJoin = ($RegistryNetlogon -contains 'JoinDomain') -or ($RegistryNetlogon -contains 'AvoidSpnSet')

                ## Query ComputerName and ActiveComputerName from the registry and setting the MethodName to GetMultiStringValue
                $InvokeCimMethodSplat.Name = 'GetStringValue'

                $InvokeCimMethodSplat.Arguments.sSubKeyName = 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
                $InvokeCimMethodSplat.Arguments.sValueName = 'ComputerName'
                $RegistryActiveComputerName = (Invoke-CimMethod @InvokeCimMethodSplat).sValue

                $InvokeCimMethodSplat.Arguments.sSubKeyName = 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
                $InvokeCimMethodSplat.Arguments.sValueName = 'ComputerName'
                $RegistryComputerName = (Invoke-CimMethod @InvokeCimMethodSplat).sValue

                $PendingComputerRename = $RegistryActiveComputerName -ne $RegistryComputerName -or $PendingDomainJoin

                ## Query PendingFileRenameOperations from the registry
                if (-not $PSBoundParameters.ContainsKey('SkipPendingFileRenameOperationsCheck'))
                {
                    $InvokeCimMethodSplat.Arguments.sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager'
                    $InvokeCimMethodSplat.Arguments.sValueName = 'PendingFileRenameOperations'
                    $RegistryPendingFileRenameOperations = (Invoke-CimMethod @InvokeCimMethodSplat).sValue
                    $RegistryPendingFileRenameOperationsBool = [bool]$RegistryPendingFileRenameOperations

                }

                ## Query ClientSDK for pending reboot status, unless SkipConfigurationManagerClientCheck is present
                if (-not $PSBoundParameters.ContainsKey('SkipConfigurationManagerClientCheck'))
                {
                    $InvokeCimMethodSplat = @{
                        CimSession  = $CimSession
                        Namespace   = 'root\ccm\ClientSDK'
                        ClassName   = 'CCM_ClientUtilities'
                        Name        = 'DetermineifRebootPending'
                    }

                    $SCCMClientSDKError = $null
                    $SCCMClientSDK = Invoke-CimMethod @InvokeCimMethodSplat -ErrorAction SilentlyContinue -ErrorVariable SCCMClientSDKError

                    if ($SCCMClientSDKError)
                    {
                        $SystemCenterConfigManager = $null
                        Write-Verbose $SCCMClientSDKError.Exception.Message
                        Write-Verbose ($script:localizedData.invokeWmiClientSDKError -f $ComputerNameItem)
                    }
                    else
                    {
                        $SystemCenterConfigManager = $SCCMClientSDK.ReturnValue -eq 0 -and ($SCCMClientSDK.IsHardRebootPending -or $SCCMClientSDK.RebootPending)
                    }

                }

                $IsRebootPending = $RegistryComponentBasedServicing -or `
                    $PendingComputerRename -or `
                    $PendingDomainJoin -or `
                    $RegistryPendingFileRenameOperations -or `
                    $SystemCenterConfigManager -or `
                    $RegistryWindowsUpdateAutoUpdate

                if ($PSBoundParameters.ContainsKey('Detailed'))
                {
                    [PSCustomObject]@{
                        ComputerName                     = $ComputerNameItem
                        ComponentBasedServicing          = $RegistryComponentBasedServicing
                        PendingComputerRenameDomainJoin  = $PendingComputerRename
                        PendingFileRenameOperations      = $registryPendingFileRenameOperationsBool
                        PendingFileRenameOperationsValue = $registryPendingFileRenameOperations
                        SystemCenterConfigManager        = $SystemCenterConfigManager
                        WindowsUpdateAutoUpdate          = $RegistryWindowsUpdateAutoUpdate
                        IsRebootPending                  = $IsRebootPending
                    }
                }
                else
                {
                    [PSCustomObject]@{
                        ComputerName    = $ComputerNameItem
                        IsRebootPending = $IsRebootPending
                    }
                }
            }
            finally
            {
                if ( $null -ne $CimSession ) {
                    Remove-CimSession -CimSession $CimSession
                }
            }
        }
    }
}
