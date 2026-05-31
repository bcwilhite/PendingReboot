function Invoke-CimWmiMethod {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [Hashtable]
        $invokeWmiMethodParameters,

        [Parameter()]
        [Switch]
        $Wmi
    )

    if ($Wmi)
    {
        Invoke-WmiMethod @invokeWmiMethodParameters
    }
    else {
        if ($invokeWmiMethodParameters.ArgumentList)
        {
            $invokeWmiMethodParameters.Arguments = @{
                hDefKey     = $invokeWmiMethodParameters.ArgumentList[0]
                sSubKeyName = $invokeWmiMethodParameters.ArgumentList[1]
            }
            if ($invokeWmiMethodParameters.Name -in ('GetStringValue', 'GetMultiStringValue'))
            {
                $invokeWmiMethodParameters.Arguments.sValueName = $invokeWmiMethodParameters.ArgumentList[2]
            }
            $invokeWmiMethodParameters.Remove('ArgumentList')
        }

        Invoke-CimMethod @invokeWmiMethodParameters
    }
}