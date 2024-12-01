function Get-TargetResource{
    param(
        [Parameter(Mandatory)]
        [string]
        $NetNatName,

        [Parameter(Mandatory)]
        [string]
        $InternalIPInterfaceAddressPrefix
    )

    @{
        NetNatName                          = $NetNatName
        InternalIPInterfaceAddressPrefix    = $InternalIPInterfaceAddressPrefix
    }
}

function Test-TargetResource {
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory)]
        [string]
        $NetNatName,

        [Parameter(Mandatory)]
        [string]
        $InternalIPInterfaceAddressPrefix
    )

    $result = Get-NetNat | Where-Object Name -EQ $NetNatName |
        Select-Object -ExpandProperty InternalIPInterfaceAddressPrefix

    if ($result -ne $InternalIPInterfaceAddressPrefix) {
        Write-Verbose -Message ("NetNat '{0}' is not set." -f $NetNatName)
        return $false
    }

    Write-Verbose -Message ("NetNat '{0}' is set." -f $NetNatName)
    return $true
}

function Set-TargetResource {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $NetNatName,

        [Parameter(Mandatory)]
        [string]
        $InternalIPInterfaceAddressPrefix
    )

    if ($PSCmdlet.ShouldProcess($NetNatName)) {
        $existingNetNat = Get-NetNat | Where-Object Name -EQ $NetNatName

        if (
            $null -ne $existingNetNat -and
            $existingNetNat.InternalIPInterfaceAddressPrefix -ne $InternalIPInterfaceAddressPrefix
        ){
            $message = ("Existing NetNat '{0}' found with IP prefix '{1}'. Removing." -f
                        $existingNetNat.Name, $InternalIPInterfaceAddressPrefix)

            Write-Verbose -Message $message
            Remove-NetNat -Name $NetNatName -Confirm:$false
        }

        $message = ("Setting NetNat '{0}' with IP prefix '{1}'." -f
            $NetNatName, $InternalIPInterfaceAddressPrefix)

        Write-Verbose -Message $message

        $newNetNatParams = @{
            Name                                = $NetNatName
            InternalIPInterfaceAddressPrefix    = $InternalIPInterfaceAddressPrefix
        }

        New-NetNat @newNetNatParams
    }
}