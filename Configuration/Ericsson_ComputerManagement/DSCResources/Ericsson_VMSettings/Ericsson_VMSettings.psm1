function Get-TargetResource{
    param(
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $AutomaticStartAction,

        [Parameter(Mandatory)]
        [string]
        $AutomaticStopAction
    )

    @{
        VMName                  = $VMName
        AutomaticStartAction    = $AutomaticStartAction
        AutomaticStopAction     = $AutomaticStopAction
    }
}
function Test-TargetResource {
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $AutomaticStartAction,

        [Parameter(Mandatory)]
        [string]
        $AutomaticStopAction
    )

    $vm = Get-VM -Name $VMName

    if ($vm.AutomaticStartAction -ne $AutomaticStartAction -or
        $vm.AutomaticStopAction -ne $AutomaticStopAction
    ){
        Write-Verbose -Message ("The VM '{0}' configuration is not set." -f $VMName)
        return $false
    }

    Write-Verbose -Message ("The VM '{0}' configuration is set." -f $VMName)
    return $true
}

function Set-TargetResource {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $AutomaticStartAction,

        [Parameter(Mandatory)]
        [string]
        $AutomaticStopAction
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Setting configuration on VM '{0}'." -f $VMName)

        $setVMParams = @{
            Name                    = $VMName
            AutomaticStartAction    = $AutomaticStartAction
            AutomaticStopAction     = $AutomaticStopAction
        }

        Set-VM @setVMParams
    }
}