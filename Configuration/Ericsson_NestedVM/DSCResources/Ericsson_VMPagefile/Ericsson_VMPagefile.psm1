function Get-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Mandatory parameter must be declared.'
    )]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    @{
        VMName = $VMName
    }
}

function Test-TargetResource {
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName      = $VMName
        Credential  = $LocalAdminCredential
    }

    $result = Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        Get-CimInstance -ClassName Win32_ComputerSystem |
        Select-Object -ExpandProperty AutomaticManagedPagefile
    }

    if ($result) {
        Write-Verbose -Message 'AutomaticManagedPagefile file is set.'
        return $true
    }

    Write-Verbose -Message 'AutomaticManagedPagefile file is not set.'
    return $false
}

function Set-TargetResource {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName      = $VMName
            Credential  = $LocalAdminCredential
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            Get-CimInstance -ClassName Win32_ComputerSystem |
            Set-CimInstance -Property @{ 'AutomaticManagedPagefile' = $true }
        }

        Write-Verbose -Message 'AutomaticManagedPagefile file is set.'
    }
}