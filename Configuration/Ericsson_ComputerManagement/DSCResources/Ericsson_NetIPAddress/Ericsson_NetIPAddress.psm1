function Get-TargetResource{
    param(
        [Parameter(Mandatory)]
        [string]
        $IpAddress,

        [Parameter(Mandatory)]
        [int]
        $PrefixLength,

        [Parameter(Mandatory)]
        [string]
        $InterfaceAlias
    )

    @{
        IpAddress       = $IpAddress
        PrefixLength    = $PrefixLength
        InterfaceAlias  = $InterfaceAlias
    }
}

function Test-TargetResource{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'PrefixLength', Justification = 'False positive.')
    ]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'InterfaceAlias', Justification = 'False positive.')
    ]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory)]
        [string]
        $IpAddress,

        [Parameter(Mandatory)]
        [int]
        $PrefixLength,

        [Parameter(Mandatory)]
        [string]
        $InterfaceAlias
    )

    $result = Get-NetIPAddress | Where-Object {
        $_.IPAddress -eq $IpAddress -and
        $_.PrefixLength -eq $PrefixLength -and
        $_.InterfaceAlias -eq $InterfaceAlias
    }

    if ($null -eq $result) {
        Write-Verbose -Message ("IP address '{0}' is not set." -f $IpAddress)
        return $false
    }

    Write-Verbose -Message ("IP address '{0}' is set." -f $IpAddress)
    return $true
}

function Set-TargetResource{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]
        $IpAddress,

        [Parameter(Mandatory)]
        [int]
        $PrefixLength,

        [Parameter(Mandatory)]
        [string]
        $InterfaceAlias
    )

    if ($PSCmdlet.ShouldProcess($InterfaceAlias)) {
        Write-Verbose -Message ("Setting IP address '{0}'." -f $IpAddress)

        $newNetIPAddressParams = @{
            IPAddress       = $IpAddress
            PrefixLength    = $PrefixLength
            InterfaceAlias  = $InterfaceAlias
        }

        New-NetIPAddress @newNetIPAddressParams
    }
}