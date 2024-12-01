function Get-TargetResource {
    param(
        [Parameter(Mandatory)]
        [string]
        $NetNatName,

        [Parameter(Mandatory)]
        [string]
        $ExternalIPAddress,

        [Parameter(Mandatory)]
        [int]
        $ExternalPort,

        [Parameter(Mandatory)]
        [ValidateSet('TCP', 'UDP')]
        [string]
        $Protocol,

        [Parameter(Mandatory)]
        [string]
        $InternalIPAddress,

        [Parameter(Mandatory)]
        [int]
        $InternalPort
    )

    @{
        NetNatName          = $NetNatName
        ExternalIPAddress   = $ExternalIPAddress
        ExternalPort        = $ExternalPort
        Protocol            = $Protocol
        InternalIPAddress   = $InternalIPAddress
        InternalPort        = $InternalPort
    }
}

function Test-TargetResource {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'NetNatName', Justification = 'False positive.')
    ]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'Protocol', Justification = 'False positive.')
    ]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'InternalIPAddress', Justification = 'False positive.')
    ]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'InternalPort', Justification = 'False positive.')
    ]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory)]
        [string]
        $NetNatName,

        [Parameter(Mandatory)]
        [string]
        $ExternalIPAddress,

        [Parameter(Mandatory)]
        [int]
        $ExternalPort,

        [Parameter(Mandatory)]
        [ValidateSet('TCP', 'UDP')]
        [string]
        $Protocol,

        [Parameter(Mandatory)]
        [string]
        $InternalIPAddress,

        [Parameter(Mandatory)]
        [int]
        $InternalPort
    )

    $ipAddress = $ExternalIPAddress -split '/' | Select-Object -First 1

    $result = Get-NetNatStaticMapping | Where-Object {
        $_.NatName -eq $NetNatName -and
        $_.ExternalIPAddress -eq $ipAddress -and
        $_.ExternalPort -eq $ExternalPort -and
        $_.Protocol -eq $Protocol -and
        $_.InternalIPAddress -eq $InternalIPAddress -and
        $_.InternalPort -eq $InternalPort
    }

    if (!$result) {
        $message = ("NetNatStaticMapping for external IP '{0}' and port '{1}' is not set." -f
            $ExternalIPAddress, $ExternalPort)

        Write-Verbose -Message $message

        return $false
    }

    $message = ("NetNatStaticMapping for external IP '{0}' and port '{1}' is set." -f
        $ExternalIPAddress, $ExternalPort)

    Write-Verbose -Message $message

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
        $ExternalIPAddress,

        [Parameter(Mandatory)]
        [int]
        $ExternalPort,

        [Parameter(Mandatory)]
        [ValidateSet('TCP', 'UDP')]
        [string]
        $Protocol,

        [Parameter(Mandatory)]
        [string]
        $InternalIPAddress,

        [Parameter(Mandatory)]
        [int]
        $InternalPort
    )

    if ($PSCmdlet.ShouldProcess($NetNatName)) {
        $message = ("Setting NetNatStaticMapping for external IP '{0}' and port '{1}'." -f
            $ExternalIPAddress, $ExternalPort)

        Write-Verbose -Message $message

        $addNetNatStaticMappingParams = @{
            ExternalIPAddress   = $ExternalIPAddress
            ExternalPort        = $ExternalPort
            Protocol            = $Protocol
            InternalIPAddress   = $InternalIPAddress
            InternalPort        = $InternalPort
            NatName             = $NetNatName
        }

        Add-NetNatStaticMapping @addNetNatStaticMappingParams
    }
}