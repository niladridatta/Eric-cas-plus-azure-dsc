function Get-TargetResource{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Mandatory parameter must be declared.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'DomainJoinCredential', Justification = 'Mandatory parameter must be declared.'
    )]
    param(
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string]
        $DomainDNSName,

        [Parameter(Mandatory)]
        [String]
        $DomainOU,

        [Parameter(Mandatory)]
        [PSCredential]
        $DomainJoinCredential
    )

    @{
        VMName = $VMName
        DomainDNSName = $DomainDNSName
        DomainOU = $DomainOU
    }
}

function Test-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'DomainOU', Justification = 'Mandatory parameter must be declared.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'DomainJoinCredential', Justification = 'Mandatory parameter must be declared.'
    )]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string]
        $DomainDNSName,

        [Parameter(Mandatory)]
        [String]
        $DomainOU,

        [Parameter(Mandatory)]
        [PSCredential]
        $DomainJoinCredential
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = $DomainDNSName
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $DomainDNSName
        )

        $domainName = Get-CimInstance -Namespace "root\cimv2" -ClassName "Win32_ComputerSystem" |
                        Select-Object -ExpandProperty Domain

        if ($domainName -eq $DomainDNSName) {
            Write-Verbose -Message ("VM is joined to the domain '{0}'." -f $DomainDNSName) -Verbose
            return $true
        }

        Write-Verbose -Message ("VM is not joined to the domain '{0}'." -f $DomainDNSName) -Verbose
        return $false
    }
}

function Set-TargetResource{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string]
        $DomainDNSName,

        [Parameter(Mandatory)]
        [String]
        $DomainOU,

        [Parameter(Mandatory)]
        [PSCredential]
        $DomainJoinCredential
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($VMName
                                $DomainJoinCredential
                                $DomainOU
                                $DomainDNSName)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param (
                [Parameter(Mandatory)]
                [string]
                $VMName,

                [Parameter(Mandatory)]
                [pscredential]
                $DomainJoinCredential,

                [Parameter(Mandatory)]
                [String]
                $DomainOU,

                [Parameter(Mandatory)]
                [string]
                $DomainDNSName
            )

            $message = ("Joining '$VMName' to the '$DomainOU' organizational unit " +
                        "of domain '$DomainDNSName'.")

            Write-Verbose -Message $message -Verbose

            $addComputerParams = @{
                DomainName  = $DomainDNSName
                OUPath      = $DomainOU
                Credential  = $DomainJoinCredential
            }

            Add-Computer @addComputerParams -Force -Verbose
        }

        Write-Verbose -Message ("Stopping VM '{0}'." -f $VMName) -Verbose
        Stop-VM -Name $VMName

        Write-Verbose -Message ("Starting VM '{0}'." -f $VMName) -Verbose
        Start-VM -Name $VMName -ErrorAction Stop
    }
}