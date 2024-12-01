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
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [bool]
        $Enabled,

        [Parameter()]
        [bool]
        $PasswordNeverExpires = $false
    )

    @{
        VMName                  = $VMName
        Name                    = $Name
        Enabled                 = $Enabled
        PasswordNeverExpires    = $PasswordNeverExpires    }
}

function Test-TargetResource {
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
        $Name,

        [Parameter(Mandatory)]
        [bool]
        $Enabled,

        [Parameter()]
        [bool]
        $PasswordNeverExpires = $false
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($Name
                            $Enabled
                            $PasswordNeverExpires)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $Name,

            [Parameter(Mandatory)]
            [bool]
            $Enabled,

            [Parameter()]
            [bool]
            $PasswordNeverExpires = $false
        )

        $user = Get-LocalUser | Where-Object Name -EQ $Name

        if ($null -eq $user) {
            Write-Verbose -Message ("User '{0}' not found." -f $Name) -Verbose
            return $true
        }

        if ($user.Enabled -ne $Enabled) {
            Write-Verbose -Message ("User '{0}' is not set." -f $Name) -Verbose
            return $false
        }

        if ($PasswordNeverExpires -and $user.PasswordExpires -ne $PasswordExpires) {
            Write-Verbose -Message ("User '{0}' is not set." -f $Name) -Verbose
            return $false
        }

        Write-Verbose -Message ("User '{0}' is set." -f $Name) -Verbose
        return $true
    }
}

function Set-TargetResource {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [bool]
        $Enabled,

        [Parameter()]
        [bool]
        $PasswordNeverExpires = $false
    )

    if ($PSCmdlet.ShouldProcess($Name)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($Name
                                $Enabled
                                $PasswordNeverExpires)
        }

        Invoke-Command @$invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [string]
                $Name,

                [Parameter(Mandatory)]
                [bool]
                $Enabled,

                [Parameter()]
                [bool]
                $PasswordNeverExpires = $false
            )

            if (-not $Enabled) {
                Write-Verbose -Message ("Disabling user '{0}'." -f $Name) -Verbose
                Disable-LocalUser -Name $Name
                return
            }

            Write-Verbose -Message ("Enabling user '{0}'." -f $Name) -Verbose
            Enable-LocalUser -Name $Name

            Write-Verbose -Message ("Setting user '{0}'." -f $Name) -Verbose
            Set-LocalUser -Name $Name -PasswordNeverExpires $PasswordNeverExpires
        }
    }
}