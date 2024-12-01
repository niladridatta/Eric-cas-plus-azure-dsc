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

        [AllowEmptyString()]
        [Parameter()]
        [string]
        $FileShareUNCPath
    )

    @{
        VMName              = $VMName
        FileShareUNCPath    = $FileShareUNCPath
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
        $LocalAdminCredential,

        [AllowEmptyString()]
        [Parameter()]
        [string]
        $FileShareUNCPath
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($FileShareUNCPath)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [AllowEmptyString()]
            [Parameter()]
            [string]
            $FileShareUNCPath
        )

        $execute = Get-Command powershell.exe | Select-Object -First 1 -ExpandProperty Definition

        $argument = ('-NoLogo -NonInteractive -ExecutionPolicy Bypass -File ' +
                        '"C:\CASPlus\Scripts\Mount-FileShareAsDrive.ps1" -FileShareUNCPath "{0}"' -f
                        $FileShareUNCPath)

        $action = Get-ScheduledTask -TaskName "Mount-FileShareAsDrive" -TaskPath "\CASPlus\" |
                    Select-Object -ExpandProperty Actions | Select-Object -First 1

        if ($action.Execute -ne $execute -or $action.Arguments -ne $argument) {
            Write-Verbose -Message "Scheduled task 'Mount-FileShareAsDrive' is not set." -Verbose
            return $false
        }

        Write-Verbose -Message "Scheduled task 'Mount-FileShareAsDrive' is set." -Verbose
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

        [AllowEmptyString()]
        [Parameter()]
        [string]
        $FileShareUNCPath
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($FileShareUNCPath)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [AllowEmptyString()]
                [Parameter()]
                [string]
                $FileShareUNCPath
            )

            $execute = Get-Command powershell.exe | Select-Object -First 1 -ExpandProperty Definition

            $argument = ('-NoLogo -NonInteractive -ExecutionPolicy Bypass -File ' +
                            '"C:\CASPlus\Scripts\Mount-FileShareAsDrive.ps1" -FileShareUNCPath "{0}"' -f
                            $FileShareUNCPath)

            $action = New-ScheduledTaskAction -Execute $execute -Argument $argument

            Write-Verbose -Message "Setting Scheduled task 'Mount-FileShareAsDrive'." -Verbose
            Set-ScheduledTask -TaskName "Mount-FileShareAsDrive" -TaskPath "\CASPlus\" -Action $action
        }
    }
}