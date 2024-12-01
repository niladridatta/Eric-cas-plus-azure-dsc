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
        $TaskName,

        [Parameter(Mandatory)]
        [string]
        $TaskPath,

        [Parameter(Mandatory)]
        [bool]
        $Enabled
    )

    @{
        VMName      = $VMName
        TaskName    = $TaskName
        TaskPath    = $TaskPath
        Enabled     = $Enabled
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

        [Parameter(Mandatory)]
        [string]
        $TaskName,

        [Parameter(Mandatory)]
        [string]
        $TaskPath,

        [Parameter(Mandatory)]
        [bool]
        $Enabled
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($TaskName
                            $TaskPath
                            $Enabled)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $TaskName,

            [Parameter(Mandatory)]
            [string]
            $TaskPath,

            [Parameter(Mandatory)]
            [bool]
            $Enabled
        )

        $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName
        $taskPathNormalized = '{0}\' -f (Split-Path -Path $taskFullPath -Parent).TrimEnd('\')
        $task = Get-ScheduledTask |
                Where-Object { $_.TaskName -eq $TaskName -and $_.TaskPath -eq $taskPathNormalized }

        if ($null -eq $task) {
            Write-Verbose -Message ("Scheduled task '{0}' does not exist." -f $taskFullPath) -Verbose
            return $true
        }

        if ($task.Settings.Enabled -ne $Enabled) {
            Write-Verbose -Message ("Scheduled task '{0}' is not set." -f $taskFullPath) -Verbose
            return $false
        }

        Write-Verbose -Message ("Scheduled task '{0}' is set." -f $taskFullPath) -Verbose
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
        $TaskName,

        [Parameter(Mandatory)]
        [string]
        $TaskPath,

        [Parameter(Mandatory)]
        [bool]
        $Enabled
    )

    $target = Join-Path -Path $TaskPath -ChildPath $TaskName

    if ($PSCmdlet.ShouldProcess($target)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($TaskName
                                $TaskPath
                                $Enabled)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [string]
                $TaskName,

                [Parameter(Mandatory)]
                [string]
                $TaskPath,

                [Parameter(Mandatory)]
                [bool]
                $Enabled
            )

            $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName
            $taskPathNormalized = '{0}\' -f (Split-Path -Path $taskFullPath -Parent).TrimEnd('\')
            $task = Get-ScheduledTask |
                    Where-Object { $_.TaskName -eq $TaskName -and $_.TaskPath -eq $taskPathNormalized }

            if ($null -eq $task) {
                Write-Verbose -Message ("Scheduled task '{0}' does not exist." -f $taskFullPath) -Verbose
                return
            }

            if ($Enabled) {
                Write-Verbose -Message ("Enabling scheduled task '{0}'." -f $taskFullPath) -Verbose
                $task | Enable-ScheduledTask
                return
            }

            Write-Verbose -Message ("Disabling scheduled task '{0}'." -f $taskFullPath) -Verbose
            $task | Disable-ScheduledTask
        }
    }
}