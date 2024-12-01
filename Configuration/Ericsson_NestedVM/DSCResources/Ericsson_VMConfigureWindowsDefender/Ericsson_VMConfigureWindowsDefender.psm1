function Get-TargetResource{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Mandatory parameter must be declared.'
    )]
    param(
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

function Test-TargetResource{
    [OutputType([System.Boolean])]
    param(
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

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        $defenderServiceStatus = Get-Service | Where-Object Name -EQ WinDefend |
                                    Select-Object -ExpandProperty Status

        if ($null -eq $defenderServiceStatus) {
            Write-Verbose -Message 'Windows Defender service not found.' -Verbose
            Write-Verbose -Message 'Windows Defender is set.' -Verbose
            return $true
        }

        if ($defenderServiceStatus -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Verbose -Message 'Windows Defender service not running.' -Verbose
            return $true
        }

        $mpPreferences = Get-MpPreference

        if ($mpPreferences.SignatureScheduleDay -ne 'Everyday' `
            -or $mpPreferences.ExclusionExtension -ne '.VHDX' `
            -or $mpPreferences.ExclusionPath -ne 'C:\ProgramData\FSLogix\Cache')
        {
            Write-Verbose -Message 'Windows Defender is not set.' -Verbose
            return $false
        }

        $scheduledTask = Get-ScheduledTask -TaskName 'Update-Defender' -TaskPath '\CASPlus\'

        if ($scheduledTask.Settings.Enabled -ne $true) {
            Write-Verbose -Message 'Windows Defender is not set.' -Verbose
            return $false
        }

        $scheduledTaskFullPath = Join-Path -Path '\CASPlus\' -ChildPath 'Update-Defender'

        $joinPathParams = @{
            Path        = $env:SystemDrive
            ChildPath   = 'CASPlus\DSCCache\TaskScheduler'
        }

        $scheduledTaskResultPath = Join-Path @joinPathParams |
                                    Join-Path -ChildPath $scheduledTaskFullPath

        if (-not (Test-Path -Path $scheduledTaskResultPath)) {
            Write-Verbose -Message 'Windows Defender is not set.' -Verbose
            return $false
        }

        Write-Verbose -Message 'Windows Defender is set.' -Verbose
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
        $LocalAdminCredential
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName      = $VMName
            Credential  = $LocalAdminCredential
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            Write-Verbose -Message 'Configuring Windows Defender.' -Verbose

            $setMpPreferenceParams = @{
                SignatureScheduleDay    = 'Everyday'
                ExclusionPath           = 'C:\ProgramData\FSLogix\Cache'
                ExclusionExtension      = '.VHDX'
            }

            Set-MpPreference @setMpPreferenceParams

            Write-Verbose -Message "Enabling '\CASPlus\Update-Defender' scheduled task." -Verbose

            Get-ScheduledTask -TaskName 'Update-Defender' -TaskPath '\CASPlus\' |
            Enable-Scheduledtask

            $joinPathParams = @{
                Path        = $env:SystemDrive
                ChildPath   = 'CASPlus\DSCCache\TaskScheduler'
            }

            $scheduledTaskResultPath = Join-Path @joinPathParams |
                                        Join-Path -ChildPath '\CASPlus\Update-Defender'

            $scheduledTaskResultPathParent = Split-Path -Path $scheduledTaskResultPath -Parent

            if (-not (Test-Path -Path $scheduledTaskResultPathParent)) {
                $message = ("Creating directory '{0}.'" -f $scheduledTaskResultPathParent)
                Write-Verbose -Message $message -Verbose
                New-Item -Path $scheduledTaskResultPathParent -ItemType Directory
            }

            Write-Verbose -Message ("Creating file '{0}'." -f $scheduledTaskResultPath)
            Get-Date | Out-File -FilePath $scheduledTaskResultPath -Force
        }
    }
}