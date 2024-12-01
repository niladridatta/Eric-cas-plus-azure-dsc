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

        [Parameter()]
        [bool]
        $Wait,

        [Parameter()]
        [int]
        $TimeoutSeconds = 600,

        [Parameter()]
        [bool]
        $SkipIfDisabled
    )

    @{
        VMName          = $VMName
        TaskName        = $TaskName
        TaskPath        = $TaskPath
        Wait            = $Wait
        TimeoutSeconds  = $TimeoutSeconds
        SkipIfDisabled  = $SkipIfDisabled
    }
}

function Test-TargetResource {
    [OutputType([System.Boolean])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'Wait', Justification = 'DSC parameter must be declared.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'TimeoutSeconds', Justification = 'DSC parameter must be declared.'
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

        [Parameter()]
        [bool]
        $Wait,

        [Parameter()]
        [int]
        $TimeoutSeconds = 600,

        [Parameter()]
        [bool]
        $SkipIfDisabled
    )

    $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName
    $resultPath = Join-Path -Path $env:SystemDrive -ChildPath 'CASPlus\DSCCache\TaskScheduler' |
        Join-Path -ChildPath $taskFullPath

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($TaskName
                            $TaskPath
                            $resultPath
                            $SkipIfDisabled)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $TaskName,

            [Parameter(Mandatory)]
            [string]
            $TaskPath,

            [Parameter()]
            [string]
            $ResultPath,

            [Parameter()]
            [bool]
            $SkipIfDisabled
        )

        $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName
        $taskPathNormalized = '{0}\' -f (Split-Path -Path $taskFullPath -Parent).TrimEnd('\')
        $task = Get-ScheduledTask |
                Where-Object { $_.TaskName -eq $TaskName -and $_.TaskPath -eq $taskPathNormalized }

        if ($null -eq $task) {
            Write-Verbose -Message ("Scheduled task '{0}' does not exist." -f $taskFullPath) -Verbose
            return $false
        }

        if ($SkipIfDisabled -and  $task.Settings.Enabled -eq $false) {
            Write-Verbose -Message ("Scheduled task '{0}' is set." -f $taskFullPath) -Verbose
            return $true
        }

        $result = Test-Path -Path $ResultPath

        if ($result) {
            Write-Verbose -Message ("File '{0}' exist." -f $ResultPath) -Verbose
            Write-Verbose -Message ("Scheduled task '{0}' is set." -f $taskFullPath) -Verbose
            return $true
        }

        Write-Verbose -Message ("File '{0}' does not exist." -f $ResultPath) -Verbose
        Write-Verbose -Message ("Scheduled task '{0}' is not set." -f $taskFullPath) -Verbose
        return $false
    }
}

function Set-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'SkipIfDisabled', Justification = 'DSC parameter must be declared.'
    )]
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

        [Parameter()]
        [bool]
        $Wait,

        [Parameter()]
        [int]
        $TimeoutSeconds = 600,

        [Parameter()]
        [bool]
        $SkipIfDisabled
    )

    $target = Join-Path -Path $TaskPath -ChildPath $TaskName

    if ($PSCmdlet.ShouldProcess($target)) {
        $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName
        $resultPath = Join-Path -Path $env:SystemDrive -ChildPath 'CASPlus\DSCCache\TaskScheduler' |
            Join-Path -ChildPath $taskFullPath

        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($TaskName
                                $TaskPath
                                $resultPath
                                $Wait
                                $TimeoutSeconds)
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
                [string]
                $ResultPath,

                [Parameter()]
                [bool]
                $Wait,

                [Parameter(Mandatory)]
                [int]
                $TimeoutSeconds
            )

            Write-Verbose -Message ("Invoking scheduled task '{0}'." -f $TaskName) -Verbose
            Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop

            if ($Wait) {
                $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName
                $taskPathNormalized = '{0}\' -f (Split-Path -Path $taskFullPath -Parent).TrimEnd('\')

                $timer = [Diagnostics.Stopwatch]::StartNew()

                while (
                    (
                        Get-ScheduledTask -TaskName $TaskName -TaskPath $taskPathNormalized |
                        Select-Object -ExpandProperty State
                    ) -ne
                    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.StateEnum]::Ready -and
                    $timer.Elapsed.TotalSeconds -lt $TimeoutSeconds
                ){
                    $message = ("Waiting scheduled task '{0}' to finish." -f $TaskName)
                    Write-Verbose -Message $message -Verbose
                    Start-Sleep -Seconds 5
                }

                $timer.Stop()

                if ($timer.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                    throw ("Scheduled task '$TaskName' did not finished in $($TimeoutSeconds) seconds " +
                            "on '$($env:COMPUTERNAME)'.")
                }

                $taskResult = Get-ScheduledTask -TaskName $TaskName -TaskPath $taskPathNormalized |
                                Get-ScheduledTaskInfo | Select-Object -ExpandProperty LastTaskResult

                $message = ("Scheduled task '{0}' finished with exit code '{1}'." -f
                            $TaskName, $taskResult)

                Write-Verbose -Message $message -Verbose

                if ($taskResult -ne 0) {
                    throw "Scheduled task '$TaskName' finished with exit code '$taskResult'."
                }
            }

            $resultPathParent = Split-Path -Path $ResultPath -Parent
            if (-not (Test-Path -Path $resultPathParent)) {
                Write-Verbose -Message ("Creating directory '{0}.'" -f $resultPathParent) -Verbose
                New-Item -Path $resultPathParent -ItemType Directory
            }

            Write-Verbose -Message ("Creating file '{0}'." -f $ResultPath) -Verbose
            Get-Date | Out-File -FilePath $ResultPath -Force
        }
    }
}