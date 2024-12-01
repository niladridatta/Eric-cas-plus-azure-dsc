function Get-TargetResource {
    param (
        [Parameter(Mandatory)]
        [string]
        $TaskName,

        [Parameter(Mandatory)]
        [string]
        $TaskPath
    )

    @{
        TaskName = $TaskName
        TaskPath = $TaskPath
    }
}

function Test-TargetResource {
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory)]
        [string]
        $TaskName,

        [Parameter(Mandatory)]
        [string]
        $TaskPath
    )

    $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName

    $resultPath = Join-Path -Path $env:SystemDrive -ChildPath "CASPlus\DSCCache\TaskScheduler" |
                  Join-Path -ChildPath $taskFullPath

    Write-Verbose -Message ("Cheking if file exist '{0}'." -f $resultPath)
    Test-Path -Path $resultPath
}

function Set-TargetResource {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $TaskName,

        [Parameter(Mandatory)]
        [string]
        $TaskPath
    )

    $target = Join-Path -Path $TaskPath -ChildPath $TaskName

    if ($PSCmdlet.ShouldProcess($target)) {
        $taskFullPath = Join-Path -Path $TaskPath -ChildPath $TaskName

        $resultPath = Join-Path -Path $env:SystemDrive -ChildPath "CASPlus\DSCCache\TaskScheduler" |
                      Join-Path -ChildPath $taskFullPath

        Write-Verbose -Message ("Invoking scheduled task '{0}'." -f $TaskName)
        Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName

        $resultPathParent = Split-Path -Path $resultPath -Parent

        if (-not (Test-Path -Path $resultPathParent)) {
            Write-Verbose -Message ("Creating directory '{0}.'" -f $resultPathParent)
            New-Item -Path $resultPathParent -ItemType Directory
        }

        Write-Verbose -Message ("Creating file '{0}'." -f $resultPath)
        Get-Date | Out-File -FilePath $resultPath -Force
    }
}