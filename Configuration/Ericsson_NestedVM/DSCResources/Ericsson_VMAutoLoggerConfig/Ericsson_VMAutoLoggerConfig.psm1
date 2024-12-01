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
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string]
        $LoggerName
    )

    @{
        VMName = $VMName
        LoggerName = $LoggerName
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
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string]
        $LoggerName
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($LoggerName)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $LoggerName
        )

        # These loggers throw a CimException when you try to remove them:
        # Cellcore (0x800706be), RadioMgr (ObjectNotFound, MI RESULT 6), WinPhoneCritical (0x800706be)
        # Skipping them until this gets fixed somehow.
        if ($LoggerName -in "Cellcore", "RadioMgr", "WinPhoneCritical") {
            Write-Verbose -Message ("AutoLogger config '{0}' is set." -f $LoggerName) -Verbose
            return $true
        }

        $logger = Get-AutologgerConfig | Where-Object Name -EQ $LoggerName

        if ($null -ne $logger) {
            Write-Verbose -Message ("AutoLogger config '{0}' is not set." -f $LoggerName) -Verbose
            return $false
        }

        Write-Verbose -Message ("AutoLogger config '{0}' is set." -f $LoggerName) -Verbose
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
        $LoggerName
    )

    if ($PSCmdlet.ShouldProcess($LoggerName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($LoggerName)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [string]
                $LoggerName
            )

            Write-Verbose -Message ("Removing AutoLogger config '{0}'." -f $LoggerName) -Verbose
            Get-AutologgerConfig | Where-Object Name -EQ $LoggerName | Remove-AutologgerConfig
        }
    }
}