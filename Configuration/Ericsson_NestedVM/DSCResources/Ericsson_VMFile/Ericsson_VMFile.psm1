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
        $SourcePath,

        [Parameter(Mandatory)]
        [string]
        $DestinationPath
    )

    @{
        VMName          = $VMName
        SourcePath      = $SourcePath
        DestinationPath = $DestinationPath
    }
}

function Test-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'SourcePath', Justification = 'Key parameter must be declared.'
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
        $SourcePath,

        [Parameter(Mandatory)]
        [string]
        $DestinationPath
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($DestinationPath)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $DestinationPath
        )

        $result = Test-Path -Path $DestinationPath

        if ($result) {
            Write-Verbose -Message ("'{0}' is set." -f $DestinationPath) -Verbose
            return $true
        }

        Write-Verbose -Message ("'{0}' is not set." -f $DestinationPath) -Verbose
        return $false
    }
}

function Set-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Mandatory parameter must be declared.'
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
        $SourcePath,

        [Parameter(Mandatory)]
        [string]
        $DestinationPath
    )

    if ($PSCmdlet.ShouldProcess($DestinationPath)) {
        $copyVMFileParams = @{
            "VMName"            = $VMName
            "SourcePath"        = $SourcePath
            "DestinationPath"   = $DestinationPath
            "CreateFullPath"    = $true
            "FileSource"        = "Host"
        }

        Copy-VMFile @copyVMFileParams
    }
}