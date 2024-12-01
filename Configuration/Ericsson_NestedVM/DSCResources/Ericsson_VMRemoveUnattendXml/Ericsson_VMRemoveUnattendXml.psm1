function Get-TargetResource {
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    $invokeCommandParams = @{
        VMName      = $VMName
        Credential  = $LocalAdminCredential
    }

    $result = Invoke-Command @invokeCommandParams -ScriptBlock {
        Join-Path -Path $env:SystemDrive -ChildPath 'Windows\Panther\unattend.xml'
    }

    @{
        VMName = $VMName
        Result = $result
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
        $LocalAdminCredential
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName      = $VMName
        Credential  = $LocalAdminCredential
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        $unattendFilePath = Join-Path -Path $env:SystemDrive -ChildPath 'Windows\Panther\unattend.xml'
        $result = Test-Path -Path $unattendFilePath

        if ($result) {
            Write-Verbose -Message ("The file '{0}' exist." -f $unattendFilePath) -Verbose
            return $false
        }

        Write-Verbose -Message ("The file '{0}' does not exist." -f $unattendFilePath) -Verbose
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
            $unattendFilePath = Join-Path -Path $env:SystemDrive -ChildPath 'Windows\Panther\unattend.xml'

            If (Test-Path -Path $unattendFilePath) {
                Write-Verbose -Message ("Removing file '{0}'." -f $unattendFilePath) -Verbose
                Remove-Item -Path $unattendFilePath -Force
                return
            }

            Write-Verbose -Message ("'{0}' does not exist." -f $unattendFilePath) -Verbose
        }
    }
}