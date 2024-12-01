function Get-TargetResource {
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential,

        [Parameter(Mandatory)]
        [string[]]
        $RuleFiles
    )

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($RuleFiles)
    }

    $result = Invoke-Command @invokeCommandParams -ScriptBlock {
        param (
            [Parameter(Mandatory)]
            [string[]]
            $RuleFiles
        )

        $results = New-Object -TypeName PSObject -Property @{
            RuleFiles    = @()
            ServiceState = (Get-Service -Name "AppIdSvc").Status
        }

        foreach ($ruleFile in $RuleFiles) {
            if (Test-Path -Path $ruleFile) {
                Write-Output ("Rule file '{0}' exists" -f $ruleFile)
                $results.RuleFiles += $ruleFile
            }
        }

        return $results
    }

    @{
        VMName          = $VMName
        RuleFiles       = $result.RuleFiles
        ServiceState    = $result.ServiceState
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
        [string[]]
        $RuleFiles
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($RuleFiles)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param (
            [Parameter(Mandatory)]
            [string[]]
            $RuleFiles
        )

        foreach ($ruleFile in $RuleFiles) {
            if (!(Test-Path -Path $ruleFile)) {
                Write-Verbose -Message ("AppLocker rule file '{0}' not found" -f $ruleFile) -Verbose
                return $false
            }
        }

        $serviceState = (Get-Service -Name "AppIdSvc").Status

        if ($serviceState -NE "Running") {
            Write-Verbose -Message ("AppLocker rule file(s) found, but AppLocker service is not running") -Verbose
            return $false
        }

        Write-Verbose -Message ("AppLocker rule file(s) found, AppLocker service is running") -Verbose
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
        [string[]]
        $RuleFiles

    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($RuleFiles)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param (
                [Parameter(Mandatory)]
                [string[]]
                $RuleFiles
            )

            # Import policies from XML
            foreach ($ruleFile in $RuleFiles) {
                Write-Verbose -Message ("Trying to import AppLocker rule file '{0}'" -f $ruleFile) -Verbose
                Set-AppLockerPolicy -XMLPolicy $ruleFile -Verbose
            }

            # Start up and enable AppLocker
            Write-Verbose -Message ("Configuring and starting up AppLocker on nested VM") -Verbose
            Start-Process -FilePath "sc.exe" -ArgumentList "config appidsvc start=auto" -Wait -NoNewWindow
            Start-Service -Name "AppIDSvc"
        }
    }
}
