function Get-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Mandatory parameter must be declared.'
    )]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter()]
        [uint32]
        $SuccessfulConnectionCount = 10,

        [Parameter()]
        [uint32]
        $TimeoutSeconds = 900,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    @{
        Name                        = $Name
        VMName                      = $VMName
        SuccessfulConnectionCount   = $SuccessfulConnectionCount
        TimeoutSeconds              = $TimeoutSeconds
    }
}

function Test-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'Name', Justification = 'Parameter is not used')
    ]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'TimeoutSeconds', Justification = 'Parameter is not used')
    ]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter()]
        [uint32]
        $SuccessfulConnectionCount = 10,

        [Parameter()]
        [uint32]
        $TimeoutSeconds = 900,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    for ($i = 0; $i -lt $SuccessfulConnectionCount; $i++) {
        $invokeCommandParams = @{
            VMName      = $VMName
            Credential  = $LocalAdminCredential
        }

        $result = Invoke-Command @invokeCommandParams -ErrorAction SilentlyContinue -ScriptBlock {
            Write-Output 'Test'
        }

        if ($result -ne 'Test') {
            $message = ("Network connectivity to VM '{0}' is not available." -f $VMName)
            Write-Verbose -Message $message

            return $false
        }

        Start-Sleep -Seconds 1
    }

    Write-Verbose -Message ("Network connectivity to VM '{0}' is available." -f $VMName)
    return $true
}

function Set-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'Name', Justification = 'Key parameter must be declared.'
    )]
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter()]
        [uint32]
        $SuccessfulConnectionCount = 10,

        [Parameter()]
        [uint32]
        $TimeoutSeconds = 900,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        $counter = 0
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $successfulConnectionCount = $SuccessfulConnectionCount
        $timeoutSeconds = $TimeoutSeconds

        do {
            Start-Sleep -Seconds 1

            $counter++
            $invokeCommandParams = @{
                VMName      = $VMName
                Credential  = $LocalAdminCredential
            }

            $result = Invoke-Command @invokeCommandParams -ErrorAction SilentlyContinue -ScriptBlock {
                Write-Output 'Test'
            }

            if ($result -ne 'Test') {
                $counter = 0
            }
        } until ($counter -ge $successfulConnectionCount -or
            $timer.Elapsed.TotalSeconds -ge $timeoutSeconds)

        $timer.Stop()

        if ($counter -lt $successfulConnectionCount) {
            throw ("The VM '$($VMName)' has failed to reach $($successfulConnectionCount) " +
                    "consecutive successful connections in $($timeoutSeconds) seconds.")
        }

        Write-Verbose -Message ("Network connectivity to VM '{0}' is available." -f $VMName)
    }
}