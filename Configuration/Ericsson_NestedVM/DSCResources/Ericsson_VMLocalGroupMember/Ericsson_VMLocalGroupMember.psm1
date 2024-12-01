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
        $MemberName,

        [Parameter(Mandatory)]
        [string]
        $GroupName
    )

    @{
        VMName      = $VMName
        MemberName  = $MemberName
        GroupName   = $GroupName
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
        $MemberName,

        [Parameter(Mandatory)]
        [string]
        $GroupName
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($MemberName
                            $GroupName)
    }


    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $MemberName,

            [Parameter(Mandatory)]
            [string]
            $GroupName
        )

        $message = "Checking if user '{0}' is the member of the group '{1}'." -f
            $MemberName, $GroupName

        Write-Verbose -Message $message

        $group = Get-LocalGroup -Name $GroupName
        $user = Get-LocalGroupMember -Group $group | Where-Object { $_.Name -eq $MemberName }

        if ($user) {
            Write-Verbose -Message ("The group '{0}' is set." -f $GroupName) -Verbose
            return $true
        }

        Write-Verbose -Message ("The group '{0}' is not set." -f $GroupName) -Verbose
        return $false
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
        $MemberName,

        [Parameter(Mandatory)]
        [string]
        $GroupName
    )

    if ($PSCmdlet.ShouldProcess($GroupName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($MemberName
                                $GroupName)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [string]
                $MemberName,

                [Parameter(Mandatory)]
                [string]
                $GroupName
            )

            $group = Get-LocalGroup -Name $GroupName

            $message = ("Adding member '{0}' to group '{1}'." -f $MemberName, $GroupName)
            Write-Verbose -Message $message -Verbose

            Add-LocalGroupMember -Group $group -Member $MemberName
        }
    }
}