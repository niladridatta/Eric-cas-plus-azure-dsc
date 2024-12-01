function Get-TargetResource{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Required parameter must be declared.'
    )]
    param(
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $UnattendDestinationPath,

        [Parameter(Mandatory)]
        [string]
        $VHDPath,

        [Parameter(Mandatory)]
        [string]
        $NestedComputerName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    @{
        VMName                  = $VMName
        UnattendDestinationPath = $UnattendDestinationPath
        VHDPath                 = $VHDPath
        NestedComputerName      = $NestedComputerName
    }
}

function Test-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter',
        'UnattendDestinationPath',
        Justification = 'Required parameter must be declared.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'VHDPath', Justification = 'Required parameter must be declared.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'NestedComputerName', Justification = 'Required parameter must be declared.'
    )]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Required parameter must be declared.'
    )]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $UnattendDestinationPath,

        [Parameter(Mandatory)]
        [string]
        $VHDPath,

        [Parameter(Mandatory)]
        [string]
        $NestedComputerName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    $vm = Get-VM | Where-Object Name -EQ $VMName

    if ($null -eq $vm) {
        Write-Verbose -Message "The unattend.xml is not set."
        return $false
    }

    Write-Verbose -Message "The unattend.xml is set."
    return $true
}

function Set-TargetResource {
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'VMName', Justification = 'Key parameter must be declared.'
    )]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $UnattendDestinationPath,

        [Parameter(Mandatory)]
        [string]
        $VHDPath,

        [Parameter(Mandatory)]
        [string]
        $NestedComputerName,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    if ($PSCmdlet.ShouldProcess($VHDPath)) {
        Write-Verbose -Message ("Mounting virtual disk '{0}'." -f $VHDPath)
        $rootOfNestedDisk = Mount-VHD -Path $VHDPath -PassThru | Get-Disk | Get-Partition |
            Get-Volume | Sort-Object Size -Descending | Select-Object -First 1 -ExpandProperty DriveLetter

        Write-Verbose -Message ("Virtual disk mounted with drive letter '{0}'." -f $rootOfNestedDisk)

        $joinPathParams = @{
            Path        = "$($rootOfNestedDisk):"
            ChildPath   = 'Windows\Panther\unattend.xml'
        }

        $unattendFilePath = Join-Path @joinPathParams

        Write-Verbose -Message ("Loading unattend.xml from '{0}'." -f $UnattendDestinationPath)
        $unattendXml = [xml](Get-Content -Path $UnattendDestinationPath)
        $unattendXmlNamespace = @{ u = $unattendXml.unattend.xmlns }
        $unattendXmlUpdates = @{
            ("/u:unattend/u:settings[@pass='specialize']" +
            "/u:component[@name='Microsoft-Windows-Shell-Setup']" +
            "/u:ComputerName") = $NestedComputerName

            ("/u:unattend/u:settings[@pass='oobeSystem']" +
            "/u:component[@name='Microsoft-Windows-Shell-Setup']" +
            "/u:UserAccounts/u:AdministratorPassword" +
            "/u:Value") = $($LocalAdminCredential).GetNetworkCredential().password

            ("/u:unattend/u:settings[@pass='oobeSystem']" +
            "/u:component[@name='Microsoft-Windows-Shell-Setup']" +
            "/u:UserAccounts/u:LocalAccounts/u:LocalAccount[u:Name='Administrator']/u:Password" +
            "/u:Value") = $($LocalAdminCredential).GetNetworkCredential().password
        }

        Write-Verbose -Message "Updating unattend.xml."
        foreach ($update in $unattendXmlUpdates.GetEnumerator()) {
            (Select-Xml -Xml $unattendXml -XPath $update.Name -Namespace $unattendXmlNamespace).
                Node.'#text' = $update.Value
        }

        # Save updated xml file
        Write-Verbose -Message ("Saving unattend.xml to '{0}'." -f $unattendFilePath)
        $unattendXml.Save($unattendFilePath)

        Write-Verbose -Message ("Dismounting virtual disk '{0}'." -f $VHDPath)
        Dismount-VHD $VHDPath
    }
}