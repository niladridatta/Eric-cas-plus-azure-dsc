<#PSScriptInfo
.VERSION 1.0
.GUID 65af6b87-bf6a-4eb2-a9bc-ec53c333d6e7
.AUTHOR Ericsson
#>

<#
.DESCRIPTION
Update-DeploymentArtifacts
#>

[CmdletBinding()]
param (
    [Alias('n')]
    [Parameter(Mandatory)]
    [string]
    $StorageAccountName,

    [Alias('r')]
    [Parameter(Mandatory)]
    [string]
    $ResourceGroupName,

    [Alias('c')]
    [Parameter()]
    [string]
    $ContainerName = 'configurations'
)

$files = @(
    '.\Configuration.zip'
)

$keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
$context = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $keys[0].Value -ErrorAction Stop

Compress-Archive -Path '.\Configuration\*' -DestinationPath .\Configuration.zip -Force

$files | ForEach-Object { Set-AzStorageBlobContent -File $_ -Container $ContainerName -Context $context -Force }

Remove-Item -Path .\Configuration.zip -Force
