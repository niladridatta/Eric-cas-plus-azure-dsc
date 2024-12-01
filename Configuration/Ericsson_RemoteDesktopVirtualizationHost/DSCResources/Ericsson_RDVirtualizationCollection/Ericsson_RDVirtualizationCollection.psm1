Import-Module RemoteDesktop -Global

$localhost = [System.Net.Dns]::GetHostByName((hostname)).HostName

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $CollectionName,

        [Parameter()]
        [System.String]
        $ConnectionBroker,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String[]]
        $VirtualizationHosts,

        [Parameter()]
        [System.String]
        $DomainName,

        [Parameter()]
        [System.String]
        $UserGroups
    )

    $result = $null

    if ($ConnectionBroker)
    {
        Write-Verbose "Getting information about RD Virtualization collection '$CollectionName' at RD Connection Broker '$ConnectionBroker'..."

        $collection = Get-RDVirtualDesktopCollection  -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue
    }
    else
    {
        Write-Verbose "Getting information about RD Virtualization collection '$CollectionName'..."
        $ConnectionBroker = $localhost
        $collection = Get-RDVirtualDesktopCollection -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue
    }

    if ($collection.CollectionName -eq $CollectionName)
    {
        Write-Verbose "Found the collection, now getting list of RD Virtualization Host servers..."
        $existingVirtualizationHosts = Get-RDVirtualDesktop -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker | Select-Object -ExpandProperty HostName
        Write-Verbose "Found $($existingVirtualizationHosts.Count) host servers assigned to the collection."

        if($existingVirtualizationHosts.Count -ne $VirtualizationHosts.Count){
            Write-Verbose "Not all VMs are in the collection..."
        }else{
            $result =
            @{
                "ConnectionBroker" = $ConnectionBroker
                "CollectionName"   = $collection.CollectionName
                "Description" = $collection.Description
                "VirtualizationHosts" = $ExistingVirtualizationHosts
            }

            Write-Verbose ">> Collection name:  $($result.CollectionName)"
            Write-Verbose ">> Collection description:  $($result.Description)"
            Write-Verbose ">> RD Connection Broker:  $($result.ConnectionBroker.ToLower())"
            if($ExistingVirtualizationHosts.count -gt 1){
                Write-Verbose ">> RD Virtualization Host servers:  $($result.VirtualizationHosts.ToLower() -join '; ')"
            }
        }
    }else{
        Write-Verbose "RD Virtualization collection '$CollectionName' not found."
    }

    $result
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $ConnectionBroker,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CollectionName,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String[]]
        $VirtualizationHosts,

        [Parameter()]
        [System.String]
        $DomainName,

        [Parameter()]
        [System.String]
        $UserGroups
    )

    if ($ConnectionBroker)
    {
        Write-Verbose "Creating or supplementing the RD Virtualization collection '$CollectionName' at the RD Connection Broker '$ConnectionBroker'..."
    }
    else
    {
        $PSBoundParameters.Remove("ConnectionBroker")
        Write-Verbose "Creating or supplementing the RD Virtualization collection '$CollectionName'..."
    }

    if ($Description)
    {
        Write-Verbose "Description: '$Description'"
    }
    else
    {
        $PSBoundParameters.Remove("Description")
    }

    if ($VirtualizationHosts)
    {
        Write-Verbose ">> RD Virtualization Host servers:  $($VirtualizationHosts -join '; ')"
    }

    if ($DomainName)
    {
        $virtualDesktopNames = $VirtualizationHosts | ForEach-Object {"{0}{1}" -f "Nested", $_ -replace ".$DomainName", ""}
        $PSBoundParameters.Remove("DomainName")
    }else{
        $virtualDesktopNames = $VirtualizationHosts | ForEach-Object {"{0}{1}" -f "Nested", $_}
    }

    $PSBoundParameters.Remove("VirtualizationHosts")

    $doesTheCollectionExist = Get-RDVirtualDesktopCollection -CollectionName $CollectionName -ErrorAction SilentlyContinue

    if($null -ne $doesTheCollectionExist){
        Write-Verbose "The collection exists, supplementing the members..."
        $PSBoundParameters.Remove("Description")
        $PSBoundParameters.Remove("DomainName")
        $PSBoundParameters.Remove("UserGroups")
        $actualMembers =  Get-RDVirtualDesktop -CollectionName $CollectionName
        $actualVirtualDesktops = $actualMembers | ForEach-Object VirtualDesktopName
        $actualVirtualizationHosts = $actualMembers | ForEach-Object HostName
        $virtualDesktopsToSupplement = Compare-Object $virtualDesktopNames $actualVirtualDesktops -PassThru
        $virtualizationHostsToSupplement = Compare-Object $VirtualizationHosts $actualVirtualizationHosts -PassThru
        $virtualizationHostsToSupplement | ForEach-Object {Add-RDServer -Server $_ -Role RDS-VIRTUALIZATION -ErrorAction SilentlyContinue | Out-Null }
        Add-RDVirtualDesktopToCollection @PSBoundParameters -VirtualDesktopName $virtualDesktopsToSupplement
    }else{
        try{
            Write-Verbose "Calling New-RDVirtualDesktopCollection cmdlet..."
            New-RDVirtualDesktopCollection @PSBoundParameters -VirtualDesktopName $virtualDesktopNames -PooledUnmanaged
        }catch{
            Write-Verbose "Something went wrong, cleaning up!"
            Write-Verbose "Calling Remove-RDVirtualDesktopCollection cmdlet..."
            Remove-RDVirtualDesktopCollection -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -Force -ErrorAction SilentlyContinue
            Write-Error "Failed to create the '$CollectionName' collection"
            return 1
        }
    }

    #Include this line if the resource requires a system reboot.
    #$global:DSCMachineStatus = 1
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter()]
        [System.String]
        $ConnectionBroker,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CollectionName,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String[]]
        $VirtualizationHosts,

        [Parameter()]
        [System.String]
        $DomainName,

        [Parameter()]
        [System.String]
        $UserGroups
    )

    Write-Verbose "Checking for existence of RD Virtualization collection named '$CollectionName'..."

    $collection = Get-TargetResource @PSBoundParameters

    if ($collection.CollectionName -eq $CollectionName)
    {
        Write-Verbose "Verifying RD Virtualization collection name and parameters..."
        $result =  ($collection.CollectionName -ieq $CollectionName)
    }
    else
    {
        Write-Verbose "RD Virtualization collection named '$CollectionName' not found."
        $result = $false
    }

    Write-Verbose "Test-TargetResource returning:  $result"
    return $result
}


Export-ModuleMember -Function *-TargetResource

