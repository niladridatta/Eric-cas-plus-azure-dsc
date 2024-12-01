if ([System.Environment]::OSVersion.Version -lt "6.2.9200.0") { Throw "The minimum OS requirement was not met."}

Import-Module RemoteDesktop -Global

$localhost = [System.Net.Dns]::GetHostByName((hostname)).HostName


#######################################################################
# The Get-TargetResource cmdlet.
#######################################################################
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [string] $ConnectionBroker,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CollectionName,

        [string] $CollectionDescription,

        [string[]] $SessionHosts
    )

    $result = $null

    if ($ConnectionBroker)
    {
        Write-Verbose "Getting information about RD Session collection '$CollectionName' at RD Connection Broker '$ConnectionBroker'..."

        $collection = Get-RDSessionCollection -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -ea SilentlyContinue
    }
    else
    {
        Write-Verbose "Getting information about RD Session collection '$CollectionName'..."

        $collection = Get-RDSessionCollection -CollectionName $CollectionName -ea SilentlyContinue

        $ConnectionBroker = $localhost
    }

    if ($collection.CollectionName -eq $CollectionName)
    {
        Write-Verbose "Found the collection, now getting list of RD Session Host servers..."

        $actualSessionHosts = Get-RDSessionHost -CollectionName $CollectionName | ForEach-Object SessionHost

        Write-Verbose "Found $($actualSessionHosts.Count) host servers assigned to the collection."

        If($actualSessionHosts.Count -ne $SessionHosts.Count){
            Write-Verbose "Not all VMs are in the collection..."
        }else{
            $result =
            @{
                "ConnectionBroker" = $ConnectionBroker
                "CollectionName"   = $collection.CollectionName
                "CollectionDescription" = $collection.CollectionDescription
                "SessionHosts" = $SessionHosts
            }
            Write-Verbose ">> Collection name:  $($result.CollectionName)"
            Write-Verbose ">> Collection description:  $($result.CollectionDescription)"
            Write-Verbose ">> RD Connection Broker:  $($result.ConnectionBroker.ToLower())"
            Write-Verbose ">> RD Session Host servers:  $($result.SessionHosts.ToLower() -join '; ')"
        }
    }
    else
    {
        Write-Verbose "RD Session collection '$CollectionName' not found."
    }

    $result
}


########################################################################
# The Set-TargetResource cmdlet.
########################################################################
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [string] $ConnectionBroker,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CollectionName,

        [string] $CollectionDescription,

        [string[]] $SessionHosts
    )

    if ($ConnectionBroker)
    {
        Write-Verbose "Creating or supplementing the RD Session collection '$CollectionName' at the RD Connection Broker '$ConnectionBroker'..."
    }
    else
    {
        $PSBoundParameters.Remove("ConnectionBroker")
        Write-Verbose "Creating or supplementing the RD Session collection '$CollectionName'..."
    }

    if ($CollectionDescription)
    {
        Write-Verbose "Description: '$CollectionDescription'"
    }
    else
    {
        $PSBoundParameters.Remove("CollectionDescription")
    }

    if ($SessionHosts)
    {
        Write-Verbose ">> RD Session Host servers:  $($SessionHosts.ToLower() -join '; ')"
    }
    else
    {
        $SessionHosts = @( $localhost )
    }

    $PSBoundParameters.Remove("SessionHosts")

    $doesTheCollectionExist = Get-RDSessionCollection -CollectionName $CollectionName -ErrorAction SilentlyContinue | Where-Object {$_.CollectionName -eq $CollectionName}

    if($null -ne $doesTheCollectionExist){
        Write-Verbose "Supplementing the collection..."
        $actualSessionHosts = Get-RDSessionHost -CollectionName $CollectionName  | ForEach-Object SessionHost
        $sessionHostsToSupplement = Compare-Object $SessionHosts $actualSessionHosts -PassThru
        $PSBoundParameters.Remove("CollectionDescription")
        $sessionHostsToSupplement | ForEach-Object {Add-RDServer -Server $_ -Role RDS-RD-SERVER}
        Add-RDSessionHost @PSBoundParameters -SessionHost $sessionHostsToSupplement -ErrorAction SilentlyContinue | Out-Null
    }else{
        Write-Verbose "Calling New-RdSessionCollection cmdlet..."
        New-RDSessionCollection @PSBoundParameters -SessionHost $SessionHosts -ErrorAction SilentlyContinue
    }
}


#######################################################################
# The Test-TargetResource cmdlet.
#######################################################################
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [string] $ConnectionBroker,

        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $CollectionName,

        [string] $CollectionDescription,

        [string[]] $SessionHosts
    )

    Write-Verbose "Checking for existence of RD Session collection named '$CollectionName'..."

    $collection = Get-TargetResource @PSBoundParameters

    if ($collection.CollectionName -eq $CollectionName)
    {
        Write-Verbose "Verifying RD Session collection name and parameters..."
        $result =  ($collection.CollectionName -ieq $CollectionName)
    }
    else
    {
        Write-Verbose "RD Session collection named '$CollectionName' not found or the collection need to be supplemented."
        $result = $false
    }

    Write-Verbose "Test-TargetResource returning:  $result"
    return $result
}


Export-ModuleMember -Function *-TargetResource