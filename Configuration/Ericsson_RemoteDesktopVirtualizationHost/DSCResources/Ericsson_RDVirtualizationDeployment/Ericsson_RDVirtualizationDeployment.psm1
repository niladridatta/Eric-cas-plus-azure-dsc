Import-Module RemoteDesktop -Global

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]$ConnectionBroker,

        [string]$WebAccessServer,

        [string[]]$VirtualizationHosts
    )

    $servers = Get-RDServer -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue

    if($servers.Roles -contains "RDS-VIRTUALIZATION"){
        write-verbose "Found deployment consisting of $($servers.Count) servers:"
        $result =
        @{
            "ConnectionBroker" = ($servers | Where-Object Roles -contains "RDS-CONNECTION-BROKER").Server
            "WebAccessServer"  = ($servers | Where-Object Roles -contains "RDS-WEB-ACCESS").Server
            "VirtualizationHosts"   = $servers | Where-Object Roles -contains "RDS-VIRTUALIZATION" | ForEach-Object Server
        }
        write-verbose ">> RD Connection Broker:     $($result.ConnectionBroker.ToLower())"

        if ($result.WebAccessServer)
        {
            write-verbose ">> RD Web Access server:     $($result.WebAccessServer.ToLower())"
        }

        if ($result.VirtualizationHosts)
        {
            write-verbose ">> RD Virtualization Host servers:  $($result.VirtualizationHosts.ToLower() -join '; ')"
        }

    }
    else
    {
        write-verbose "Remote Desktop deployment does not exist on server '$ConnectionBroker' (or Remote Desktop Management Service is not running)."
    }

    $result
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ConnectionBroker,

        [Parameter()]
        [System.String]
        $WebAccessServer,

        [Parameter()]
        [System.String[]]
        $VirtualizationHosts
    )



    write-verbose "Initiating new RD Virtualization-based deployment on '$ConnectionBroker'..."

    write-verbose ">> RD Connection Broker:     $($ConnectionBroker.ToLower())"

    if ($WebAccessServer)
    {
        write-verbose ">> RD Web Access server:     $($WebAccessServer.ToLower())"

    }
    else
    {
        $PSBoundParameters.Remove("WebAccessServer")
    }

    write-verbose ">> RD Virtualization Host servers:  $($VirtualizationHosts -join '; ')"


    write-verbose "calling New-RDVirtualDesktopDeployment cmdlet..."
    #{
        $PSBoundParameters.Remove("VirtualizationHosts");

        New-RDVirtualDesktopDeployment @PSBoundParameters -VirtualizationHost $VirtualizationHosts
    #}
    write-verbose "New-RDVirtualDesktopDeployment done."


  # write-verbose "RD Virtualization deployment done, setting reboot flag..."
  # $global:DSCMachineStatus = 1

}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ConnectionBroker,

        [Parameter()]
        [System.String]
        $WebAccessServer,

        [Parameter()]
        [System.String[]]
        $VirtualizationHosts
    )

    write-verbose "Checking whether Remote Desktop deployment exists on server '$ConnectionBroker'..."

    $rddeployment = Get-TargetResource @PSBoundParameters

    if ($rddeployment)
    {
        write-verbose "verifying RD Connection broker name..."
        $result =  ($rddeployment.ConnectionBroker -ieq $ConnectionBroker)
    }
    else
    {
        write-verbose "RD deployment not found."
        $result = $false
    }

    write-verbose "Test-TargetResource returning:  $result"
    return $result
}

Export-ModuleMember -Function *-TargetResource

