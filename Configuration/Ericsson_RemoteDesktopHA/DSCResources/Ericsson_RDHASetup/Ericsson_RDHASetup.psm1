Import-Module RemoteDesktop -Global

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ConnectionBroker,

        [Parameter()]
        [System.String]
        $ClientAccessName,

        [Parameter()]
        [System.String]
        $sqlServer,

        [Parameter()]
        [System.String]
        $sqlDatabase,

        [Parameter()]
        [System.String]
        $sqlAdmin,

        [Parameter()]
        [System.String]
        $sqlPassword,

        [Parameter()]
        [System.String]
        $connectionBrokerClusterDNS
    )

    $result = $null

    Write-Verbose "Getting the HA configuration..."

    $ha = Get-RDConnectionBrokerHighAvailability

    if ($HA)
    {
        $result = $true
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
        $ClientAccessName,

        [Parameter()]
        [System.String]
        $sqlServer,

        [Parameter()]
        [System.String]
        $sqlDatabase,

        [Parameter()]
        [System.String]
        $sqlAdmin,

        [Parameter()]
        [System.String]
        $sqlPassword,

        [Parameter()]
        [System.String]
        $connectionBrokerClusterDNS

    )

    Write-Verbose "Setting up the HA ..."

    $connectionString = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:$sqlServer,1433;Database=$sqlDatabase;Uid=$sqlAdmin;Pwd=$sqlPassword;Encrypt=yes;TrustServerCertificate=yes;Connection Timeout=30;"
    Set-RDConnectionBrokerHighAvailability -ClientAccessName $ClientAccessName -DatabaseConnectionString $connectionString

    #Include this line if the resource requires a system reboot.
    #$global:DSCMachineStatus = 1
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
        $ClientAccessName,

        [Parameter()]
        [System.String]
        $sqlServer,

        [Parameter()]
        [System.String]
        $sqlDatabase,

        [Parameter()]
        [System.String]
        $sqlAdmin,

        [Parameter()]
        [System.String]
        $sqlPassword,

        [Parameter()]
        [System.String]
        $connectionBrokerClusterDNS
    )

    Write-Verbose "Checking for existence of HA configuration..."

    $collection = Get-TargetResource @PSBoundParameters

    if ($collection)
    {
        Write-Verbose "The HA is set, nothing to do..."
        $result =  $true
    }
    else
    {
        Write-Verbose "The HA is not set on the connection broker..."
        $result = $false
    }

    Write-Verbose "Test-TargetResource returning:  $result"
    return $result
}

Export-ModuleMember -Function *-TargetResource

