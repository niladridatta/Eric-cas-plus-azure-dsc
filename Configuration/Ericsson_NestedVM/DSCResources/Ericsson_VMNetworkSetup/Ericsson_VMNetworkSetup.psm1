function Get-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'LocalAdminCredential', Justification = 'Mandatory parameter must be declared.'
    )]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $IP,

        [Parameter(Mandatory)]
        [byte]
        $SubnetMask,

        [Parameter(Mandatory)]
        [string]
        $DefaultGateway,

        [Parameter(Mandatory)]
        [string]
        $DomainDNSName,

        [Parameter(Mandatory)]
        [array]
        $DNSServers,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    @{
        VMName = $VMName
        IP = $IP
        SubnetMask = $SubnetMask
        DefaultGateway = $DefaultGateway
        DomainDNSName = $DomainDNSName
        DNSServers = $DNSServers
    }
}

function Test-TargetResource {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', 'SubnetMask', Justification = 'DSC parameters must be declared.'
    )]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $IP,

        [Parameter(Mandatory)]
        [byte]
        $SubnetMask,

        [Parameter(Mandatory)]
        [string]
        $DefaultGateway,

        [Parameter(Mandatory)]
        [string]
        $DomainDNSName,

        [Parameter(Mandatory)]
        [array]
        $DNSServers,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    $pingTest = Test-Connection -ComputerName $IP -Quiet

    if (-not $pingTest) {
        Write-Verbose -Message ("The network of VM '{0}' is not set." -f $VMName)
        return $false
    }

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @(
                            $IP
                            $DefaultGateway
                            $DomainDNSName
                            (, $DNSServers)
                        )
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $IP,

            [Parameter(Mandatory)]
            [string]
            $DefaultGateway,

            [Parameter(Mandatory)]
            [string]
            $DomainDNSName,

            [Parameter(Mandatory)]
            [string[]]
            $DNSServers
        )

        $interfaceIndex = Get-NetAdapter -InterfaceDescription 'Microsoft Hyper-V Network Adapter*' |
            Select-Object -First 1 -ExpandProperty ifIndex

        $ipAddressAssigned = Get-NetIPAddress | Where-Object IPAddress -EQ $IP

        if (-not $ipAddressAssigned -or $ipAddressAssigned.InterfaceIndex -ne $interfaceIndex) {
            Write-Verbose -Message 'The IP addres on VM is not set.' -Verbose
            return $false
        }

        $defaultGatewayAssigned = Get-NetIPConfiguration -InterfaceIndex $interfaceIndex |
                                    Select-Object -First 1 -ExpandProperty IPv4DefaultGateway |
                                    Select-Object -ExpandProperty NextHop

        if (-not $defaultGatewayAssigned -or $defaultGatewayAssigned -ne $DefaultGateway) {
            Write-Verbose -Message 'The default gateway on VM is not set.' -Verbose
            return $false
        }

        $getDnsClientServerAddressParams = @{
            InterfaceIndex  = $interfaceIndex
            AddressFamily   = 'IPv4'
        }

        $dnsServersAssigned = Get-DnsClientServerAddress  @getDnsClientServerAddressParams |
                                Select-Object -ExpandProperty ServerAddresses

        $compareObjectParams = @{
            ReferenceObject     = $DNSServers
            DifferenceObject    = $dnsServersAssigned
        }

        $dnsServersDontMatch = Compare-Object @compareObjectParams

        if ($dnsServersDontMatch) {
            Write-Verbose -Message 'The DNS server on VM is not set.' -Verbose
            return $false
        }

        Get-NetIPInterface -InterfaceIndex $interfaceIndex | ForEach-Object {
            if ($_.NlMtu -ne 1400) {
                Write-Verbose -Message 'The MTU size on VM is not set.' -Verbose
                return $false
            }
        }

        Write-Verbose -Message ("Testing connectivity to domain '{0}'." -f $DomainDNSName) -Verbose
        Test-Connection -ComputerName $DomainDNSName -Quiet
    }
}

function Set-TargetResource {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter(Mandatory)]
        [string]
        $IP,

        [Parameter(Mandatory)]
        [byte]
        $SubnetMask,

        [Parameter(Mandatory)]
        [string]
        $DefaultGateway,

        [Parameter(Mandatory)]
        [string]
        $DomainDNSName,

        [Parameter(Mandatory)]
        [array]
        $DNSServers,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @(
                                $IP
                                $SubnetMask
                                $DefaultGateway
                                $DomainDNSName
                                (, $DNSServers)
                            )
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [string]
                $IP,

                [Parameter(Mandatory)]
                [byte]
                $SubnetMask,

                [Parameter(Mandatory)]
                [string]
                $DefaultGateway,

                [Parameter(Mandatory)]
                [string]
                $DomainDNSName,

                [Parameter(Mandatory)]
                [string[]]
                $DNSServers
            )

            $message = "Enabling firewall rule 'File and Printer Sharing (Echo Request - ICMPv4-In)'."
            Write-Verbose -Message $message -Verbose

            $setNetFirewallRule = @{
                DisplayName     = 'File and Printer Sharing (Echo Request - ICMPv4-In)'
                Enabled         = 'True'
            }

            Set-NetFirewallRule @setNetFirewallRule

            $interfaceIndex = Get-NetAdapter -InterfaceDescription 'Microsoft Hyper-V Network Adapter*' |
                                Select-Object -First 1 -ExpandProperty ifIndex
            Write-Verbose -Message ("Setting network interface '{0}'." -f $interfaceIndex) -Verbose

            $ipAddressAssigned = Get-NetIPAddress | Where-Object IPAddress -EQ $IP

            if ($ipAddressAssigned) {
                Write-Verbose -Message ("IP address '{0}' already assigned. Removing." -f $IP) -Verbose
                Remove-NetIPAddress -IPAddress $IP -Confirm:$false
            }

            $defaultGatewayAssigned = Get-NetIPConfiguration -InterfaceIndex $interfaceIndex |
                                        Select-Object -First 1 -ExpandProperty IPv4DefaultGateway

            if ($defaultGatewayAssigned) {
                $message = ('Default gateway already assigned to network interface ' +
                            "'{0}'. Removing." -f $interfaceIndex)

                Write-Verbose -Message $message -Verbose
                Remove-NetRoute -InterfaceIndex $interfaceIndex -Confirm:$false
            }

            $message = (("Setting the IP address '{0}' on network interface '{1}' with prefix '{2}' " +
                        "and default gateway '{3}'.") -f
                        $IP, $interfaceIndex, $SubnetMask, $DefaultGateway)

            Write-Verbose -Message $message -Verbose

            $newNetIPAddressParams = @{
                IPAddress       = $IP
                InterfaceIndex  = $interfaceIndex
                PrefixLength    = $SubnetMask
                DefaultGateway  = $DefaultGateway
            }

            New-NetIPAddress @newNetIPAddressParams

            $message = ("Setting DNS server on network interface '{0}'." -f $interfaceIndex)
            Write-Verbose -Message $message -Verbose

            Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses $DNSServers

            # Reduce default MTU as recommended by microsoft for VPNs - fix for http-proxy with Telefonica
            # https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-tcpip-performance-tuning

            $message = ("Setting MTU on network interface '{0}' to '{1}'." -f $interfaceIndex, 1400)
            Write-Verbose -Message $message -Verbose
            Set-NetIPInterface -InterfaceIndex $interfaceIndex -NlMtuBytes 1400

            Start-Sleep -Seconds 3

            Write-Verbose -Message ("Testing connectivity to domain '{0}'." -f $DomainDNSName) -Verbose
            $domainAvailable = Test-Connection -ComputerName $DomainDNSName -Quiet

            if (-not $domainAvailable) {
                throw 'The network connection test from the nested VM to the domain has failed.'
            }

            $message = ("Network connectivity to domain '{0}' is available." -f $DomainDNSName)
            Write-Verbose -Message $message -Verbose
        }

        Start-Sleep -Seconds 3

        Write-Verbose -Message ("Testing connectivity to IP address '{0}'." -f $IP)
        $nestedVMAvailable = Test-Connection -ComputerName $IP -Quiet

        if (-not $nestedVMAvailable) {
            throw 'The network connection test from the host to the nested VM has failed.'
        }

        Write-Verbose -Message ("Network connectivity to '{0}' is available." -f $IP)
    }
}