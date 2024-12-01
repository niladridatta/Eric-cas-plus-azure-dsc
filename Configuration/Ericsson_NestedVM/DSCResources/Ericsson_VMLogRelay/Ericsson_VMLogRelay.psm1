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
        $WEFServer
    )

    @{
        VMName      = $VMName
        WEFServer   = $WEFServer
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
        $WEFServer
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($WEFServer)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $WEFServer
        )

        $winRMService = Get-Service | Where-Object Name -EQ WinRM

        If ($winRMService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Verbose -Message "The 'WinRM' service is not running. Log relay is not set." -Verbose
            return $false
        }

        $winRMFirewallRule = Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-NoScope'

        if ($winRMFirewallRule.Enabled -ne $true) {
            $message = ("The 'WINRM-HTTP-In-TCP-NoScope' firewall rule is not enabled. " +
                        'Log relay is not set.')

            Write-Verbose -Message $message -Verbose
            return $false
        }

        $regPath = ('HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding' +
                    '\SubscriptionManager')

        $regKey = Test-Path -Path $regPath

        if (-not $regKey) {
            Write-Verbose -Message ("'{0}' does not exist. Log relay is not set." -f $regPath) -Verbose
            return $false
        }

        $itemProperty = Get-ItemProperty -Path $regPath

        $config = 'Server=http://{0}.ericsson.se:5985/wsman/SubscriptionManager/WEC,Refresh=30' -f
                    $WEFServer

        if ($itemProperty.1 -ne $config) {
            $message = ("'{0}\1' property is not set to '{1}'. Log relay is not set." -f
                        $regPath, $config)

            Write-Verbose -Message $message -Verbose
            return $false
        }

        $forwardedEventsChannelEnabled = Get-WinEvent -ListLog ForwardedEvents |
                                            Select-Object -ExpandProperty IsEnabled

        if (-not $forwardedEventsChannelEnabled) {
            $message = "'ForwardedEvents channel' is disabled. Log relay is not set."
            Write-Verbose -Message $message -Verbose
            return $false
        }

        # We need to check for delayed automatic service start however Get-Service in PowerShell 5
        # does not return if the automatic startup is delayed or not.
        $wecServiceConfig = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc'

        if ($wecServiceConfig.Start -ne 2 -and $wecServiceConfig.DelayedAutostart -ne 1) {
            $message = ("The 'Windows Event Collcetor' service is not set to " +
                        "'Automatic (Delayed)' start. Log relay is not set.")

            Write-Verbose -Message $message -Verbose
            return $false
        }

        $wecServiceStatus = Get-Service | Where-Object Name -EQ wecsvc |
                            Select-Object -ExpandProperty Status

        if ($wecServiceStatus -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            $message = "The 'Windows Event Collcetor' service is not running. Log relay is not set."
            Write-Verbose -Message $message -Verbose
            return $false
        }

        $expectedSubscriptions = @(
            'CASWECSubscriptionApp'
            'CASWECSubscriptionSec'
            'CASWECSubscriptionSys'
        )

        $wecutil = Get-Command -Name wecutil | Select-Object -First 1 -ExpandProperty Definition
        $subscriptions = & $wecutil 'es'

        $compareObjectParams = @{
            ReferenceObject     = $expectedSubscriptions
            DifferenceObject    = $subscriptions
        }

        $subscriptionsDifferent = Compare-Object @compareObjectParams

        if ($subscriptionsDifferent) {
            $message = ("The 'Windows Event Collcetor' subscriptions are not set. " +
                        'Log relay is not set.')

            Write-Verbose -Message $message -Verbose
            return $false
        }

        Write-Verbose -Message 'Log relay is set.' -Verbose
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
        [string]
        $WEFServer
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($WEFServer)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [string]
                $WEFServer
            )

            Write-Verbose -Message 'Configuring WinRM.' -Verbose
            $winrm = Get-Command -Name winrm | Select-Object -First 1 -ExpandProperty Definition
            Start-Process -FilePath $winrm -ArgumentList 'qc -q' -NoNewWindow -Wait

            $subscriptionManagerKey = ('HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\' +
                                        'EventForwarding\SubscriptionManager')

            if (-not (Test-Path -Path $subscriptionManagerKey))
            {
                $message = ("Creating registry key 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\" +
                            "EventLog\EventForwarding\SubscriptionManager'.")

                Write-Verbose -Message $message -Verbose
                New-Item -Path $subscriptionManagerKey -Force
            }

            $config = 'Server=http://{0}.ericsson.se:5985/wsman/SubscriptionManager/WEC,Refresh=30' -f
                        $WEFServer

            $message = ("Setting property '1' of 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\" +
                        "EventLog\EventForwarding\SubscriptionManager' to '{0}'." -f $config)

            Write-Verbose -Message $message -Verbose

            $newItemPropertyParams = @{
                Path            = ('HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\' +
                                    'SubscriptionManager')
                Name            = '1'
                Value           = $config
                PropertyType    = 'String'
            }

            New-ItemProperty @newItemPropertyParams -Force

            $wecutil = Get-Command -Name wecutil | Select-Object -First 1 -ExpandProperty Definition

            Write-Verbose -Message 'Configuring Windows Event Collcetor.' -Verbose
            Start-Process -FilePath $wecutil -ArgumentList 'qc /q' -NoNewWindow -Wait

            $subscriptions = & $wecutil 'es'

            foreach ($subscription in $subscriptions) {
                $message = ("Removing existing Event Collector subscription '{0}'." -f $subscription)
                Write-Verbose -Message $message -Verbose
                Start-Process -FilePath $wecutil -ArgumentList "ds ""$subscription""" -NoNewWindow -Wait
            }

            $applicationXMLPath = 'CASPlus\Deployment\cas-event-collector-application.xml'
            $securityXMLPath    = 'CASPlus\Deployment\cas-event-collector-security.xml'
            $systemXMLPath      = 'CASPlus\Deployment\cas-event-collector-system.xml'

            $xmls = @(
                Join-Path -Path $env:SystemDrive -ChildPath $applicationXMLPath
                Join-Path -Path $env:SystemDrive -ChildPath $securityXMLPath
                Join-Path -Path $env:SystemDrive -ChildPath $systemXMLPath
            )

            foreach ($xml in $xmls)
            {
                $message = ("Creating Event Collector subscription from '{0}'." -f $xml)
                Write-Verbose -Message $message -Verbose
                Start-Process -FilePath $wecutil -ArgumentList "cs ""$($xml)""" -NoNewWindow -Wait
            }
        }
    }
}