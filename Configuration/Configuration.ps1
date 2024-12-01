<#PSScriptInfo
.VERSION 1.1
.GUID 289a8758-6f44-427b-a898-f5065a7756b8
.AUTHOR Ericsson
#>

<#
.DESCRIPTION
Configurations
#>

configuration DomainJoin
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', "", Justification = 'False positive.')
    ]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [string]
        $DomainOU,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers,

        [Parameter()]
        [int]
        $RetryCount = 200,

        [Parameter()]
        [int]
        $RetryIntervalSec = 30
    )

    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 3.0.0.0
    Import-DscResource -ModuleName xComputerManagement -ModuleVersion 4.1.0.0

    $domainCreds = [pscredential]::new("$DomainName\$($AdminCreds.UserName)", $AdminCreds.Password)

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }

        WindowsFeature ADPowershell
        {
            Name    = "RSAT-AD-PowerShell"
            Ensure  = "Present"
        }

        xWaitForADDomain DscForestWait
        {
            DomainName              = $DomainName
            DomainUserCredential    = $domainCreds
            RetryCount              = $RetryCount
            RetryIntervalSec        = $RetryIntervalSec
            DependsOn               = "[WindowsFeature]ADPowershell"
        }

        xComputer DomainJoin
        {
            Name        = $env:COMPUTERNAME
            DomainName  = $DomainName
            Credential  = $DomainCreds
            JoinOU      = $DomainOU
            DependsOn   = "[xWaitForADDomain]DscForestWait"
        }

        Registry RdmsEnableUILog
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS"
            ValueName   = "EnableUILog"
            ValueType   = "Dword"
            ValueData   = "1"
        }

        Registry EnableDeploymentUILog
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS"
            ValueName   = "EnableDeploymentUILog"
            ValueType   = "Dword"
            ValueData   = "1"
        }

        Registry EnableTraceLog
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS"
            ValueName   = "EnableTraceLog"
            ValueType   = "Dword"
            ValueData   = "1"
        }

        Registry EnableTraceToFile
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS"
            ValueName   = "EnableTraceToFile"
            ValueType   = "Dword"
            ValueData   = "1"
        }

        # CVE-2013-3900
        Registry EnableCertPaddingCheck
        {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Wintrust\Config'
            ValueName   = 'EnableCertPaddingCheck'
            ValueType   = 'String'
            ValueData   = '1'
        }

        # CVE-2013-3900
        Registry EnableCertPaddingCheckx86
        {
            Ensure      = 'Present'
            Key         = 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'
            ValueName   = 'EnableCertPaddingCheck'
            ValueType   = 'String'
            ValueData   = '1'
        }

        Group AddUsersToAdminGroup
        {
            GroupName        = "Administrators"
            MembersToInclude = $LocalAdminGroupMembers
            DependsOn        = "[xComputer]DomainJoin"
        }

        Registry TurnOffPowerShellTranscription
        {
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
            ValueName = "EnableTranscripting"
            ValueType = "Dword"
            ValueData = "0"
        }
   }
}

# Make sure that NoAutoUpdate value must be set to 0,
# if Azure Update Management feature related codes removed from DSC.
configuration AzureUpdateManagement
{
    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode  = "ApplyOnly"
        }

        Registry NoAutoUpdate
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "NoAutoUpdate"
            ValueType = "DWord"
            ValueData = "0"
        }

        Registry AUOptions
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "AUOptions"
            ValueType = "DWord"
            ValueData = "2"
        }

        Registry NoAutoRebootWithLoggedOnUsers
        {
            Ensure    = "Present"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "NoAutoRebootWithLoggedOnUsers"
            ValueType = "DWord"
            ValueData = "1"
        }

        Registry AutomaticMaintenanceEnabled
        {
            Ensure    = "Absent"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "AutomaticMaintenanceEnabled"
        }

        Registry ScheduledInstallFirstWeek
        {
            Ensure    = "Absent"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "ScheduledInstallFirstWeek"
        }

        Registry ScheduledInstallSecondWeek
        {
            Ensure    = "Absent"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "ScheduledInstallSecondWeek"
        }

        Registry ScheduledInstallThirdWeek
        {
            Ensure    = "Absent"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "ScheduledInstallThirdWeek"
        }

        Registry ScheduledInstallFourthWeek
        {
            Ensure    = "Absent"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "ScheduledInstallFourthWeek"
        }

        Registry AllowMUUpdateService
        {
            Ensure    = "Absent"
            Key       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName = "AllowMUUpdateService"
        }
    }
}

configuration WEF
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', "", Justification = 'False positive.')
    ]
    param
    (
        [Parameter(Mandatory)]
        [String]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [String]
        $DomainOU,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers
    )

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded  = $true
            ConfigurationMode   = "ApplyOnly"
        }

        DomainJoin DomainJoin
        {
            DomainName              = $DomainName
            AdminCreds              = $AdminCreds
            DomainOU                = $DomainOU
            LocalAdminGroupMembers  = $LocalAdminGroupMembers
        }

        AzureUpdateManagement UpdateManagement
        {}
    }
}

Configuration InstallProgram
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', "", Justification = 'False positive.')
    ]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $DisplayName,

        [Parameter(Mandatory)]
        [string]
        $InstallerPath,

        [Parameter(Mandatory)]
        [string]
        $Arguments
    )

    Node localhost
    {
        Script InstallCustomApplication
        {
            GetScript = {
                # Check if the application is already installed
                $paths = @(
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )

                $existing = Get-ItemProperty -Path $paths | Where-Object{
                    $_.DisplayName -like "*$using:DisplayName*"
                }

                if ($existing) {
                    Write-Verbose -Message "The application '$($using:DisplayName)' is already installed."
                    return $true
                }

                return $false
            }
            SetScript = {
                # Installing application
                Write-Verbose -Message "Installing application '$($using:DisplayName)'..."
                Start-Process -FilePath $using:installerPath -ArgumentList $using:Arguments -Wait
            }
            TestScript = {
                # Check if application is installed
                $paths = @(
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )

                $existing = Get-ItemProperty -Path $paths | Where-Object {
                    $_.DisplayName -like "*$using:DisplayName*"
                }

                if ($existing) {
                    Write-Verbose -Message "The application '$($using:DisplayName)' is installed."
                    return $true
                }

                Write-Verbose -Message "The application '$($using:DisplayName)' is not installed."
                return $false
            }
        }
    }
}

configuration WebAccess
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', "", Justification = 'False positive.')
    ]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [string]
        $DomainOU,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers
    )

    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 3.0.0.0
    Import-DscResource -ModuleName xComputerManagement -ModuleVersion 4.1.0.0
    Import-DscResource -ModuleName xNetworking -ModuleVersion 5.7.0.0

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded  = $true
            ConfigurationMode   = "ApplyOnly"
        }

        DomainJoin DomainJoin
        {
            DomainName              = $DomainName
            AdminCreds              = $AdminCreds
            DomainOU                = $DomainOU
            LocalAdminGroupMembers  = $LocalAdminGroupMembers
        }

        AzureUpdateManagement UpdateManagement
        {}

        xFirewall FirewallRuleForGWRDSH
        {
            Direction   = "Inbound"
            Name        = "Firewall-WA-RDSH-TCP-In"
            DisplayName = "Firewall-WA-RDSH-TCP-In"
            Description = ("Inbound rule for CB to allow TCP traffic for configuring WA and RDSH machines " +
                           "during deployment.")
            Group       = "Connection Broker"
            Enabled     = "True"
            Action      = "Allow"
            Protocol    = "TCP"
            LocalPort   = "5985"
            Ensure      = "Present"
        }

        WindowsFeature RDS-Web-Access
        {
            Ensure = "Present"
            Name   = "RDS-Web-Access"
        }

        WindowsFeature Hyper-V
        {
            Ensure               = "Present"
            Name                 = "Hyper-V"
            IncludeAllSubFeature = $true
        }

        WindowsFeature RSAT-Hyper-V-Tools
        {
            Ensure               = "Present"
            Name                 = "RSAT-Hyper-V-Tools"
            IncludeAllSubFeature = $true
        }
    }
}

configuration SetupHyperVHost
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '', Justification = 'False positive.')
    ]
    param(
        [Parameter()]
        [string]
        $SwitchName = 'NewInternal'
    )

    Import-DscResource -ModuleName xHyper-V -ModuleVersion 3.17.0.0

    xVMSwitch NewInternal
    {
        Name    = $SwitchName
        Type    = 'Internal'
        Ensure  = 'Present'
    }

    xVMHost VMHost
    {
        IsSingleInstance            = 'Yes'
        EnableEnhancedSessionMode   = $true
    }
}

configuration NestedVM
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '', Justification = 'False positive.')
    ]
    param(
        [Parameter(Mandatory)]
        [string]
        $VMName,

        [Parameter()]
        [string]
        $SwitchName = 'NewInternal',

        [Parameter(Mandatory)]
        [uint64]
        $StartupMemory,

        [Parameter(Mandatory)]
        [string]
        $UnattendUri,

        [Parameter(Mandatory)]
        [string]
        $WEFApplicationXMLURI,

        [Parameter(Mandatory)]
        [string]
        $WEFSecurityXMLURI,

        [Parameter(Mandatory)]
        [string]
        $WEFSystemXMLURI,

        [Parameter(Mandatory)]
        [PSCredential]
        $LocalAdminCredential,

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
        [String]
        $DomainOU,

        [Parameter(Mandatory)]
        [PSCredential]
        $DomainJoinCredential,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers,

        [Parameter(Mandatory)]
        [String]
        $FSLogixProfileShare,

        [Parameter(Mandatory)]
        [String]
        $FSLogixProfilePath,

        [AllowEmptyString()]
        [Parameter()]
        [string]
        $FileShareUNCPath,

        [Parameter(Mandatory)]
        [String]
        $WEFServer,

        [Parameter()]
        [int]
        $BootTimeoutSeconds = 900,

        [Parameter()]
        [hashtable]
        $HostSpecificScheduledTasks = @{}
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 9.1.0
    Import-DscResource -ModuleName xHyper-V -ModuleVersion 3.17.0.0
    Import-DscResource -ModuleName Ericsson_NestedVM -ModuleVersion 1.0
    Import-DscResource -ModuleName Ericsson_ComputerManagement -ModuleVersion 1.0

    $unattendDestinationPath = Join-Path -Path $env:SystemDrive -ChildPath 'CASPlus\Deployment\unattend.xml'

    $joinPathParams = @{
        Path        = $env:SystemDrive
        ChildPath   = 'CASPlus\Deployment\cas-event-collector-application.xml'
    }
    $wefApplicationXMLDestinationPath = Join-Path @joinPathParams

    $joinPathParams = @{
        Path        = $env:SystemDrive
        ChildPath   = 'CASPlus\Deployment\cas-event-collector-security.xml'
    }
    $wefSecurityXMLDestinationPath = Join-Path @joinPathParams

    $joinPathParams = @{
        Path        = $env:SystemDrive
        ChildPath   = 'CASPlus\Deployment\cas-event-collector-system.xml'
    }
    $wefSystemXMLDestinationPath = Join-Path @joinPathParams

    $vhdPath = 'C:\vhds\windows10.vhdx'

    $nestedComputerName = "$($env:COMPUTERNAME)N"

    # The NestedVMMemory value must be even.
    [uint64]$startupMemoryBytes = ($StartupMemory - ($StartupMemory % 2)) * 1MB

    $automaticStartAction = 'Nothing'
    $automaticStopAction = 'ShutDown'

    $interfaceIndex = Get-NetAdapter -InterfaceDescription 'Microsoft Hyper-V Network Adapter*' |
        Select-Object -First 1 -ExpandProperty ifIndex
    $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $interfaceIndex |
        Select-Object -ExpandProperty ServerAddresses

    $scheduledTaskEnabled = @{
        '\CASPlus\Show hostname on taskbar' = $true
        '\CASPlus\Always Show All Icons Notification Area' = $true
        '\CASPlus\Clean-TaskSchedulerTree' = $true
        '\CASPlus\ProfileCleanup' = $true
        '\CASPlus\Mount-FileShareAsDrive' = $true
        '\Microsoft\Windows\Management\Provisioning\Cellular' = $false
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' = $false
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator' = $false
        '\Microsoft\Windows\DiskFootprint\Diagnostics' = $false
        '\Microsoft\Windows\Shell\FamilySafetyMonitor' = $false
        '\Microsoft\Windows\Shell\FamilySafetyRefreshTask' = $false
        '\Microsoft\Windows\Maps\MapsToastTask' = $false
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' = $false
        '\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser' = $false
        '\Microsoft\Windows\Autochk\Proxy' = $false
        '\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic' = $false
        '\Microsoft\Windows\Server Manager\ServerManager' = $false
        '\Microsoft\Windows\Speech\SpeechModelDownloadTask' = $false
        '\Microsoft\XblGameSave\XblGameSaveTask' = $false
        '\Microsoft\Windows\Location\WindowsActionDialog' = $false
        '\Microsoft\Windows\PI\Sqm-Tasks' = $false
    }

    $scheduledTaskEnabled += $HostSpecificScheduledTasks

    $loggerConfigNames = @(
        'Cellcore'
        'CloudExperienceHostOOBE'
        'DiagLog'
        'RadioMgr'
        'ReadyBoot'
        'WDIContextLog'
        'WiFiDriverIHVSession'
        'WiFiSession'
        'WinPhoneCritical'
    )

    Node localhost {
        xRemoteFile UnattendXML
        {
            Uri             = $UnattendUri
            DestinationPath = $unattendDestinationPath
        }

        xRemoteFile WEFApplicationXML
        {
            Uri             = $WEFApplicationXMLURI
            DestinationPath = $wefApplicationXMLDestinationPath
        }

        xRemoteFile WEFSecurityXML
        {
            Uri             = $WEFSecurityXMLURI
            DestinationPath = $wefSecurityXMLDestinationPath
        }

        xRemoteFile WEFSystemXML
        {
            Uri             = $WEFSystemXMLURI
            DestinationPath = $wefSystemXMLDestinationPath
        }

        DeployUnattendXML DeployUnattendXML
        {
            VMName                  = $VMName
            UnattendDestinationPath = $unattendDestinationPath
            VHDPath                 = $vhdPath
            NestedComputerName      = $nestedComputerName
            LocalAdminCredential    = $LocalAdminCredential
            DependsOn               = '[xRemoteFile]UnattendXML'
        }

        xVMHyperV NestedVM
        {
            Name                = $VMName
            VhdPath             = $vhdPath
            SwitchName          = $SwitchName
            Generation          = 1
            StartupMemory       = $startupMemoryBytes
            ProcessorCount      = $env:NUMBER_OF_PROCESSORS
            EnableGuestService  = $true
            Ensure              = 'Present'
        }

        VMSettings NestedVMSettings
        {
            VMName                  = $VMName
            AutomaticStartAction    = $automaticStartAction
            AutomaticStopAction     = $automaticStopAction
            DependsOn               = '[xVMHyperV]NestedVM'
        }

        InvokeScheduledTask StartVM
        {
            TaskName    = 'Start-NestedVM'
            TaskPath    = '\CASPlus'
            DependsOn   = '[VMSettings]NestedVMSettings'
        }

        VMWaitForWinRM FirstBoot
        {
            Name                    = 'FirstBoot'
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            TimeoutSeconds          = $BootTimeoutSeconds
            DependsOn               = '[InvokeScheduledTask]StartVM'
        }

        VMNetworkSetup VMNetworkSetup
        {
            VMName                  = $VMName
            IP                      = $IP
            SubnetMask              = $SubnetMask
            DefaultGateway          = $DefaultGateway
            DomainDNSName           = $DomainDNSName
            DNSServers              = $dnsServers
            LocalAdminCredential    = $LocalAdminCredential
            DependsOn               = '[VMWaitForWinRM]FirstBoot'
        }

        # CVE-2013-3900
        VMRegistry EnableCertPaddingCheck
        {
            VMName                  = $VMName
            LocalAdminCredential    = $NestedAdminCreds
            Key                     = 'HKLM:\Software\Microsoft\Cryptography\Wintrust\Config'
            PropertyName            = 'EnableCertPaddingCheck'
            PropertyType            = 'String'
            PropertyValue           = '1'
            DependsOn               = '[VMNetworkSetup]VMNetworkSetup'
        }

        # CVE-2013-3900
        VMRegistry EnableCertPaddingCheckx86
        {
            VMName                  = $VMName
            LocalAdminCredential    = $NestedAdminCreds
            Key                     = 'HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'
            PropertyName            = 'EnableCertPaddingCheck'
            PropertyType            = 'String'
            PropertyValue           = '1'
            DependsOn               = '[VMNetworkSetup]VMNetworkSetup'
        }

        VMRemoveUnattendXml VMRemoveUnattendXml
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            DependsOn               = '[VMNetworkSetup]VMNetworkSetup'
        }

        VMPagefile VMPagefile
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            DependsOn               = '[VMRemoveUnattendXml]VMRemoveUnattendXml'
        }

        VMDomainJoin VMDomainJoin
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            DomainDNSName           = $DomainDNSName
            DomainOU                = $DomainOU
            DomainJoinCredential    = $DomainJoinCredential
            DependsOn               = '[VMPagefile]VMPagefile'
        }

        VMWaitForWinRM DomainJoinBoot
        {
            Name                    = 'DomainJoinBoot'
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            TimeoutSeconds          = $BootTimeoutSeconds
            DependsOn               = '[VMDomainJoin]VMDomainJoin'
        }

        VMLocalUser casadmin
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            Name                    = 'casadmin'
            Enabled                 = $false
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMLocalUser packer
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            Name                    = 'packer'
            Enabled                 = $false
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMLocalUser administrator
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            Name                    = ($LocalAdminCredential.UserName -split '\\' | Select-Object -Last 1)
            Enabled                 = $true
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMLocalGroupMember fslogixProfileExclude
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            MemberName              = $LocalAdminCredential.UserName
            GroupName               = 'FSLogix Profile Exclude List'
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        foreach ($member in $LocalAdminGroupMembers) {
            VMLocalGroupMember $("adminGroup"+$member)
            {
                VMName                  = $VMName
                LocalAdminCredential    = $LocalAdminCredential
                MemberName              = $member
                GroupName               = 'Administrators'
                DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
            }
        }

        VMLocalGroupMember remoteDesktopUsers
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            MemberName              = 'ERICSSON\Domain Users'
            GroupName               = 'Remote Desktop Users'
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMLocalGroupMember hyperVAdministrators
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            MemberName              = 'ERICSSON\Domain Users'
            GroupName               = 'Hyper-V Administrators'
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMLocalGroupMember eventLogReadersNetworkService
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            MemberName              = 'NT AUTHORITY\NETWORK SERVICE'
            GroupName               = 'Event Log Readers'
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMLocalGroupMember eventLogReadersDomainComputers
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            MemberName              = 'Ericsson\Domain Computers'
            GroupName               = 'Event Log Readers'
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMFSLogix VMFSLogix
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            FSLogixProfileShare     = $FSLogixProfileShare
            FSLogixProfilePath      = $FSLogixProfilePath
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMMountFileShareAsDriveScheduledTask VMMountFileShareAsDriveScheduledTask
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            FileShareUNCPath        = $FileShareUNCPath
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        foreach ($scheduledTask in $scheduledTaskEnabled.GetEnumerator()) {
            VMScheduledTasksState $scheduledTask.Name.Trim('\')
            {
                VMName                  = $VMName
                LocalAdminCredential    = $LocalAdminCredential
                TaskName                = (Split-Path -Path $scheduledTask.Name -Leaf)
                TaskPath                = (Split-Path -Path $scheduledTask.Name -Parent)
                Enabled                 = $scheduledTask.Value
                DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
            }
        }

        foreach ($logger in $loggerConfigNames) {
            VMAutoLoggerConfig $logger
            {
                VMName                  = $VMName
                LocalAdminCredential    = $LocalAdminCredential
                LoggerName              = $logger
                DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
            }
        }

        VMFile WEFApplicationXML
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            SourcePath              = $wefApplicationXMLDestinationPath
            DestinationPath         = $wefApplicationXMLDestinationPath
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMFile WEFSecurityXML
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            SourcePath              = $wefSecurityXMLDestinationPath
            DestinationPath         = $wefSecurityXMLDestinationPath
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMFile WEFSystemXML
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            SourcePath              = $wefSystemXMLDestinationPath
            DestinationPath         = $wefSystemXMLDestinationPath
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMLogRelay LogRelay
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            WEFServer               = $WEFServer
        }

        VMConfigureWindowsDefender VMConfigureWindowsDefender
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMInvokeScheduledTask UpdateDefenderSignature
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            TaskName                = 'Update-Defender'
            TaskPath                = '\CASPlus\'
            Wait                    = $true
            SkipIfDisabled          = $true
            DependsOn               = '[VMConfigureWindowsDefender]VMConfigureWindowsDefender'
        }

        VMInvokeScheduledTask CleanTaskSchedulerTree
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            TaskName                = 'Clean-TaskSchedulerTree'
            TaskPath                = '\CASPlus\'
            Wait                    = $true
            SkipIfDisabled          = $false
            DependsOn               = '[VMScheduledTasksState]CASPlus\Clean-TaskSchedulerTree'
        }

        Registry NestedVMMemoryBytes
        {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\CASPlus'
            ValueName   = 'NestedVMMemoryBytes'
            ValueType   = 'QWord'
            ValueData   = $startupMemoryBytes
        }

        Registry NestedVMName
        {
            Ensure      = 'Present'
            Key         = 'HKLM:\SOFTWARE\CASPlus'
            ValueName   = 'NestedVMName'
            ValueType   = 'String'
            ValueData   = $VMName
        }

        VMAppLocker AppLocker
        {
            VMName                  = $VMName
            LocalAdminCredential    = $LocalAdminCredential
            RuleFiles               = @('C:\CASPlus\AppLocker\AppLockerRules.xml')
            DependsOn               = '[VMWaitForWinRM]DomainJoinBoot'
        }

        VMRegistry NoAutoUpdate
        {
            VMName                  = $VMName
            LocalAdminCredential    = $NestedAdminCreds
            Key                     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            PropertyName            = 'NoAutoUpdate'
            PropertyType            = 'DWord'
            PropertyValue           = 0
            DependsOn               = '[VMAppLocker]AppLocker'
        }

        VMRegistry AUOptions
        {
            VMName                  = $VMName
            LocalAdminCredential    = $NestedAdminCreds
            Key                     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            PropertyName            = 'AUOptions'
            PropertyType            = 'DWord'
            PropertyValue           = 4
            DependsOn               = '[VMAppLocker]AppLocker'
        }
    }
}

configuration SessionHost
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '', Justification = 'False positive.')
    ]
    param
    (
        [Parameter()]
        [string]
        $VMName = 'NestedVMForConnection',

        [Parameter(Mandatory)]
        [string]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [PSCredential]
        $NestedAdminCreds,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers,

        [Parameter(Mandatory)]
        [String]
        $DomainOU,

        [Parameter()]
        [string]
        $SwitchName = 'NewInternal',

        [Parameter()]
        [bool]
        $UpdateNow = $true,

        [Parameter(Mandatory)]
        [uint64]
        $StartupMemory,

        [Parameter(Mandatory)]
        [string]
        $UnattendUri,

        [Parameter(Mandatory)]
        [string]
        $WEFApplicationXMLURI,

        [Parameter(Mandatory)]
        [string]
        $WEFSecurityXMLURI,

        [Parameter(Mandatory)]
        [string]
        $WEFSystemXMLURI,

        [Parameter()]
        [string]
        $VmIP = '192.168.42.5',

        [Parameter()]
        [string]
        $VmSubnet = '192.168.42.0/24',

        [Parameter()]
        [String]
        $FSLogixProfilePath = 'C:\FSLogixProfiles',

        [Parameter(Mandatory)]
        [string]
        $FSLogixProfileShare,

        [AllowEmptyString()]
        [Parameter()]
        [string]
        $FileShareUNCPath,

        [Parameter(Mandatory)]
        [String]
        $WEFServer,

        [Parameter()]
        [int]
        $VmBootTimeoutSeconds = 900
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 9.1.0
    Import-DscResource -ModuleName xWindowsUpdate -ModuleVersion 2.8.0.0
    Import-DscResource -ModuleName xNetworking -ModuleVersion 5.7.0.0
    Import-DscResource -ModuleName Ericsson_ComputerManagement -ModuleVersion 1.0

    $vmSubnetAddress, $vmSubnetMask = $VmSubnet -split '/'

    $vmSubnetIPNumber   = [ipaddress]$vmSubnetAddress | Select-Object -ExpandProperty Address
    $firstHostIPNumber  = [ipaddress]'0.0.0.1' | Select-Object -ExpandProperty Address

    # Calculate the default gateway of the subnet by adding 0.0.0.1 to the subnet address.
    $vmSubnetDefaultGatewayIPNumber = $vmSubnetIPNumber + $firstHostIPNumber

    $vmDefaultGateway = [ipaddress]$vmSubnetDefaultGatewayIPNumber |
        Select-Object -ExpandProperty IPAddressToString

    $hostSpecificScheduledTasks = @{
        '\CASPlus\Restart-SHNestedVM' = $true
    }

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded  = $true
            ConfigurationMode   = 'ApplyOnly'
        }

        xWindowsUpdateAgent WindowsUpdate
        {
            IsSingleInstance    = 'yes'
            UpdateNow           = $UpdateNow
            Source              = 'WindowsUpdate'
            Category            = 'Important', 'Security', 'Optional'
        }

        Registry WindowsUpdateNoAutoUpdate
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName   = "NoAutoUpdate"
            ValueType   = "Dword"
            ValueData   = "0"
            DependsOn   = '[xWindowsUpdateAgent]WindowsUpdate'
        }

        WindowsFeature RDS-RD-Server
        {
            Ensure      = 'Present'
            Name        = 'RDS-RD-Server'
            DependsOn   = '[xWindowsUpdateAgent]WindowsUpdate'
        }

        DomainJoin DomainJoin
        {
            DomainName              = $DomainName
            AdminCreds              = $AdminCreds
            DomainOU                = $DomainOU
            LocalAdminGroupMembers  = $LocalAdminGroupMembers
            DependsOn               = '[WindowsFeature]RDS-RD-Server'
        }

        xGroup AddUsersToHyperVGroup
        {
            GroupName           = 'Hyper-V Administrators'
            MembersToInclude    = 'ERICSSON\Domain Users'
            DependsOn           = '[DomainJoin]DomainJoin'
        }

        xFirewall FirewallRuleForMonitoring_ICMP
        {
            Name    = 'FPS-ICMP4-ERQ-In'
            Enabled = 'True'
            Ensure  = 'Present'
        }
        SetupHyperVHost SetupHyperVHost
        {
            SwitchName  = $SwitchName
            DependsOn   = '[DomainJoin]DomainJoin'
        }

        NetIPAddress NetIPAddress
        {
            IpAddress       = $vmDefaultGateway
            PrefixLength    = $vmSubnetMask
            InterfaceAlias  = 'vEthernet ({0})' -f $SwitchName
            DependsOn       = '[SetupHyperVHost]SetupHyperVHost'
        }

        NetNat NetNat
        {
            NetNatName                          = 'CASNATnetwork'
            InternalIPInterfaceAddressPrefix    = $VmSubnet
            DependsOn                           = '[NetIPAddress]NetIPAddress'
        }

        NestedVM Nested
        {
            VMName                      = $VMName
            StartupMemory               = $StartupMemory
            UnattendUri                 = $UnattendUri
            WEFApplicationXMLURI        = $WEFApplicationXMLURI
            WEFSecurityXMLURI           = $WEFSecurityXMLURI
            WEFSystemXMLURI             = $WEFSystemXMLURI
            LocalAdminCredential        = $NestedAdminCreds
            IP                          = $vmIP
            SubnetMask                  = $vmSubnetMask
            DefaultGateway              = $vmDefaultGateway
            DomainDNSName               = $DomainName
            DomainJoinCredential        = $AdminCreds
            LocalAdminGroupMembers      = $LocalAdminGroupMembers
            DomainOU                    = $DomainOU
            FSLogixProfileShare         = $FSLogixProfileShare
            FSLogixProfilePath          = $FSLogixProfilePath
            FileShareUNCPath            = $FileShareUNCPath
            WEFServer                   = $WEFServer
            BootTimeoutSeconds          = $VmBootTimeoutSeconds
            HostSpecificScheduledTasks  = $hostSpecificScheduledTasks
            DependsOn                   = '[NetNat]NetNat'
        }
    }
}

configuration VirtualizationHost
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '', Justification = 'False positive.')
    ]
    param
    (
        [Parameter()]
        [string]
        $VMName = "Nested$($env:COMPUTERNAME)",

        [Parameter(Mandatory)]
        [string]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [PSCredential]
        $NestedAdminCreds,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers,

        [Parameter(Mandatory)]
        [String]
        $DomainOU,

        [Parameter()]
        [string]
        $SwitchName = 'NewInternal',

        [Parameter()]
        [bool]
        $UpdateNow = $true,

        [Parameter(Mandatory)]
        [uint64]
        $StartupMemory,

        [Parameter(Mandatory)]
        [string]
        $UnattendUri,

        [Parameter(Mandatory)]
        [string]
        $WEFApplicationXMLURI,

        [Parameter(Mandatory)]
        [string]
        $WEFSecurityXMLURI,

        [Parameter(Mandatory)]
        [string]
        $WEFSystemXMLURI,

        [Parameter(Mandatory)]
        [string]
        $VmIP,

        [Parameter(Mandatory)]
        [string]
        $VmSubnet,

        [Parameter(Mandatory)]
        [int]
        $NATNestedVMRDPOnHostPort,

        [Parameter()]
        [String]
        $FSLogixProfilePath = 'C:\FSLogixProfiles',

        [Parameter(Mandatory)]
        [string]
        $FSLogixProfileShare,

        [AllowEmptyString()]
        [Parameter()]
        [string]
        $FileShareUNCPath,

        [Parameter(Mandatory)]
        [String]
        $WEFServer,

        [Parameter(Mandatory)]
        [int]
        $ActiveSessionLimitHours,

        [Parameter(Mandatory)]
        [int]
        $IdleSessionLimitHours,

        [Parameter(Mandatory)]
        [int]
        $DisconnectedSessionLimitHours,

        [Parameter()]
        [int]
        $VmBootTimeoutSeconds = 900
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 9.1.0
    Import-DscResource -ModuleName xWindowsUpdate -ModuleVersion 2.8.0.0
    Import-DscResource -ModuleName Ericsson_ComputerManagement -ModuleVersion 1.0
    Import-DscResource -ModuleName Ericsson_NestedVM -ModuleVersion 1.0

    $vmSubnetAddress, $vmSubnetMask = $VmSubnet -split '/'

    $vmSubnetIPNumber = [ipaddress]$vmSubnetAddress | Select-Object -ExpandProperty Address
    $firstHostIPNumber = [ipaddress]'0.0.0.1' | Select-Object -ExpandProperty Address

    # Calculate the default gateway of the subnet by adding 0.0.0.1 to the subnet address.
    $vmSubnetDefaultGatewayIPNumber = $vmSubnetIPNumber + $firstHostIPNumber

    $vmDefaultGateway = [ipaddress]$vmSubnetDefaultGatewayIPNumber |
        Select-Object -ExpandProperty IPAddressToString

    $activeSessionLimitMiliseconds = $ActiveSessionLimitHours * 3600000
    $disconnectedSessionLimitMiliseconds = $DisconnectedSessionLimitHours * 3600000
    $idleSessionLimitMiliseconds = $IdleSessionLimitHours * 3600000

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded  = $true
            ConfigurationMode   = 'ApplyOnly'
        }

        xWindowsUpdateAgent WindowsUpdate
        {
            IsSingleInstance    = 'yes'
            UpdateNow           = $UpdateNow
            Source              = 'WindowsUpdate'
            Category            = 'Important', 'Security', 'Optional'
        }

        Registry WindowsUpdateNoAutoUpdate
        {
            Ensure      = "Present"
            Key         = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
            ValueName   = "NoAutoUpdate"
            ValueType   = "Dword"
            ValueData   = "0"
            DependsOn   = '[xWindowsUpdateAgent]WindowsUpdate'
        }

        WindowsFeature RDS-Virtualization
        {
            Ensure      = 'Present'
            Name        = 'RDS-Virtualization'
            DependsOn   = '[xWindowsUpdateAgent]WindowsUpdate'
        }

        DomainJoin DomainJoin
        {
            DomainName              = $DomainName
            AdminCreds              = $AdminCreds
            DomainOU                = $DomainOU
            LocalAdminGroupMembers  = $LocalAdminGroupMembers
            DependsOn               = '[WindowsFeature]RDS-Virtualization'
        }

        xGroup AddUsersToHyperVGroup
        {
            GroupName           = 'Hyper-V Administrators'
            MembersToInclude    = 'ERICSSON\Domain Users'
            DependsOn           = '[DomainJoin]DomainJoin'
        }

        Registry MaxInstanceCount
        {
            Ensure      = 'Present'
            Key         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            ValueName   = 'MaxInstanceCount'
            ValueType   = 'DWord'
            ValueData   = '1'
        }

        SetupHyperVHost SetupHyperVHost
        {
            SwitchName  = $SwitchName
            DependsOn   = '[DomainJoin]DomainJoin'
        }

        NetIPAddress NetIPAddress
        {
            IpAddress       = $vmDefaultGateway
            PrefixLength    = $VmSubnetMask
            InterfaceAlias  = 'vEthernet ({0})' -f $SwitchName
            DependsOn       = '[SetupHyperVHost]SetupHyperVHost'
        }

        NetNat NetNat
        {
            NetNatName                          = 'CASNATnetwork'
            InternalIPInterfaceAddressPrefix    = $VmSubnet
            DependsOn                           = '[NetIPAddress]NetIPAddress'
        }

        NetNatStaticMapping MSTSC
        {
            NetNatName          = 'CASNATnetwork'
            ExternalIPAddress   = '0.0.0.0/24'
            ExternalPort        = $NATNestedVMRDPOnHostPort
            Protocol            = 'TCP'
            InternalIPAddress   = $VmIP
            InternalPort        = 3389
            DependsOn           = '[NetNat]NetNat'
        }

        NestedVM Nested
        {
            VMName                  = $VMName
            StartupMemory           = $StartupMemory
            UnattendUri             = $UnattendUri
            WEFApplicationXMLURI    = $WEFApplicationXMLURI
            WEFSecurityXMLURI       = $WEFSecurityXMLURI
            WEFSystemXMLURI         = $WEFSystemXMLURI
            LocalAdminCredential    = $NestedAdminCreds
            IP                      = $VmIP
            SubnetMask              = $VmSubnetMask
            DefaultGateway          = $vmDefaultGateway
            DomainDNSName           = $DomainName
            DomainJoinCredential    = $AdminCreds
            LocalAdminGroupMembers  = $LocalAdminGroupMembers
            DomainOU                = $DomainOU
            FSLogixProfileShare     = $FSLogixProfileShare
            FSLogixProfilePath      = $FSLogixProfilePath
            FileShareUNCPath        = $FileShareUNCPath
            WEFServer               = $WEFServer
            BootTimeoutSeconds      = $VmBootTimeoutSeconds
            DependsOn               = '[NetNat]NetNat'
        }

        VMRegistry MaxIdleTime
        {
            VMName                  = $VMName
            LocalAdminCredential    = $NestedAdminCreds
            Key                     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            PropertyName            = 'MaxIdleTime'
            PropertyType            = 'DWord'
            PropertyValue           = $idleSessionLimitMiliseconds
            DependsOn               = '[NestedVM]Nested'
        }

        VMRegistry MaxConnectionTime
        {
            VMName                  = $VMName
            LocalAdminCredential    = $NestedAdminCreds
            Key                     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            PropertyName            = 'MaxConnectionTime'
            PropertyType            = 'DWord'
            PropertyValue           = $activeSessionLimitMiliseconds
            DependsOn               = '[NestedVM]Nested'
        }

        VMRegistry MaxDisconnectionTime
        {
            VMName                  = $VMName
            LocalAdminCredential    = $NestedAdminCreds
            Key                     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            PropertyName            = 'MaxDisconnectionTime'
            PropertyType            = 'DWord'
            PropertyValue           = $disconnectedSessionLimitMiliseconds
            DependsOn               = '[NestedVM]Nested'
        }
    }
}

configuration RDSDeployment
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword', '',
        Justification='The password will be encrypted with a cert that Azure provides.')
    ]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '', Justification = 'False positive.')
    ]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [PSCredential]
        $DeployCreds,

        [Parameter(Mandatory)]
        [string]
        $DomainOU,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers,

        [Parameter(Mandatory)]
        [string]
        $ConnectionBroker,

        [Parameter(Mandatory)]
        [String[]]
        $WebAccessServers,

        [Parameter(Mandatory)]
        [String[]]
        $LicenseServers,

        [Parameter(Mandatory)]
        [string]
        $HAConnectionBrokerName,

        [Parameter(Mandatory)]
        [string]
        $sqlServer,

        [Parameter(Mandatory)]
        [string]
        $sqlDatabase,

        [Parameter(Mandatory)]
        [string]
        $sqlAdmin,

        [Parameter(Mandatory)]
        [string]
        $sqlPassword,

        [Parameter(Mandatory)]
        [string]
        $connectionBrokerClusterDNS,

        [Parameter(Mandatory)]
        [string]
        $uriVCRedist,

        [Parameter(Mandatory)]
        [string]
        $uriODBCdriver,

        [Parameter(Mandatory)]
        [string]
        $sqlServerPublicFQDN,

        [Parameter(Mandatory)]
        [string]
        $sqlServerPrivateIP,

        [Parameter()]
        $sessionCollections,

        [Parameter()]
        $virtualizationCollections
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 9.1.0
    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 3.0.0.0
    Import-DscResource -ModuleName xComputerManagement -ModuleVersion 4.1.0.0
    Import-DscResource -ModuleName Ericsson_xRemoteDesktopSessionHost -ModuleVersion 1.0.1.0
    Import-DscResource -ModuleName Ericsson_RemoteDesktopVirtualizationHost -ModuleVersion 0.0.1
    Import-DscResource -ModuleName Ericsson_RemoteDesktopHA -ModuleVersion 0.0.1
    Import-DscResource -ModuleName xNetworking -ModuleVersion 5.7.0.0

    $licenseServersFQDN = @( $LicenseServers | ForEach-Object {"$_.$DomainName"})
    $webAccessServersFQDN = @( $WebAccessServers | ForEach-Object {"$_.$DomainName"})

    #region Flexible options
    $sessionCollectionNames = $sessionCollections.Keys
    $virtualizationCollectionNames = $virtualizationCollections.Keys
    $sessionHosts = @()
    $virtualizationHosts = @()

    foreach($collection in $sessionCollectionNames) {
            $sessionHosts += $sessionCollections.$collection.VMs
    }

    foreach($collection in $virtualizationCollectionNames) {
            $virtualizationHosts += $virtualizationCollections.$collection.VMs
    }
    #endregion

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded             = $true
            ConfigurationMode              = "ApplyOnly"
            ConfigurationModeFrequencyMins = 1200
        }

        # This is for preventing Symantec Endpoint Protection to update itself,
        # which causes reboot pending and ODBC/VCredist fail to install.
        xFirewall FirewallRuleForSEP
        {
            Direction   = "Outbound"
            Name        = "Firewall-CB-Symantec-Out"
            DisplayName = "Firewall-CB-Symantec-Out"
            Description = ("Outbound rule for CB to prevent Symantec Endpoint Protection to update itself, " +
                           "which causes pending reboot and fails install of ODBC/VCredist")
            Group       = "Symantec Endpoint Protection"
            Enabled     = "True"
            Action      = "Block"
            Program     = "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\SepLiveUpdate.exe"
            Ensure      = "Present"
        }

        # Copy Visual C++ Redistributable to machine
        xRemoteFile VCRedist
        {
            DestinationPath = "C:\Packages\vcredist17.exe"
            Uri             = $uriVCRedist
        }

        # Copy ODBC Driver to machine
        xRemoteFile ODBCDriver
        {
            DestinationPath = "C:\Packages\msodbcsql18.msi"
            Uri             = $uriODBCdriver
        }

        # Install Visual C++ Redistributable
        InstallProgram VCRedist
        {
            DisplayName   = "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
            InstallerPath = "C:\Packages\vcredist17.exe"
            Arguments     = "/quiet /norestart"
            DependsOn     = "[xRemoteFile]VCRedist"
        }

        # Install ODBC Driver
        InstallProgram ODBCDriver
        {
            DisplayName   = "Microsoft ODBC Driver 18 for SQL Server"
            InstallerPath = "C:\Packages\msodbcsql18.msi"
            Arguments     = "/quiet /norestart IACCEPTMSODBCSQLLICENSETERMS=YES"
            DependsOn     = "[xRemoteFile]ODBCDriver"
        }

        xHostsFile PaasSQL
        {
            HostName  = $sqlServerPublicFQDN
            IPAddress = $sqlServerPrivateIP
            Ensure    = "Present"
        }

        AzureUpdateManagement UpdateManagement
        {}

        DomainJoin DomainJoin
        {
            DomainName             = $DomainName
            AdminCreds             = $AdminCreds
            DomainOU               = $DomainOU
            LocalAdminGroupMembers = $LocalAdminGroupMembers
        }

        WindowsFeature RDS-Connection-Broker
        {
            Ensure    = "Present"
            Name      = "RDS-Connection-Broker"
            DependsOn = "[DomainJoin]DomainJoin"
        }

        # Since May 2024 the IIS installation files are not copied to C:\Windows\System32\inetsrv directory
        # when installing some IIS subfeatures. This causes the RSAT-RDS-Tools feature to fail to install
        # with error code 0x800f0922.
        # As a workaround we install Web-Mgmt-Tools first which copies the required file to the inetsrv folder.
        WindowsFeature Web-Mgmt-Tools
        {
            Ensure    = "Present"
            Name      = "Web-Mgmt-Tools"
            DependsOn = "[WindowsFeature]RDS-Connection-Broker"
        }

        WindowsFeature RSAT-RDS-Tools
        {
            Ensure               = "Present"
            Name                 = "RSAT-RDS-Tools"
            IncludeAllSubFeature = $true
            DependsOn            = "[WindowsFeature]Web-Mgmt-Tools"
        }

        # The Web-Mgmt-Tools only installs the Web-Mgmt-Console. We can remove this after RSAT-RDS-Tools is
        # installed. We remove it after installing RSAT-RDS-Tools otherwise the required installation files
        # would be removed as well.
        WindowsFeature Web-Mgmt-Console
        {
            Ensure    = "Absent"
            Name      = "Web-Mgmt-Console"
            DependsOn = "[WindowsFeature]RSAT-RDS-Tools"
        }

        # Wait for the AD logon server to be reachable (workaround to avoid Device not attached error)

        Service RDMSStart
        {
            Name      = "RDMS"
            State     = "Running"
            DependsOn = "[DomainJoin]DomainJoin"
        }

        if($sessionCollections.Keys.Count -gt 0) {
            xRDSessionDeployment RDSDeployment
            {
                DependsOn               = "[Service]RDMSStart"
                ConnectionBroker        = $ConnectionBroker
                WebAccessServer         = $webAccessServersFQDN[0]
                SessionHosts            = $sessionHosts
                PsDscRunAsCredential    = $DeployCreds
            }

            foreach($shCollectionName in $sessionCollectionNames) {
                xRDSessionCollection $("RDSCollection"+$shCollectionName)
                {
                    DependsOn               = "[xRDSessionDeployment]RDSDeployment"
                    ConnectionBroker        = $ConnectionBroker
                    CollectionName          = $sessionCollections.$shCollectionName.Name
                    CollectionDescription   = $sessionCollections.$shCollectionName.Description
                    SessionHosts            = $sessionCollections.$shCollectionName.VMs
                    PsDscRunAsCredential    = $DeployCreds
                }

                xRDSessionCollectionConfiguration $("ConfigureCollection"+$shCollectionName)
                {
                    DependsOn                       = $("[xRDSessionCollection]RDSCollection"+$shCollectionName)
                    CollectionName                  = $sessionCollections.$shCollectionName.Name
                    MaxRedirectedMonitors           = $sessionCollections.$shCollectionName.MaxRedirectedMonitors
                    AuthenticateUsingNLA            = $sessionCollections.$shCollectionName.AuthenticateUsingNLA
                    SecurityLayer                   = $sessionCollections.$shCollectionName.SecurityLayer
                    UserGroup                       = $sessionCollections.$shCollectionName.Group
                    ClientPrinterAsDefault          = $sessionCollections.$shCollectionName.ClientPrinterAsDefault
                    ClientPrinterRedirected         = $sessionCollections.$shCollectionName.ClientPrinterRedirected
                    ActiveSessionLimitMin           = (
                        $sessionCollections.$shCollectionName.ActiveSessionLimitHour * 60)
                    DisconnectedSessionLimitMin     = (
                        $sessionCollections.$shCollectionName.DisconnectedSessionLimitHour * 60)
                    IdleSessionLimitMin             = (
                        $sessionCollections.$shCollectionName.IdleSessionLimitHour * 60)
                    ClientDeviceRedirectionOptions  = (
                        $sessionCollections.$shCollectionName.ClientDeviceRedirectionOptions)
                    PsDscRunAsCredential            = $DeployCreds
                }
            }
        }

        if($virtualizationCollections.Keys.Count -gt 0) {
            RDVirtualizationDeployment VHCDeployment
            {
                DependsOn            = "[Service]RDMSStart"
                ConnectionBroker     = $ConnectionBroker
                WebAccessServer      = $webAccessServersFQDN[0]
                VirtualizationHosts  = $virtualizationHosts
                PsDscRunAsCredential = $DeployCreds
            }

            foreach($vhCollectionName in $virtualizationCollectionNames) {
                RDVirtualizationCollection $("VHCollection" + $vhCollectionName)
                {
                    DependsOn            = "[RDVirtualizationDeployment]VHCDeployment"
                    CollectionName       = $vhCollectionName
                    ConnectionBroker     = $ConnectionBroker
                    VirtualizationHosts  = $virtualizationCollections.$vhCollectionName.VMs
                    DomainName           = $DomainName
                    UserGroups           = $virtualizationCollections.$vhCollectionName.DomainGroup
                    PsDscRunAsCredential = $DeployCreds
                }
            }
        }

        foreach ($lserver in $licenseServersFQDN) {
            xRDServer $("AddServer" + $lserver.replace($DomainName,""))
            {
                DependsOn            = "[Service]RDMSStart"
                Role                 = "RDS-Licensing"
                Server               = $lserver
                ConnectionBroker     = $ConnectionBroker
                PsDscRunAsCredential = $DeployCreds
            }
        }

        foreach ($wserver in $webAccessServersFQDN) {
            xRDServer $("AddServer" + $wserver.replace($DomainName,""))
            {
                DependsOn            = "[Service]RDMSStart"
                Role                 = "RDS-WEB-ACCESS"
                Server               = $wserver
                ConnectionBroker     = $ConnectionBroker
                PsDscRunAsCredential = $DeployCreds
            }
        }

        xRDLicenseConfiguration SetLicensing
        {
            DependsOn            = "[Service]RDMSStart"
            ConnectionBroker     = $ConnectionBroker
            LicenseMode          = "PerUser"
            LicenseServers       = $licenseServersFQDN
            PsDscRunAsCredential = $DeployCreds
        }

        RDHASetup SetupHA
        {
            DependsOn            = "[Service]RDMSStart"
            ConnectionBroker     = $ConnectionBroker
            sqlServer            = $sqlServer
            ClientAccessName     = $connectionBrokerClusterDNS
            sqlDatabase          = $sqlDatabase
            sqlAdmin             = $sqlAdmin
            sqlPassword          = $sqlPassword
            PsDscRunAsCredential = $DeployCreds
        }

        xRDServer AddSecondCB
        {
            Role                 = "RDS-CONNECTION-BROKER"
            Server               = $HAConnectionBrokerName
            ConnectionBroker     = $ConnectionBroker
            DependsOn            = "[RDHASetup]SetupHA"
            PsDscRunAsCredential = $DeployCreds
        }

    }
}

configuration EmptyConnectionBroker
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        "PSAvoidUsingPlainTextForPassword", "", Justification="It is not a password")
    ]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', "", Justification = 'False positive.')
    ]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [PSCredential]
        $DeployCreds,

        [Parameter(Mandatory)]
        [string]
        $DomainOU,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers,

        [Parameter(Mandatory)]
        [string]
        $uriVCRedist,

        [Parameter(Mandatory)]
        [string]
        $uriODBCdriver,

        [Parameter(Mandatory)]
        [string]
        $sqlServerPublicFQDN,

        [Parameter(Mandatory)]
        [string]
        $sqlServerPrivateIP
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 9.1.0
    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 3.0.0.0
    Import-DscResource -ModuleName xComputerManagement -ModuleVersion 4.1.0.0
    Import-DscResource -ModuleName Ericsson_xRemoteDesktopSessionHost -ModuleVersion 1.0.1.0
    Import-DscResource -ModuleName xNetworking -ModuleVersion 5.7.0.0

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded             = $true
            ConfigurationMode              = "ApplyOnly"
            ConfigurationModeFrequencyMins = 1200
        }

        # This is for preventing Symantec Endpoint Protection to update itself,
        # which causes reboot pending and ODBC/VCredist fail to install.
        xFirewall FirewallRuleForSEP
        {
            Direction   = "Outbound"
            Name        = "Firewall-CB-Symantec-Out"
            DisplayName = "Firewall-CB-Symantec-Out"
            Description = ("Outbound rule for CB to prevent Symantec Endpoint Protection to update itself, " +
                           "which causes pending reboot and fails install of ODBC/VCredist")
            Group       = "Symantec Endpoint Protection"
            Enabled     = "True"
            Action      = "Block"
            Program     = "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\SepLiveUpdate.exe"
            Ensure      = "Present"
        }

        # Copy Visual C++ Redistributable to machine
        xRemoteFile VCRedist
        {
            DestinationPath = "C:\Packages\vcredist17.exe"
            Uri             = $uriVCRedist
        }

        # Copy ODBC Driver to machine
        xRemoteFile ODBCDriver
        {
            DestinationPath = "C:\Packages\msodbcsql18.msi"
            Uri             = $uriODBCdriver
        }

        # Install Visual C++ Redistributable
        InstallProgram VCRedist
        {
            DisplayName   = "Microsoft Visual C++ 2015-2022 Redistributable (x64)"
            InstallerPath = "C:\Packages\vcredist17.exe"
            Arguments     = "/quiet /norestart"
        }

        # Install ODBC Driver
        InstallProgram ODBCDriver
        {
            DisplayName   = "Microsoft ODBC Driver 18 for SQL Server"
            InstallerPath = "C:\Packages\msodbcsql18.msi"
            Arguments     = "/quiet /norestart IACCEPTMSODBCSQLLICENSETERMS=YES"
        }

        xHostsFile PaasSQL
        {
            HostName  = $sqlServerPublicFQDN
            IPAddress = $sqlServerPrivateIP
            Ensure    = "Present"
        }

        DomainJoin DomainJoin
        {
            DomainName             = $DomainName
            AdminCreds             = $AdminCreds
            DomainOU               = $DomainOU
            LocalAdminGroupMembers = $LocalAdminGroupMembers
        }

        AzureUpdateManagement UpdateManagement
        {}

        # Since May 2024 the IIS installation files are not copied to C:\Windows\System32\inetsrv directory
        # when installing some IIS subfeatures. This causes the RSAT-RDS-Tools feature to fail to install
        # with error code 0x800f0922.
        # As a workaround we install Web-Mgmt-Tools first which copies the required file to the inetsrv folder.
        WindowsFeature Web-Mgmt-Tools
        {
            Ensure = "Present"
            Name   = "Web-Mgmt-Tools"
        }

        WindowsFeature RSAT-RDS-Tools
        {
            Ensure               = "Present"
            Name                 = "RSAT-RDS-Tools"
            IncludeAllSubFeature = $true
            DependsOn            = "[WindowsFeature]Web-Mgmt-Tools"
        }

        # The Web-Mgmt-Tools only installs the Web-Mgmt-Console. We can remove this after RSAT-RDS-Tools is
        # installed. We remove it after installing RSAT-RDS-Tools otherwise the required installation files
        # would be removed as well.
        WindowsFeature Web-Mgmt-Console
        {
            Ensure    = "Absent"
            Name      = "Web-Mgmt-Console"
            DependsOn = "[WindowsFeature]RSAT-RDS-Tools"
        }

        WindowsFeature RDS-Connection-Broker
        {
            Ensure = "Present"
            Name   = "RDS-Connection-Broker"
        }
    }
}

configuration RDLSDeployment
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', "", Justification = 'False positive.')
    ]
    param
    (
        [Parameter(Mandatory)]
        [string]
        $DomainName,

        [Parameter(Mandatory)]
        [PSCredential]
        $AdminCreds,

        [Parameter(Mandatory)]
        [PSCredential]
        $DeployCreds,

        [Parameter(Mandatory)]
        [string]
        $DomainOU,

        [Parameter(Mandatory)]
        [string[]]
        $LocalAdminGroupMembers
    )

    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion 9.1.0
    Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 3.0.0.0
    Import-DscResource -ModuleName xComputerManagement -ModuleVersion 4.1.0.0

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded             = $true
            ConfigurationMode              = "ApplyOnly"
            ConfigurationModeFrequencyMins = 1200
        }

        DomainJoin DomainJoin
        {
            DomainName             = $DomainName
            AdminCreds             = $AdminCreds
            DomainOU               = $DomainOU
            LocalAdminGroupMembers = $LocalAdminGroupMembers
        }

        AzureUpdateManagement UpdateManagement
        {}

        # Since May 2024 the IIS installation files are not copied to C:\Windows\System32\inetsrv directory
        # when installing some IIS subfeatures. This causes the RSAT-RDS-Tools feature to fail to install
        # with error code 0x800f0922.
        # As a workaround we install Web-Mgmt-Tools first which copies the required file to the inetsrv folder.
        WindowsFeature Web-Mgmt-Tools
        {
            Ensure = "Present"
            Name   = "Web-Mgmt-Tools"
        }

        WindowsFeature RSAT-RDS-Tools
        {
            Ensure               = "Present"
            Name                 = "RSAT-RDS-Tools"
            IncludeAllSubFeature = $true
            DependsOn            = "[WindowsFeature]Web-Mgmt-Tools"
        }

        # The Web-Mgmt-Tools only installs the Web-Mgmt-Console. We can remove this after RSAT-RDS-Tools is
        # installed. We remove it after installing RSAT-RDS-Tools otherwise the required installation files
        # would be removed as well.
        WindowsFeature Web-Mgmt-Console
        {
            Ensure    = "Absent"
            Name      = "Web-Mgmt-Console"
            DependsOn = "[WindowsFeature]RSAT-RDS-Tools"
        }

        WindowsFeature RDS-Licensing
        {
            Ensure = "Present"
            Name   = "RDS-Licensing"
        }
    }
}
