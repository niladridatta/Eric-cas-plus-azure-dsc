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
        [String]
        $FSLogixProfileShare,

        [Parameter(Mandatory)]
        [String]
        $FSLogixProfilePath
    )

    @{
        VMName              = $VMName
        FSLogixProfileShare = $FSLogixProfileShare
        FSLogixProfilePath  = $FSLogixProfilePath
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
        [String]
        $FSLogixProfileShare,

        [Parameter(Mandatory)]
        [String]
        $FSLogixProfilePath
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @($FSLogixProfileShare
                            $FSLogixProfilePath)
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [String]
            $FSLogixProfileShare,

            [Parameter(Mandatory)]
            [String]
            $FSLogixProfilePath
        )

        $fsLogixPath = Test-Path -Path $FSLogixProfilePath

        if (!$fsLogixPath) {
            $message = ("FSLogix profile path '{0}' does not exist. FSLogix is not set." -f
                        $FSLogixProfilePath)

            Write-Verbose -Message $message -Verbose
            return $false
        }

        # TODO: ACL check

        $targetCCDLocations = @("type=smb,connectionString=$($FSLogixProfilePath)"
                                "type=smb,connectionString=$($FSLogixProfileShare)")

        $targetCCDLocationsString = $targetCCDLocations -join ''

        try {
            $getItemPropertyValueParams = @{
                Path = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                Name = 'CCDLocations'
            }

            $ccdLocations = Get-ItemPropertyValue @getItemPropertyValueParams

            $compareObjectParams = @{
                ReferenceObject     = $targetCCDLocations
                DifferenceObject    = $ccdLocations
            }

            $different = Compare-Object @compareObjectParams

            if ($different) {
                $message = ("FSLogix CCDLocations '{0}' is not set." -f $targetCCDLocationsString)
                Write-Verbose -Message $message -Verbose
                return $false
            }
        }
        catch {
            $message = ("FSLogix CCDLocations '{0}' is not set." -f $targetCCDLocationsString)
            Write-Verbose -Message $message -Verbose
            return $false
        }

        try {
            $value = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\FSLogix\Profiles' -Name 'Enabled'
            if ($value -ne '1') {
                Write-Verbose -Message 'FSLogix is not enabled. FSLogix is not set.' -Verbose
                return $false
            }
        }
        catch{
            Write-Verbose -Message 'FSLogix is not enabled. FSLogix is not set.' -Verbose
            return $false
        }

        Write-Verbose -Message 'FSLogix is set.' -Verbose
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
        [String]
        $FSLogixProfileShare,

        [Parameter(Mandatory)]
        [String]
        $FSLogixProfilePath
    )

    if ($PSCmdlet.ShouldProcess($VMName)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @($FSLogixProfileShare
                                $FSLogixProfilePath)
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [String]
                $FSLogixProfileShare,

                [Parameter(Mandatory)]
                [String]
                $FSLogixProfilePath
            )

            $message = ("Creating FSLogix profile directory '{0}'." -f $FSLogixProfilePath)
            Write-Verbose -Message $message -Verbose
            New-Item -ItemType Directory -Path $FSLogixProfilePath -Force

            $accessControlEntryUsers = [System.Security.AccessControl.FileSystemAccessRule]::new(
                'Users',
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )

            $accessControlEntryCREATOROWNER = [System.Security.AccessControl.FileSystemAccessRule]::new(
                'CREATOR OWNER',
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )

            $accessControlEntryDomainUsers = [System.Security.AccessControl.FileSystemAccessRule]::new(
                'Domain Users',
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )

            $objACL = Get-ACL -Path $FSLogixProfilePath
            $objACL.RemoveAccessRuleAll($accessControlEntryUsers)
            $objACL.AddAccessRule($accessControlEntryCREATOROWNER)
            $objACL.AddAccessRule($accessControlEntryDomainUsers)

            $message = ("Setting ACLs on FSLogix profile directory '{0}'." -f $FSLogixProfilePath)
            Write-Verbose -Message $message -Verbose

            Set-ACL -Path $FSLogixProfilePath -AclObject $objACL

            # To workaround an issue with FSLogix, the local profile location is the first in this list.
            # This should be switched after the root cause of the issue is fixed.
            $ccdLocations = @("type=smb,connectionString=$($FSLogixProfilePath)"
                                "type=smb,connectionString=$($FSLogixProfileShare)")

            $ccdLocationsString = $ccdLocations -join ''

            $message = ("Setting FSLogix CCDLocations to '{0}'." -f $ccdLocationsString)
            Write-Verbose -Message $message -verbose

            $setItemPropertyParams = @{
                Path    = 'HKLM:\SOFTWARE\FSLogix\Profiles'
                Name    = 'CCDLocations'
                Value   = $ccdLocations
            }

            Set-ItemProperty @setItemPropertyParams -Force

            Write-Verbose -Message 'Enabling FSLogix.' -Verbose
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\FSLogix\Profiles' -Name 'Enabled' -Value '1' -Force
        }
    }
}