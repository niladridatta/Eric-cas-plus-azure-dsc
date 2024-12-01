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
        $Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [ValidateNotNull()]
        [string]
        $PropertyName,

        [Parameter()]
        [ValidateSet('DWord', 'QWord', 'String', 'MultiString', 'ExpandString', 'Binary')]
        [string]
        $PropertyType = 'String',

        [Parameter()]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [string[]]
        $PropertyValue = @()
    )

    @{
        VMName          = $VMName
        Key             = $Key
        PropertyName    = $PropertyName
        PropertyType    = $PropertyType
        PropertyValue   = $PropertyValue
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
        $Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [ValidateNotNull()]
        [string]
        $PropertyName,

        [Parameter()]
        [ValidateSet('DWord', 'QWord', 'String', 'MultiString', 'ExpandString', 'Binary')]
        [string]
        $PropertyType = 'String',

        [Parameter()]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [string[]]
        $PropertyValue = @()
    )

    Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

    $invokeCommandParams = @{
        VMName          = $VMName
        Credential      = $LocalAdminCredential
        ArgumentList    = @(
                            $Key
                            $PropertyName
                            $PropertyType
                            (, $PropertyValue)
                        )
    }

    Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
        param(
            [Parameter(Mandatory)]
            [string]
            $Key,

            [Parameter(Mandatory)]
            [AllowEmptyString()]
            [ValidateNotNull()]
            [string]
            $PropertyName,

            [Parameter()]
            [ValidateSet('DWord', 'QWord', 'String', 'MultiString', 'ExpandString', 'Binary')]
            [string]
            $PropertyType = 'String',

            [Parameter()]
            [AllowEmptyCollection()]
            [ValidateNotNull()]
            [string[]]
            $PropertyValue = @()
        )

        Write-Verbose -Message ("Validating registry key '{0}'." -f $Key) -Verbose
        $keyExists = Test-Path -Path $Key

        If (!$keyExists) {
            Write-Verbose -Message ("Registry key '{0}' does not exists." -f $Key) -Verbose
            Write-Verbose -Message ("Registry key '{0}' is not set." -f $Key) -Verbose
            return $false
        }

        Write-Verbose -Message ("Registry key '{0}' exists." -f $Key) -Verbose

        if (!$PropertyName) {
            Write-Verbose -Message ("Registry key '{0}' is set." -f $Key) -Verbose
            return $true
        }

        $keyItem = Get-Item -Path $Key

        if ($PropertyName -notin $keyItem.Property) {
            Write-Verbose -Message ("Property '{0}' does not exists." -f $PropertyName) -Verbose
            Write-Verbose -Message ("Registry key '{0}' is not set." -f $Key) -Verbose
            return $false
        }

        $keyProperty = Get-ItemProperty -Path $Key -Name $PropertyName
        $keyPropertyValue = $keyProperty | Select-Object -ExpandProperty $PropertyName
        $keyPropertyType = $keyPropertyValue.GetType()

        $expectedValueType = switch ($PropertyType) {
            'DWord'         { 'Int32' }
            'QWord'         { 'Int64' }
            'Binary'        { 'Byte[]' }
            'MultiString'   { 'String[]' }
            Default         { 'String' }
        }

        Write-Verbose -Message ("Expected type for property '{0}' is '{1}'. Actual value is '{2}'." -f
            $PropertyName, $expectedValueType, $keyPropertyType.Name) -Verbose

        if ($keyPropertyType.Name -ne $expectedValueType) {
            Write-Verbose -Message ("Property '{0}' type mismatch." -f $PropertyName) -Verbose
            Write-Verbose -Message ("Registry key '{0}' is not set." -f $Key) -Verbose
            return $false
        }

        $expectedValue = switch ($PropertyType) {
            'DWord'         { [int32]($PropertyValue | Select-Object -First 1) }
            'QWord'         { [int64]($PropertyValue | Select-Object -First 1) }
            'Binary'        { [byte[]]$PropertyValue }
            'MultiString'   { $PropertyValue }
            Default         { $PropertyValue | Select-Object -First 1 }
        }

        Write-Verbose -Message ("Expected value for property '{0}' is '{1}'. Actual value is '{2}'." -f
            $PropertyName, $expectedValue, $keyPropertyValue) -Verbose

        if ($keyPropertyValue -ne $expectedValue) {
            Write-Verbose -Message ("Property '{0}' value mismatch." -f $PropertyName) -Verbose
            Write-Verbose -Message ("Registry key '{0}' is not set." -f $Key) -Verbose
            return $false
        }

        Write-Verbose -Message ("Registry key '{0}' is set." -f $Key) -Verbose
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
        $Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [ValidateNotNull()]
        [string]
        $PropertyName,

        [Parameter()]
        [ValidateSet('DWord', 'QWord', 'String', 'MultiString', 'ExpandString', 'Binary')]
        [string]
        $PropertyType = 'String',

        [Parameter()]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [string[]]
        $PropertyValue = @()
    )

    if ($PSCmdlet.ShouldProcess($Key)) {
        Write-Verbose -Message ("Connecting to VM '{0}'." -f $VMName)

        $invokeCommandParams = @{
            VMName          = $VMName
            Credential      = $LocalAdminCredential
            ArgumentList    = @(
                                $Key
                                $PropertyName
                                $PropertyType
                                (, $PropertyValue)
                            )
        }

        Invoke-Command @invokeCommandParams -Verbose -ScriptBlock {
            param(
                [Parameter(Mandatory)]
                [string]
                $Key,

                [Parameter(Mandatory)]
                [AllowEmptyString()]
                [ValidateNotNull()]
                [string]
                $PropertyName,

                [Parameter()]
                [ValidateSet('DWord', 'QWord', 'String', 'MultiString', 'ExpandString', 'Binary')]
                [string]
                $PropertyType = 'String',

                [Parameter()]
                [AllowEmptyCollection()]
                [ValidateNotNull()]
                [string[]]
                $PropertyValue = @()
            )

            Write-Verbose -Message ("Setting registry key '{0}'." -f $Key) -Verbose
            $keyExists = Test-Path -Path $Key

            if (!$keyExists) {
                Write-Verbose -Message ("Registry key '{0}' does not exists." -f $Key) -Verbose
                Write-Verbose -Message ("Creating registry key '{0}'." -f $Key) -Verbose
                New-Item -Path $Key -ItemType Directory -Force
            }

            Write-Verbose -Message ("Registry key '{0}' exists." -f $Key) -Verbose

            if (!$PropertyName) {
                return
            }

            $value = switch ($PropertyType) {
                'DWord'         { [int32]($PropertyValue | Select-Object -First 1) }
                'QWord'         { [int64]($PropertyValue | Select-Object -First 1) }
                'Binary'        { [byte[]]$PropertyValue }
                'MultiString'   { $PropertyValue }
                Default         { $PropertyValue | Select-Object -First 1 }
            }

            $newItemPropertyParams = @{
                Path            = $Key
                Name            = $PropertyName
                PropertyType    = $PropertyType
                Value           = $value
                Force           = $true
            }

            Write-Verbose -Message ("Setting property '{0}' with type '{1}' and value '{2}'." -f
                $PropertyName, $PropertyType, $value) -Verbose

            New-ItemProperty @newItemPropertyParams
        }
    }
}