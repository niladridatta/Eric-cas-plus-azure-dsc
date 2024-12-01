<#PSScriptInfo
.VERSION 1.0
.GUID d64010be-87d8-46e7-a254-4c5c30a92c13
.AUTHOR Ericsson
#>

<#
.DESCRIPTION
Configurations.Tests
#>

$global:here = (Split-Path -Parent $MyInvocation.MyCommand.Path)
[array]$global:dscModules = "xActiveDirectory", "xComputerManagement", "xHyper-V", "xNetworking", "xPSDesiredStateConfiguration", "Ericsson_xRemoteDesktopSessionHost", "xWindowsUpdate", "Ericsson_RemoteDesktopHA", "Ericsson_RemoteDesktopVirtualizationHost"
$global:scriptsModule = $global:here + "\Configuration.ps1"

Describe 'General - Testing all scripts and modules against the Script Analyzer Rules' {
    Context "Checking file to test exist and Invoke-ScriptAnalyzer cmdLet is available" {
        It "Checking file exist to test." {
            Test-Path -Path $global:scriptsModule -PathType Leaf | Should -BeTrue
        }
        It "Checking Invoke-ScriptAnalyzer exists." {
            { Get-Command Invoke-ScriptAnalyzer -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context "Checking DSC modules" -Foreach $global:dscModules {
        It "Checking <_>" {
            $dir = $global:here + "\" + $($_)
            [System.IO.Directory]::Exists($dir) | Should -BeTrue
        }
    }
}
