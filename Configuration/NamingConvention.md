# DSC Modules naming convention and explanation

This folder contains **Desired State Configuration** files for CAS Plus.
Each subfolder contains a standalone module.

## Folder naming convention

Folder names for all DSC modules in Configuration folder should reflect to its origin:

- DSC modules coming from PowerShell Gallery use the same original package name as a folder name, regardless from any prefix character (c or x) in package name, i.e: xHyper_V
- DSC modules coming from PowerShell Gallery but modified by developers use prefix "**Ericsson_**" and end with the original package name as folder name, i.e: Ericsson_xRemoteDesktopSessionHost
- DSC modules which are entirely our custom development use folder name starting with prefix "**Ericsson_**" and end with the given unique package name. In this case no prefix characters (c or x) used, i.e: Ericsson_RemoteDesktopHA

## Resource files naming convention

Resource files inside DSCResources folders should reflect to the vendor in its name prefix:

- DSC resource files coming from PowerShell Gallery use the original vendor prefix, like **MSFT_** or other
- DSC resource files coming from PowerShell Gallery but modified by developers use prefix "**Ericsson_**"
- DSC resource files which are fully our custom development use prefix "**Ericsson_**"
