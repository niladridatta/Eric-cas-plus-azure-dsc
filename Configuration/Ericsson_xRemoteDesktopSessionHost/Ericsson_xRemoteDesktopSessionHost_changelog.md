# Changelog

## Version 1.0.1

### Summary

This is the initial version of Ericsson developed xRemoteDesktopSessionHost DSC module.
This module is a fork of Microsoft xRemoteDesktopSessionHost module version 1.0.1. It also contains submodules from later version of xRemoteDesktopSessionHost:

- xRDGatewayConfiguration (no source version information available)
- xRDLicenseConfiguration (no source version information available)
- xRDServer (no source version information available)

Please note that the following submodules also has been updated to an unknown version and customized.
Updating these modules may need code comparison and transplantation of custom features.

- Ericsson_xRDRemoteApp
- Ericsson_xRDSessionCollection
- Ericsson_xRDSessionCollectionConfiguration
- Ericsson_xRDSessionDeployment

### Changes

Ericsson_xRDSessionCollection.psm1

- added extended functionality to function Get-TargetResource
- added extended functionality to function Set-TargetResource
- added extended functionality to function Test-TargetResource

Ericsson_xRDSessionDeployment.psm1

- added extended functionality to function Get-TargetResource
- added extended functionality to function Set-TargetResource
- added extended functionality to function Test-TargetResource
