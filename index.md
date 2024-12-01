# CAS Plus DSC

This repository contains **Desired State Configuration** files for CAS Plus.

## Version

`package.yaml` file contains the version of the DSC. It should be increased following gitflow rules and semantic versioning.

## Documentation

You can read how DSC fits in the entire solution reading the [documentation](https://gitlab.internal.ericsson.com/san-tools-technology-platform/cas/infra/cas-plus/cas-plus-azure/-/tree/develop/doc).

## Utilities

Requires [Az module](https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-6.3.0) to be installed.

```powershell
#Push DSC to a storage account
.\Update-DeploymentArtifacts.ps1 -ResourceGroupName rg-cas-rds -StorageAccountName cassatelefonicaartifacts
```
