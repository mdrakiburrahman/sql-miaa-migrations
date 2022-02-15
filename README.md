# SQL Server to Arc SQL MI - Migration environment
A terraform-built demo environment for migrating various SQL Servers to Arc SQL MI.

We showcase the following entities in this repo:
> `#TODO DIAGRAM`

The Domain and DNS setup looks like this:
> `#TODO DIAGRAM`

## Table of Contents <!-- omit in toc -->
- [Infrastructure Deployment](#infrastructure-deployment)
  - [Dev Container](#dev-container)
  - [Terraform apply](#terraform-apply)
- [Post Deployment Steps](#post-deployment)
  - [Create Root Domain fg.contoso.com](#create-root-domain-with-dc1)
  - [Join new Domain Controller DC2 to Root Domain](#join-new-dc2-to-root-domain)
  - [Create Child Domain maple.fg.contoso.com](#create-child-domain)
  - [Add DNS Forwarding and Delegation](#add-dns-forwarding-and-delegation)
  - [Domain join SQL Servers & Client](#domain-join-remaining-machines)
  - [Client VM tooling](#client-vm-tooling)
  - [Create Windows Logins in SQL](#create-windows-logins-in-sql)
- [Arc Deployment](#post-deployment)
- [Data Migration Setup](#migration-setup)
- [Arc SQL MI Setup with AD](#arc-sql-mi-setup)

## Infrastructure Deployment

### Dev Container
The folder `.devcontainer` has necessary tools (terraform, azure-cli, kubectl etc) to get started on this demo with [Remote Containers](https://code.visualstudio.com/docs/remote/containers).

## Terraform apply

The following script deploys the environment with Terraform:
```bash
# ---------------------
# ENVIRONMENT VARIABLES
# For Terraform
# ---------------------
# Secrets
export TF_VAR_SPN_CLIENT_ID=$spnClientId
export TF_VAR_SPN_CLIENT_SECRET=$spnClientSecret
export TF_VAR_SPN_TENANT_ID=$spnTenantId
export TF_VAR_SPN_SUBSCRIPTION_ID=$subscriptionId
export TF_VAR_VM_USER_PASSWORD=$localPassword # RDP password for VMs

# Module specific
export TF_VAR_resource_group_name='raki-sql-to-miaa-migration-test-rg'

# ---------------------
# DEPLOY TERRAFORM
# ---------------------
cd terraform
terraform init
terraform plan
terraform apply -auto-approve

# ---------------------
# DESTROY ENVIRONMENT
# ---------------------
terraform destory
```
And we see:

![Resources Deployed](_images/terraform-resources.png)

## Post Deployment

The following steps weren't automated via Terraform because of return on invetment (and because automating stuff inside Windows is hard) - so we perform them manually:

---

### Create Root Domain with DC1

We run the following on: `FG-DC-1` to create `fg.contoso.com`

```powershell
# Configure the Domain Controller
$domainName = 'fg.contoso.com'
$domainAdminPassword = "P@s5w0rd123!!"
$secureDomainAdminPassword = $domainAdminPassword | ConvertTo-SecureString -AsPlainText -Force

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Create Active Directory Forest
Install-ADDSForest `
    -DomainName "$domainName" `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "7" `
    -DomainNetbiosName $domainName.Split('.')[0].ToUpper() ` # FG
    -ForestMode "7" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$false `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Force:$true `
    -SafeModeAdministratorPassword $secureDomainAdminPassword
```

After the reboot, we can login via Bastion as our Domain Admin `boor@fg.contoso.com`.

---

### Join new DC2 to Root Domain

We run the following on: `FG-DC-2` to join `fg.contoso.com`:

```powershell
# Join to Domain
$user = "FG\boor"
$domainAdminPassword = "P@s5w0rd123!!"
$domainName = 'fg.contoso.com'
$pass = $domainAdminPassword | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $pass
add-computer –domainname $domainName -Credential $Credential

# Install Windows Features
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Verbose

# Import Module
Import-Module ADDSDeployment -Verbose

Install-ADDSDomainController `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainName $domainName `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoGlobalCatalog:$false `
    -SiteName "Default-First-Site-Name" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -NoRebootOnCompletion:$false `
    -Force:$true `
    -SafeModeAdministratorPassword $pass `
    -Credential $Credential

# Reboot, and login with Domain Admin

# Test install after reboot
Test-ADDSDomainControllerInstallation -Debug -Credential $Credential -DomainName $domainName -SafeModeAdministratorPassword $pass

# Get DC information
Get-ADDomainController -Discover
Get-ADDomainController -Verbose

# Get PDC
Get-ADDomainController -Discover -Domain $domainName -Service "PrimaryDC","TimeService"

```
And we see:

![DC2 Verify](_images/dc-2-verify.png)

DNS:

![DC2 DNS Verify](_images/dc2-dns-verify.png)

And we can check the domain and Forest information:
``` Powershell
# To find the Domain Functional Level, use this command:
Get-ADDomain | fl Name,DomainMode

# To find the Forest Functional Level, use this command:
Get-ADForest | fl Name,ForestMode
```
![Domain and Forest](_images/domain-forest.png)

---

### Create Child Domain

We run the following on: `MAPLE-DC-1` to create `maple.fg.contoso.com`:

```Powershell
# Install Windows Features
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Verbose

# Set Creds
$user = "boor@fg.contoso.com" # Different format than before since machine isn't domain joined
$domainAdminPassword = "P@s5w0rd123!!"
$domainName = 'fg.contoso.com'
$pass = $domainAdminPassword | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $pass

# Create Child Domain
Install-ADDSDomain `
    -Credential $Credential `
    -NewDomainName "maple" `
    -ParentDomainName $domainName `
    -InstallDNS `
    -DatabasePath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -LogPath "C:\Windows\NTDS" `
    -SafeModeAdministratorPassword $pass `
    -NoRebootOnCompletion:$false `
    -Force:$true

# Reboot, and login with Domain Admin for Child Domain boor@maple.fg.contoso.com
whoami

# Test install after reboot
Test-ADDSDomainControllerInstallation -Debug -Credential $Credential -DomainName $domainName -SafeModeAdministratorPassword $pass

# Get DC information
Get-ADDomainController -Discover
Get-ADDomainController -Verbose

# Get PDC
Get-ADDomainController -Discover -Domain $domainName -Service "PrimaryDC","TimeService"
```

We see after logging in with `boor@maple.fg.contoso.com`:

![Logged in with Child Domain User](_images/child-domain-setup.png)

And note we can also login with `boor@fg.contoso.com` into the `maple` machine - which is desirable:

Finally we see the new Child Domain and domain controller get added as well:

![Logged in with Root Domain User](_images/child-domain-login.png)

The Child Domain is visible in the Root Domain Controller as well:

![Child Domain](_images/ad-trusts.png)

---

### Add DNS Forwarding and Delegation

On both `FG-DC-1` and `MAPLE-DC-1`, we need to configure DNS Delegation and Conditional Forwarding so any domain queries end up in the correct domain's DNS server:

* Run on `FG-DC-1` for `maple.fg.contoso.com` goes to the `MAPLE-DC-1` DNS Server

  ```PowerShell
  Add-DnsServerZoneDelegation -Name "fg.contoso.com" -ChildZoneName "maple" -NameServer "maple-dc-1-vm.maple.fg.contoso.com" -IPAddress 192.168.1.4 -PassThru -Verbose
  ```
* Run on `MAPLE-DC-1` for `fg.contoso.com` goes to the `FG-DC-1` DNS Server

  ```PowerShell
  Add-DnsServerConditionalForwarderZone -Name "fg.contoso.com" -MasterServers "192.168.0.4" # FG-DC-1-vm
  ```

> Run `ipconfig /flushdns` each machine testing this update.

`ping FG-DC-1-vm.fg.contoso.com`:

We see on `FG-DC-1`:

![DNS Delegation to MAPLE](_images/dns-delegation.png)

![DNS Delegation to MAPLE](_images/dns-delegation-1.png)

And we see on `MAPLE-DC-1`:

`ping MAPLE-DC-1-vm.maple.fg.contoso.com`

![Conditional Forwarding to FG](_images/conditional-forwardering-1.png)

![Conditional Forwarding to FG](_images/conditional-forwardering.png)

---

### Domain Join remaining machines

On each of the following `FG` machines, run the following PowerShell script as local admin:
* `FG-CLIENT-vm`
* `FG-SQL-2012-sql-vm`
* `FG-SQL-2014-sql-vm`
* `FG-SQL-2016-sql-vm`

``` Powershell
# Join to FG Domain
$user = "FG\boor"
$domainAdminPassword = "P@s5w0rd123!!"
$domainName = 'fg.contoso.com'
$pass = $domainAdminPassword | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $pass
add-computer –domainname $domainName -Credential $Credential -restart –force
```

We see:

![FG Machines](_images/fg-pc.png)

And for `MAPLE-SQL-2019-sql-vm`:

``` Powershell
# Join to MAPLE Domain
$user = "MAPLE\boor"
$domainAdminPassword = "P@s5w0rd123!!"
$domainName = 'maple.fg.contoso.com'
$pass = $domainAdminPassword | ConvertTo-SecureString -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $pass
add-computer –domainname $domainName -Credential $Credential -restart –force
```

![MAPLE Machines](_images/maple-pc.png)

---

### Client VM tooling

We install a few tools on `FG-CLIENT-vm` for demo purposes later by signing in as `boor@fg.contoso.com`:

```Powershell
# Install chocolatey
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install apps
$chocolateyAppList = 'azure-cli,kubernetes-cli,vscode,kubernetes-helm,grep,ssms'

$appsToInstall = $chocolateyAppList -split "," | foreach { "$($_.Trim())" }

foreach ($app in $appsToInstall)
{
    Write-Host "Installing $app"
    & choco install $app /y -Force| Write-Output
}

# Kubectl alias
New-Item -path alias:kubectl -value 'C:\ProgramData\chocolatey\lib\kubernetes-cli\tools\kubernetes\client\bin\kubectl.exe'
```

---

### Create Windows logins in SQL

Now, we must RDP in as the **local** user `boor` and not the domain user (`FG\boor` or `MAPLE\boor`) - so that we can sign into our 4 SQL Servers and create Windows AD logins.

> This is because the SQL Marketplace images created local user logins by default.

For example:

![Sign in as local user](_images/windows-onboard.png)

Launch SSMS and sign in:

![Sign in as local user](_images/windows-onboard-1.png)

Perform on:
* `FG-SQL-2012-sql-vm`
* `FG-SQL-2014-sql-vm`
* `FG-SQL-2016-sql-vm`
* `MAPLE-SQL-2019-sql-vm`

``` SQL
USE [master]
GO
-- Create login for FG
CREATE LOGIN [FG\boor] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
GO
ALTER SERVER ROLE [sysadmin] ADD MEMBER [FG\boor]
GO
-- Create login for MAPLE
CREATE LOGIN [MAPLE\boor] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
GO
ALTER SERVER ROLE [sysadmin] ADD MEMBER [MAPLE\boor]
GO
```

We create the windows logins on all 4 SQL servers:

![Domain logins successfully created](_images/windows-onboard-2.png)

From `FG-SQL-2014`, and `MAPLE-SQL-2019`, login to all 4 instances as Windows AD login:

![Test login to all instances with each domain](_images/windows-onboard-6.png)

---

### Arc SQL MI Setup

We deploy in _Indirect_ mode since it's a bit faster but this will work identically in _Direct_:
