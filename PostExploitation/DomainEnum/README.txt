======================================
|
|    p.j.hartlieb
|    powershell post-exploitation
|    DomainEnum module v.0.0.3
|    2014.08.19
|    last verified 2014.09.05
|
======================================

#background

The DomainEnum module is intended to support post-exploitation activities from within the user context on the target domain. It will enumerate domain computers, servers, users, groups, group membership(s), sites, subnets, and subnets per site and save the results to one or more files. Whenever possible it will also enumerate computers, servers, users, groups, and group membership per OU. It's really intended to establish situational awareness once you drop onto "patient 0" and set you up to make the most of who you pivot to.

This module was created and tested with:
	Windows Powershell 2.0
	Windows 7 Professional SP1

#requirements

- n/a

#execution
- Create the following directory structure %USERPROFILE%\documents\windowspowershell\modules\DomainEnum
- Open terminal
- Type
	  >powershell -ExecutionPolicy Bypass -
	PS>import-module DomainEnum
	PS>get-command -module DomainEnum
- All output will be posted to C:\Users\Public\

#functionality

- Get-Pedigree			returns baseline infromation from the target host (patient 0)
- Get-Computer			returns all computers in the current domain
- Get-DC			returns the DCs and PDC for the current domain
- Get-Group			returns all groups in the current domain
- Get-GroupUser			returns all users in each group for the current domain
- Get-Server			returns all servers in the current domain
- Get-User 			returns all users in the current domain
- Get-OU 			returns all OUs in the current domain
- Get-OUUser 			returns all users for each OU in the current domain
- Get-OUServer 			returns all servers for each OU in the current domain
- Get-OUGroup 			returns all groups for each OU in the currentdomain
- Get-OUComputer 		returns all computers for each OU in the current domain
- Get-SiteServer 		returns all servers for each site in the current domain
- Get-SiteSubnet 		returns all subnets for each site in the current domain

#thanks
- Lucius for helping to find those unholy syntax errors and figuring out to get it to execute hassle free.
