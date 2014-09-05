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

#thanks
- Lucius for helping to find those unholy syntax errors and figuring out to get it to execute hassle free.
