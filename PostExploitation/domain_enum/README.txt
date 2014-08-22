======================================
|
|    p.j.hartlieb
|    powershell post-exploitation
|    domain_enum module v.0.0.1
|    2014.08.19
|    last verified 2014.08.19
|
======================================

#background

The domain_enum module is intended to support post-exploitation activities from within the user context on the target domain. It will enumerate domain computers, servers, users, groups, group membership(s), sites, subnets, and subnets per site and save the results to one or more files. Whenever possible it will also enumerate computers, servers, users, groups, and group membership per OU. It's really intended to establish situational awareness once you drop onto "patient 0" and set you up to make the most of who you pivot to. It requires dsquery and dsget to be resident on the system. They must also be executable in plain user context.

This module was created and tested with:
	Windows Powershell 2.0
	Windows 7 Professional SP1

#requirements

- dsquery.exe must be resident on the target system
- dsget.exe must be resident on the target system

#execution
- Create the following directory structure %USERPROFILE%\documents\windowspowershell\modules\domain_enum
- Open terminal
- Type
	  >powershell -ExecutionPolicy Bypass -
	PS>import-module domain_enum
	PS>get-command -module domain_enum
	PS>Get-Gattling
- All output will be posted to C:\Users\Public\

#thanks
- Lucius for helping to find those unholy syntax errors and figuring out to get it to execute hassle free.
