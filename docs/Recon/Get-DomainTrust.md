# Get-DomainTrust

## SYNOPSIS
{{Fill in the Synopsis}}

## SYNTAX

### NET (Default)
```
Get-DomainTrust [[-Domain] <String>] [-FindOne]
```

### API
```
Get-DomainTrust [[-Domain] <String>] [-API] [-Server <String>] [-FindOne]
```

### LDAP
```
Get-DomainTrust [[-Domain] <String>] [-LDAP] [-LDAPFilter <String>] [-Properties <String[]>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-FindOne] [-Credential <PSCredential>]
```

## DESCRIPTION
{{Fill in the Description}}

## EXAMPLES

### Example 1
```
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -API
{{Fill API Description}}

```yaml
Type: SwitchParameter
Parameter Sets: API
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
{{Fill Credential Description}}

```yaml
Type: PSCredential
Parameter Sets: LDAP
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
{{Fill Domain Description}}

```yaml
Type: String
Parameter Sets: (All)
Aliases: Name

Required: False
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -FindOne
{{Fill FindOne Description}}

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: ReturnOne

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LDAP
{{Fill LDAP Description}}

```yaml
Type: SwitchParameter
Parameter Sets: LDAP
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LDAPFilter
{{Fill LDAPFilter Description}}

```yaml
Type: String
Parameter Sets: LDAP
Aliases: Filter

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Properties
{{Fill Properties Description}}

```yaml
Type: String[]
Parameter Sets: LDAP
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ResultPageSize
{{Fill ResultPageSize Description}}

```yaml
Type: Int32
Parameter Sets: LDAP
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchBase
{{Fill SearchBase Description}}

```yaml
Type: String
Parameter Sets: LDAP
Aliases: ADSPath

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchScope
{{Fill SearchScope Description}}

```yaml
Type: String
Parameter Sets: LDAP
Aliases: 
Accepted values: Base, OneLevel, Subtree

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
{{Fill Server Description}}

```yaml
Type: String
Parameter Sets: API, LDAP
Aliases: DomainController

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServerTimeLimit
{{Fill ServerTimeLimit Description}}

```yaml
Type: Int32
Parameter Sets: LDAP
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Tombstone
{{Fill Tombstone Description}}

```yaml
Type: SwitchParameter
Parameter Sets: LDAP
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

### System.String


## OUTPUTS

### PowerView.DomainTrust.NET
PowerView.DomainTrust.LDAP
PowerView.DomainTrust.API


## NOTES

## RELATED LINKS

