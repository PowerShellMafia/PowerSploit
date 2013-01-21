function Get-Member
{
<#
.SYNOPSIS

Gets the properties and methods of objects.

PowerSploit Proxy Function: Get-Member
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause (Except for the help documentation derived from the original Get-Member)
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The Get-Member cmdlet gets the "members" (properties and methods) of objects.

To specify the object, use the InputObject parameter or pipe an object to Get-Member. To retrieve information about static members (members of the class, not of the instance), use the Static parameter. To get only certain types of members, such as NoteProperties, use the MemberType parameter.

.PARAMETER Private

Gets only the non-public members of the object.

These members are typically not exposed and are extracted using reflection.

.PARAMETER Static

Gets only the static properties and methods of the object. 

Static properties and methods are defined on the class of objects, not on any particular instance of the class.

If you use the Static parameter with the View parameter, the View parameter is ignored. If you use the Static parameter with the MemberType parameter, Get-Member gets only the members that belong to both sets.

.PARAMETER Force

Adds the intrinsic members (PSBase, PSAdapted, PSObject, PSTypeNames) and the compiler-generated get_, set_, op_, .ctor, and .cctor methods to the display. By default, Get-Member gets these properties in all views other than "Base" and "Adapted," but it does not display them. 

The following list describes the properties that are added when you use the Force parameter:
        
-- PSBase:  The original properties of the .NET Framework object without extension or adaptation. These are the properties defined for the object class and listed in MSDN. 
-- PSAdapted: The properties and methods defined in the Windows PowerShell extended type system.
-- PSExtended: The properties and methods that were added in the Types.ps1xml files or by using the Add-Member cmdlet.
-- PSObject: The adapter that converts the base object to a Windows PowerShell PSObject object.
-- PSTypeNames: A list of object types that describe the object, in order of specificity. When formatting the object, Windows PowerShell searches for the types in the Format.ps1xml files in the Windows PowerShell installation directory ($pshome). It uses the formatting definition for the first type that it finds.
-- get_*: The object's getter methods
-- set_*: The object's setter methods
-- op_*: The object's operator methods
-- .ctor: The object's constructor
-- .cctor: The object's copy constructor

.PARAMETER InputObject

Specifies the object whose members are retrieved.

Using the InputObject parameter is not the same as piping an object to Get-Member. The differences are as follows:
        
-- When you pipe a collection of objects to Get-Member, Get-Member gets the members of the individual objects in the collection, such as the properties of the integers in an array of integers. 
        
-- When you use InputObject to submit a collection of objects, Get-Member gets the members of the collection, such as the properties of the array in an array of integers.

.PARAMETER PrivateMemberType

When the 'Private' parameter is specified, only members with the specified member type. The default is All.

The valid values for this parameter are:

-- Constructor: A constructor method of the underlying .NET Framework object.
-- Event: Indicates that the object sends a message to indicate an action or a change in state. 
-- Field: A private field of the underlying .NET Framework object.
-- Method: A method of the underlying .NET Framework object.
-- Property: A property of the underlying .NET Framework object.
-- TypeInfo: A type of the underlying .NET Framework object.
-- Custom: A custom member type
-- NestedType: A nested type of the underlying .NET Framework object.

-- All: Gets all member types.

.PARAMETER MemberType

Gets only members with the specified PowerShell member type. The default is All.

The valid values for this parameter are: 
        
-- AliasProperty: A property that defines a new name for an existing property.
-- CodeMethod: A method that references a static method of a .NET Framework class.
-- CodeProperty: A property that references a static property of a .NET Framework class.
-- Event: Indicates that the object sends a message to indicate an action or a change in state. 
-- MemberSet: A predefined collection of properties and methods, such as PSBase, PSObject, and PSTypeNames.
-- Method: A method of the underlying .NET Framework object.  
-- NoteProperty: A property with a static value.
-- ParameterizedProperty: A property that takes parameters and parameter values. 
-- Property: A property of the underlying .NET Framework object.
-- PropertySet: A predefined collection of object properties.
-- ScriptMethod: A method whose value is the output of a script.
-- ScriptProperty: A property whose value is the output of a script.
        
-- All: Gets all member types.  
-- Methods: Gets all types of methods of the object (for example, Method, CodeMethod, ScriptMethod).
-- Properties: Gets all types of properties of the object (for example, Property, CodeProperty, AliasProperty, ScriptProperty).
        
Not all objects have every type of member. If you specify a member type that the object does not have, Windows PowerShell returns a null value.
        
To get related types of members, such as all extended members, use the View parameter. If you use the MemberType parameter with the Static or View parameters, Get-Member gets the members that belong to both sets.

.PARAMETER Name

Specifies the names of one or more properties or methods of the object. Get-Member gets only the specified properties and methods.
        
If you use the Name parameter with the MemberType, View, or Static parameters, Get-Member gets only the members that satisfy the criteria of all parameters. 
        
To get a static member by name, use the Static parameter with the Name parameter.

.PARAMETER View

Gets only particular types of members (properties and methods). Specify one or more of the values. The default is "Adapted, Extended".

Valid values are:
-- Base:  Gets only the original properties and methods of the .NET Framework object (without extension or adaptation).
-- Adapted:  Gets only the properties and methods defined in the Windows PowerShell extended type system.
-- Extended: Gets only the properties and methods that were added in the Types.ps1xml files or by using the Add-Member cmdlet.
-- All: Gets the members in the Base, Adapted, and Extended views.

The View parameter determines the members retrieved, not just the display of those members. 

To get particular member types, such as script properties, use the MemberType parameter. If you use the MemberType and View parameters in the same command, Get-Member gets the members that belong to both sets. If you use the Static and View parameters in the same command, the View parameter is ignored.

.EXAMPLE

C:\PS> [String] | Get-Member -Static -Private

Description
-----------
Returns all staic, non-public members of the String class.

.EXAMPLE

C:\PS> [Diagnostics.Process] | Get-Member -Private -PrivateMemberType Method

Description
-----------
Returns all non-public instance methods of the Diagnostics.Process class

.EXAMPLE

C:\PS> "Hello, World" | Get-Member -Private -Force

Description
-----------
Returns all instance members including those with special names (like .ctor) of the string instance

.LINK

http://www.exploit-monday.com/2012/08/surgical-net-dissection.html

#>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param (
        [Parameter(ValueFromPipeline=$true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipeline=$true, ParameterSetName = 'Private')]
        [System.Management.Automation.PSObject]
        $InputObject,

        [Parameter(Position=0, ParameterSetName = 'Default')]
        [Parameter(Position=0, ParameterSetName = 'Private')]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $Name,

        [Parameter(ParameterSetName = 'Default')]
        [Alias('Type')]
        [System.Management.Automation.PSMemberTypes]
        $MemberType,
        
        [Parameter(ParameterSetName = 'Private')]
        [System.Reflection.MemberTypes]
        $PrivateMemberType = [System.Reflection.MemberTypes]::All,

        [Parameter(ParameterSetName = 'Default')]
        [System.Management.Automation.PSMemberViewTypes]
        $View,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Private')]
        [Switch]
        $Static,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Private')]
        [Switch]
        $Force,
        
        [Parameter(ParameterSetName = 'Private')]
        [Switch]
        $Private
    )

    BEGIN
    {
        try {
            $outBuffer = $null
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\Get-Member', [System.Management.Automation.CommandTypes]::Cmdlet)
            # Redirect the output of the command to $out variable
            $null = $PSBoundParameters.Add('OutVariable', 'out')
            # Redirect original output to $null
            if ($PSBoundParameters['Private']) {
                $null = $PSBoundParameters.Remove('Private')
                $Private = $True
            }
            if ($PSBoundParameters['PrivateMemberType']) {
                $PrivateMemberType = $PSBoundParameters['PrivateMemberType']
                $null = $PSBoundParameters.Remove('PrivateMemberType')
            }
            $scriptCmd = {& $wrappedCmd @PSBoundParameters | Out-Null }
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($PSCmdlet)
        } catch {
        }
    }

    PROCESS
    {
        try {
            $steppablePipeline.Process($_)
        } catch {
        }
    }

    END
    {
        try {
            $steppablePipeline.End()
            if ($Private) {
            
                $Object = $PSBoundParameters['InputObject']
                if ($Object.GetType().FullName -ne 'System.RuntimeType') {
                    # If InputObject is an instance of an object, get its type
                    # Otherwise, it's assumed that what was passed in was already a type
                    $Object = $Object.GetType()
                }
                
                if ($PSBoundParameters['Static']) {
                    $Flags = 'Static, NonPublic'
                    
                    # Retrieve all static, nonpublic members except for constructors
                    $Types = foreach ($Val in [Enum]::GetValues([System.Reflection.MemberTypes])) {
                        $Object.GetMembers($Flags) | Where-Object { ($_.MemberType -eq ($Val.value__ -band $PrivateMemberType)) -and ($Val -ne [System.Reflection.MemberTypes]::All) -and ($_.MemberType -ne 'Constructor') }
                    }
                    
                    # Retrieve all static constructors (both public and nonpublic)
                    # Public constructors are retrieved because the original 'Get-Member -Force' does not retrieve constructors
                    $Types += $Object.GetConstructors('Static, NonPublic, Public')
                } else {
                    $Flags = 'Instance, NonPublic'
                    
                    # Retrieve all instance, nonpublic members except for constructors
                    $Types = foreach ($Val in [Enum]::GetValues([System.Reflection.MemberTypes])) {
                        $Object.GetMembers($Flags) | Where-Object { ($_.MemberType -eq ($Val.value__ -band $PrivateMemberType)) -and ($Val -ne [System.Reflection.MemberTypes]::All) -and ($_.MemberType -ne 'Constructor') }
                    }
                    
                    # Retrieve all instance constructors (both public and nonpublic)
                    # Public constructors are retrieved because the original 'Get-Member -Force' does not retrieve constructors
                    $Types += $Object.GetConstructors('Instance, NonPublic, Public')
                }
                
                # Filter out types with special names if '-Force' is not specified
                if (!$Force) {
                    $Types = $Types | Where-Object { !$_.IsSpecialName }
                }
                
                $TypeTable = @{}
                
                # For each type, build an array of object equivalent to an array of Microsoft.PowerShell.Commands.MemberDefinition objects.
                # An array of custom objects is required because the MemberDefinition object doesn't take System.Reflection.MemberTypes
                # objects in its constructor.
                $Results = $Types | ForEach-Object {
                
                    $Type = $_
                    
                    switch ($Type.MemberType) {
                        'Constructor' {
                            $Parameters = ($Type.GetParameters() | % {$_.ParameterType.FullName}) -join ', '
                            $Definition = "$(if ($Type.IsStatic){'static '})$($Type.Name)($($Parameters))"
                        }
                        'Field' {
                            $Definition = "$(if ($Type.IsStatic){'static '})$($Type.FieldType)"
                        }
                        'Method' {
                            $Parameters = ($Type.GetParameters() | % {$_.ParameterType.FullName}) -join ', '
                            $Definition = "$(if ($Type.IsStatic){'static '})$($Type.ReturnType) $($Type.Name)($($Parameters))"
                        }
                        'Property' {
                            $Definition = "$(if ($Type.IsStatic){'static '})$($Type.PropertyType) $($Type.Name) {$(if ($Type.CanRead){'get;'})$(if ($Type.CanWrite){'set;'})}"
                        }
                        'NestedType' {
                            $Definition = "$(if ($Type.IsStatic){'static '})$($Type.FullName) BaseType=$($Type.BaseType)"
                        }
                        'Event' {
                            $Parameters = ($Type.GetAddMethod().GetParameters() | % {$_.ParameterType.FullName}) -join ', '
                            $Definition = "$(if ($Type.IsStatic){'static '})$($Type.EventHandlerType) $($Type.Name)(System.Object, $($Parameters))"
                        }
                    }
                    
                    # Identical properties as the Microsoft.PowerShell.Commands.MemberDefinition object
                    $InternalMemberType = @{
                        TypeName = $Type.DeclaringType.FullName
                        Name = $Type.Name
                        MemberType = $Type.MemberType
                        Definition = $Definition
                    }
                    
                    New-Object PSObject -Property $InternalMemberType
                }
                
                # For members with the same name, compress them into an array that will be stored in a hashtable
                $Results | ForEach-Object {
                    $TypeTable["$($_.Name)"] += @($_)
                }
                
                $Results = foreach ($Type in $TypeTable.Keys) {
                    $ReturnType = @{
                        TypeName = $TypeTable[$Type][0].TypeName
                        Name = $TypeTable[$Type][0].Name
                        MemberType = $TypeTable[$Type][0].MemberType
                        # Append each definition into a single definition.
                        # This behavior is indentical to what the unmodified
                        # Get-Member does.
                        Definition = ($TypeTable[$Type] | ForEach-Object { $_.Definition }) -join ', '
                    }
                    
                    $MemberDef = New-Object PSObject -Property $ReturnType
                    <# 
                     Cool trick. Even though the custom object is actually a Microsoft.PowerShell.Commands.MemberDefinition
                      object, you can trick it into thinking it is so that it will display the same way the result of the
                      original Get-Member cmdlet would. 
                    #>
                    $MemberDef.PSObject.TypeNames.Insert(0, 'Microsoft.PowerShell.Commands.MemberDefinition')
                    $MemberDef
                }
                
                # If '-Name' parameter is specified, only return members matching the name specified
                if ($PSBoundParameters['Name']) {
                    $MemberNames = [String[]] $PSBoundParameters['Name']
                    
                    $Tmp = New-Object PSObject[](0)
                    
                    foreach ($MemberName in $MemberNames) {
                        $Tmp += $Results | Where-Object { $_.Name -eq $MemberName }
                    }
                    
                    $Results = $Tmp
                }
                
                # Return the results if the results are non-null
                if ($Results.Count) {
                    $Results | Sort-Object TypeName, MemberType, Name
                }
            } else {
                # If '-Private' is not set, return the results of the original Get-Member cmdlet
                $out | Sort-Object TypeName, MemberType, Name
            }
        } catch {
        }
    }
}

