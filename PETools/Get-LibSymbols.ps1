function Get-LibSymbols
{
<#
.SYNOPSIS

    Displays symbolic information from Windows lib files.

    PowerSploit Function: Get-LibSymbols
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.DESCRIPTION

    Get-LibSymbols parses and returns symbols in Windows .lib files
    in both decorated and undecorated form (for C++ functions).

.PARAMETER Path

    Specifies a path to one or more lib file locations.

.EXAMPLE

    C:\PS>Get-LibSymbols -Path msvcrt.lib

.EXAMPLE

    C:\PS>ls *.lib | Get-LibSymbols

.INPUTS

    System.String[]

    You can pipe a file system path (in quotation marks) to Get-LibSymbols.

.OUTPUTS

    COFF.SymbolInfo

.LINK

    http://www.exploit-monday.com/
#>
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateScript({ Test-Path $_ })]
        [Alias('FullName')]
        [String[]]
        $Path
    )

    BEGIN
    {
        $Code = @'
        using System;
        using System.IO;
        using System.Text;
        using System.Runtime.InteropServices;

        namespace COFF
        {
            public class HEADER
	        {
		        public ushort Machine;
		        public ushort NumberOfSections;
		        public DateTime TimeDateStamp;
		        public uint PointerToSymbolTable;
		        public uint NumberOfSymbols;
		        public ushort SizeOfOptionalHeader;
		        public ushort Characteristics;

                public HEADER(BinaryReader br)
                {
                    this.Machine = br.ReadUInt16();
                    this.NumberOfSections = br.ReadUInt16();
                    this.TimeDateStamp = (new DateTime(1970, 1, 1, 0, 0, 0)).AddSeconds(br.ReadUInt32());
                    this.PointerToSymbolTable = br.ReadUInt32();
                    this.NumberOfSymbols = br.ReadUInt32();
                    this.SizeOfOptionalHeader = br.ReadUInt16();
                    this.Characteristics = br.ReadUInt16();
                }
	        }

            public class IMAGE_ARCHIVE_MEMBER_HEADER
            {
                public string Name;
                public DateTime Date;
                public ulong Size;
                public string EndHeader;

                public IMAGE_ARCHIVE_MEMBER_HEADER(BinaryReader br)
                {
                    string tempName = Encoding.UTF8.GetString(br.ReadBytes(16));
                    DateTime dt = new DateTime(1970, 1, 1, 0, 0, 0);
                    this.Name = tempName.Substring(0, tempName.IndexOf((Char) 47));
                    this.Date = dt.AddSeconds(Convert.ToDouble(Encoding.UTF8.GetString(br.ReadBytes(12)).Split((Char) 20)[0]));
                    br.ReadBytes(20); // Skip over UserID, GroupID, and Mode. They are useless fields.
                    this.Size = Convert.ToUInt64(Encoding.UTF8.GetString(br.ReadBytes(10)).Split((Char) 20)[0]);
                    this.EndHeader = Encoding.UTF8.GetString(br.ReadBytes(2));
                }
            }

            public class Functions
            {
                [DllImport("dbghelp.dll", SetLastError=true, PreserveSig=true)]
                public static extern int UnDecorateSymbolName(
                    [In] [MarshalAs(UnmanagedType.LPStr)] string DecoratedName,
                    [Out] StringBuilder UnDecoratedName,
                    [In] [MarshalAs(UnmanagedType.U4)] uint UndecoratedLength,
                    [In] [MarshalAs(UnmanagedType.U4)] uint Flags);
            }
        }
'@

        Add-Type -TypeDefinition $Code

        function Dispose-Objects
        {
            $BinaryReader.Close()
            $FileStream.Dispose()
        }
    }

    PROCESS
    {
        foreach ($File in $Path)
        {
            # Resolve the absolute path of the lib file. [IO.File]::OpenRead requires an absolute path.
            $LibFilePath = Resolve-Path $File

            # Pull out just the file name
            $LibFileName = Split-Path $LibFilePath -Leaf

            $IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR = 60
            $IMAGE_ARCHIVE_START = "!<arch>`n" # Magic used for lib files
            $IMAGE_SIZEOF_LIB_HDR = $IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR + $IMAGE_ARCHIVE_START.Length
            $IMAGE_ARCHIVE_END = "```n" # Footer of an archive header
            $SizeofCOFFFileHeader = 20

            # Open the object file for reading
            $FileStream = [IO.File]::OpenRead($LibFilePath)

            $FileLength = $FileStream.Length

            # Validate lib header size
            if ($FileLength -lt $IMAGE_SIZEOF_LIB_HDR)
            {
                # You cannot parse the lib header if the file is not big enough to contain a lib header.
                Write-Error "$($LibFileName) is too small to store a lib header."
                $FileStream.Dispose()
                return
            }

            # Open a BinaryReader object for the lib file
            $BinaryReader = New-Object IO.BinaryReader($FileStream)

            $ArchiveStart = [Text.Encoding]::UTF8.GetString($BinaryReader.ReadBytes(8))

            if ($ArchiveStart -ne $IMAGE_ARCHIVE_START)
            {
                Write-Error "$($LibFileName) does not contain a valid lib header."
                Dispose-Objects
                return
            }

            # Parse the first archive header
            $ArchiveHeader = New-Object COFF.IMAGE_ARCHIVE_MEMBER_HEADER($BinaryReader)

            if ($ArchiveHeader.EndHeader -ne $IMAGE_ARCHIVE_END)
            {
                Write-Error "$($LibFileName) does not contain a valid lib header."
                Dispose-Objects
                return
            }

            # Check for the existence of symbols
            if ($ArchiveHeader.Size -eq 0)
            {
                Write-Warning "$($LibFileName) contains no symbols."
                Dispose-Objects
                return
            }

            $NumberOfSymbols = $BinaryReader.ReadBytes(4)

            # The offsets in the first archive header of a Microsoft lib file are stored in big-endian format
            if ([BitConverter]::IsLittleEndian)
            {
                [Array]::Reverse($NumberOfSymbols)
            }

            $NumberOfSymbols = [BitConverter]::ToUInt32($NumberOfSymbols, 0)

            $SymbolOffsets = New-Object UInt32[]($NumberOfSymbols)

            foreach ($Offset in 0..($SymbolOffsets.Length - 1))
            {
                $SymbolOffset = $BinaryReader.ReadBytes(4)

                if ([BitConverter]::IsLittleEndian)
                {
                    [Array]::Reverse($SymbolOffset)
                }

                $SymbolOffsets[$Offset] = [BitConverter]::ToUInt32($SymbolOffset, 0)
            }

            $SymbolStringLength = $ArchiveHeader.Size + $IMAGE_SIZEOF_LIB_HDR - $FileStream.Position - 1
            # $SymbolStrings = [Text.Encoding]::UTF8.GetString($BinaryReader.ReadBytes($SymbolStringLength)).Split([Char] 0)

            # Write-Output $SymbolStrings

            # There will be many duplicate offset entries. Remove them.
            $SymbolOffsetsSorted = $SymbolOffsets | Sort-Object -Unique

            $SymbolOffsetsSorted | ForEach-Object {
                # Seek to the each repective offset in the file
                $FileStream.Seek($_, 'Begin') | Out-Null

                $ArchiveHeader = New-Object COFF.IMAGE_ARCHIVE_MEMBER_HEADER($BinaryReader)

                # This is not a true COFF header. It's the same size and mostly resembles a standard COFF header
                # but Microsoft placed a marker (0xFFFF) in the first WORD to indicate that the 'object file'
                # consists solely of the module name and symbol.
                $CoffHeader = New-Object COFF.HEADER($BinaryReader)

                # Check for 0xFFFF flag value
                if ($CoffHeader.NumberOfSections -eq [UInt16]::MaxValue)
                {
                    # Get the total length of the module and symbol name
                    $SymbolStringLength = $CoffHeader.NumberOfSymbols
                    $Symbols = [Text.Encoding]::UTF8.GetString($BinaryReader.ReadBytes($SymbolStringLength)).Split([Char] 0)

                    $DecoratedSymbol = $Symbols[0]
                    $UndecoratedSymbol = ''

                    # Default to a 'C' type symbol unless it starts with a '?'
                    $SymbolType = 'C'

                    # Is the symbol a C++ type?
                    if ($DecoratedSymbol.StartsWith('?'))
                    {
                        $StrBuilder = New-Object Text.Stringbuilder(512)
                        # Magically undecorated the convoluted C++ symbol into a proper C++ function definition
                        [COFF.Functions]::UnDecorateSymbolName($DecoratedSymbol, $StrBuilder, $StrBuilder.Capacity, 0) | Out-Null
                        $UndecoratedSymbol = $StrBuilder.ToString()
                        $SymbolType = 'C++'
                    }
                    else
                    {
                        if ($DecoratedSymbol[0] -eq '_' -or $DecoratedSymbol[0] -eq '@')
                        {
                            $UndecoratedSymbol = $DecoratedSymbol.Substring(1).Split('@')[0]
                        }
                        else
                        {
                            $UndecoratedSymbol = $DecoratedSymbol.Split('@')[0]
                        }
                    }

                    $SymInfo = @{
                        DecoratedName = $DecoratedSymbol
                        UndecoratedName = $UndecoratedSymbol
                        Module = $Symbols[1]
                        SymbolType = $SymbolType
                    }

                    $ParsedSymbol = New-Object PSObject -Property $SymInfo
                    $ParsedSymbol.PSObject.TypeNames[0] = 'COFF.SymbolInfo'

                    Write-Output $ParsedSymbol
                }
            }

            # Close file and binaryreader objects
            Dispose-Objects
        }
    }

    END {}
}