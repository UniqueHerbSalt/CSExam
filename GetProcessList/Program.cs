using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace GetProcessList
{
    class Program
    {
        static void Main(string[] args)
        {
            #region WInAPIMarshal을 이용한 방식
            var p = new ProcessWMI();
            //p.Privilege_Up();
            foreach (var info in p.GetProcessList())
            {
                Console.WriteLine($"ProcessName = {info.ProcessNameWithExtension}, Path = {info.ProcessPath}");
            }
            #endregion

            var a = p.GetProcessList();


            //Console.WriteLine(a.Where(pp => pp.ProcessNameWithExtension.IndexOf("winlogon.exe") != -1).Count());

        }
    }
    public class ProcessInfo
    {
        public string ProcessNameWithExtension { set; get; }
        public string ProcessPath { set; get; }
        public int SessionId { set; get; }
    }
    public class ProcessWINAPIMarshal
    {
        #region Win32 API Marshal
        private static uint STILL_ACTIVE = 0x00000103;
        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal UInt32 th32ModuleID;
            internal UInt32 cntThreads;
            internal UInt32 th32ParentProcessID;
            internal Int32 pcPriClassBase;
            internal UInt32 dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }
        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MODULEENTRY32
        {
            const int MAX_PATH = 260;
            internal UInt32 dwSize;
            internal UInt32 th32ModuleID;
            internal UInt32 th32ProcessID;
            internal UInt32 GlblcntUsage;
            internal UInt32 ProccntUsage;
            internal Byte modBaseAddr;
            internal UInt32 modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH - 4)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExePath;
        }
        [DllImport("kernel32.dll")]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);
        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle([In] IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern bool QueryFullProcessImageName(IntPtr hprocess, int dwFlags, StringBuilder lpExeName, out int size);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

        internal static int INVALID_HANDLE_VALUE = -1;
        internal const uint TH32CS_SNAPPROCESS = 0x00000002;
        internal const uint MAXIMUM_ALLOWED = 0x2000000;

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        internal const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        internal const string SE_DEBUG_NAME = "SeDebugPrivilege";
        internal const string SE_TCB_NAME = "SeTcbPrivilege";
        internal const int EWX_LOGOFF = 0x00000000;
        internal const int EWX_SHUTDOWN = 0x00000001;
        internal const int EWX_REBOOT = 0x00000002;
        internal const int EWX_FORCE = 0x00000004;
        internal const int EWX_POWEROFF = 0x00000008;
        internal const int EWX_FORCEIFHUNG = 0x00000010;

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupPrivilegeValue(IntPtr lpSystemName, string lpname, [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        internal struct TokPriv1Luid
        {
            public int Count;
            public LUID Luid;
            public int Attr;
        }

        [DllImport("kernel32.dll")]
        static extern uint WTSGetActiveConsoleSessionId();
        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            internal int PrivilegeCount;
            //LUID_AND_ATRIBUTES
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            internal int[] Privileges;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public int LowPart;
            public int HighPart;
        }//end struct

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATRIBUTES
        {
            public LUID Luid;
            public int Attributes;
        }//end struct

        private const int READ_CONTROL = 0x00020000;

        private const int STANDARD_RIGHTS_READ = READ_CONTROL;
        private const int STANDARD_RIGHTS_WRITE = READ_CONTROL;
        private const int STANDARD_RIGHTS_EXECUTE = READ_CONTROL;
        private const int STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        private const int TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const int TOKEN_DUPLICATE = 0x0002;
        private const int TOKEN_IMPERSONATE = 0x0004;
        private const int TOKEN_QUERY_SOURCE = 0x0010;
        private const int TOKEN_ADJUST_GROUPS = 0x0040;
        private const int TOKEN_ADJUST_DEFAULT = 0x0080;
        private const int TOKEN_ADJUST_SESSIONID = 0x0100;

        private const int TOKEN_ALL_ACCESS_P = (STANDARD_RIGHTS_REQUIRED |
                                        TOKEN_ASSIGN_PRIMARY |
                                        TOKEN_DUPLICATE |
                                        TOKEN_IMPERSONATE |
                                        TOKEN_QUERY |
                                        TOKEN_QUERY_SOURCE |
                                        TOKEN_ADJUST_PRIVILEGES |
                                        TOKEN_ADJUST_GROUPS |
                                        TOKEN_ADJUST_DEFAULT);
        private const int TOKEN_ALL_ACCESS = TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID;
        private const int TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
        private const int TOKEN_WRITE = STANDARD_RIGHTS_WRITE |
                                        TOKEN_ADJUST_PRIVILEGES |
                                        TOKEN_ADJUST_GROUPS |
                                        TOKEN_ADJUST_DEFAULT;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }
        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        private extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType,
            int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

        private enum SECURITY_IMPERSONATION_LEVEL : int
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        private enum TOKEN_TYPE : int
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }
        private enum TOKEN_INFORMATION_CLASS : int
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            MaxTokenInfoClass  // MaxTokenInfoClass should always be the last enum
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, uint TokenInformation, uint TokenInformationLength);

        private const int ERROR_NOT_ALL_ASSIGNED = 1300;
        private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        private extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
            String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        #endregion
        public void Privilege_Up()
        {
            bool ok;
            TokPriv1Luid tp;
            IntPtr htok = IntPtr.Zero;
            ok = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);

            tp.Count = 1;
            tp.Luid = new LUID();
            tp.Attr = SE_PRIVILEGE_ENABLED;

            ok = LookupPrivilegeValue(IntPtr.Zero, SE_DEBUG_NAME, ref tp.Luid);
            ok = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(htok);
        }
        public List<ProcessInfo> GetProcessList()
        {
            var list = new List<ProcessInfo>();
            // Find the winlogon process
            PROCESSENTRY32 procEntry = new PROCESSENTRY32();
            MODULEENTRY32 lpme = new MODULEENTRY32();
            IntPtr hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap == IntPtr.Zero)
            {
                return null;
            }

            procEntry.dwSize = (uint)Marshal.SizeOf(procEntry); //sizeof(PROCESSENTRY32);

            if (!Process32First(hSnap, ref procEntry))
            {
                CloseHandle(hSnap);
                return null;
            }

            do
            {
                if (Environment.OSVersion.Version.Major.Equals(5))
                {
                    var pi = new ProcessInfo();
                    IntPtr hsnap_module = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procEntry.th32ProcessID);
                    Module32First(hSnap, ref lpme);
                    pi.ProcessNameWithExtension = procEntry.szExeFile;
                    pi.ProcessPath = lpme.szExePath;
                    CloseHandle(hsnap_module);
                    list.Add(pi);
                }
                else
                {
                    StringBuilder sb = new StringBuilder(1024);

                    IntPtr openprocesshandle = OpenProcess(MAXIMUM_ALLOWED, false, procEntry.th32ProcessID);
                    try
                    {
                        int size = sb.Capacity;

                        if (QueryFullProcessImageName(openprocesshandle, 0, sb, out size))
                        {
                            var pi = new ProcessInfo();
                            string fullPath = sb.ToString();
                            pi.ProcessNameWithExtension = procEntry.szExeFile;
                            pi.ProcessPath = fullPath;
                            list.Add(pi);
                        }
                    }
                    finally
                    {
                        CloseHandle(openprocesshandle);
                    }
                }
            } while (Process32Next(hSnap, ref procEntry));
            CloseHandle(hSnap);
            return list;
        }
        public bool CreateProcessInConsoleSession(string CommandLine, int sessionID, bool bElevate = true) //서비스 모드에서만 사용 가능
        {
            var pWmi = new ProcessWMI();
            bool findwinlogon = false;
            bool bResult = false;
            uint dwSessionId, winlogonPid = 0;
            IntPtr hUserTokenDup = IntPtr.Zero, hPToken = IntPtr.Zero, hProcess = IntPtr.Zero;

            if (sessionID != -1)
            {
                dwSessionId = (uint)sessionID;
            }
            else
            {
                // Log the client on to the local computer.
                dwSessionId = WTSGetActiveConsoleSessionId();
            }
            var getProcessList = pWmi.GetProcessList();
            findwinlogon = getProcessList.Where(p => p.ProcessNameWithExtension.ToLower().Equals("winlogon.exe")).Count() != 0;
            if (findwinlogon)
            {
                winlogonPid = (uint)(getProcessList.Where(p => p.ProcessNameWithExtension.ToLower().Equals("winlogon.exe")).First().SessionId);
                Debug.WriteLine("winlogonPid = " + winlogonPid.ToString());
                STARTUPINFO si = new STARTUPINFO();
                si.cb = (int)Marshal.SizeOf(si);
                //si.lpDesktop = "winsta0\\default";
                si.lpDesktop = "winsta0\\default";
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                LUID luid = new LUID();
                hProcess = OpenProcess(MAXIMUM_ALLOWED, false, winlogonPid);

                if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
                                                | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE, ref hPToken))
                {
                    Debug.WriteLine(String.Format("CreateProcessInConsoleSession OpenProcessToken error: {0}", Marshal.GetLastWin32Error()));
                }

                if (!LookupPrivilegeValue(IntPtr.Zero, SE_TCB_NAME/*SE_DEBUG_NAME*/, ref luid))
                {
                    Debug.WriteLine(String.Format("CreateProcessInConsoleSession LookupPrivilegeValue error: {0}", Marshal.GetLastWin32Error()));
                }

                tp.PrivilegeCount = 1;
                tp.Privileges = new int[3];
                tp.Privileges[2] = SE_PRIVILEGE_ENABLED;
                tp.Privileges[1] = luid.HighPart;
                tp.Privileges[0] = luid.LowPart;

                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.Length = Marshal.SizeOf(sa);

                if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa, (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int)TOKEN_TYPE.TokenPrimary, ref hUserTokenDup))
                {
                    Debug.WriteLine(String.Format("CreateProcessInConsoleSession DuplicateTokenEx error: {0} Token does not have the privilege.", Marshal.GetLastWin32Error()));
                    CloseHandle(hProcess);
                    CloseHandle(hPToken);
                    return false;
                }

                if (bElevate)
                {
                    //tp.Privileges[0].Luid = luid;
                    //tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    tp.PrivilegeCount = 1;
                    tp.Privileges = new int[3];
                    tp.Privileges[2] = SE_PRIVILEGE_ENABLED;
                    tp.Privileges[1] = luid.HighPart;
                    tp.Privileges[0] = luid.LowPart;

                    //Adjust Token privilege
                    if (!SetTokenInformation(hUserTokenDup, TOKEN_INFORMATION_CLASS.TokenSessionId, dwSessionId, (uint)IntPtr.Size))
                    {
                        Debug.WriteLine(String.Format("CreateProcessInConsoleSession SetTokenInformation error: {0} Token does not have the privilege.", Marshal.GetLastWin32Error()));
                        //yCloseHandle(hProcess);
                        //CloseHandle(hPToken);
                        //CloseHandle(hUserTokenDup);
                        //return false;
                    }
                    if (!AdjustTokenPrivileges(hUserTokenDup, false, ref tp, Marshal.SizeOf(tp), /*(PTOKEN_PRIVILEGES)*/IntPtr.Zero, IntPtr.Zero))
                    {
                        int nErr = Marshal.GetLastWin32Error();

                        if (nErr == ERROR_NOT_ALL_ASSIGNED)
                        {
                            Debug.WriteLine(String.Format("CreateProcessInConsoleSession AdjustTokenPrivileges error: {0} Token does not have the privilege.", nErr));
                        }
                        else
                        {
                            Debug.WriteLine(String.Format("CreateProcessInConsoleSession AdjustTokenPrivileges error: {0}", nErr));
                        }
                    }
                }

                uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;//NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
                IntPtr pEnv = IntPtr.Zero;
                if (CreateEnvironmentBlock(ref pEnv, hUserTokenDup, true))
                {
                    //dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
                }
                else
                {
                    pEnv = IntPtr.Zero;
                }
                PROCESS_INFORMATION pi;
                // Launch the process in the client's logon session.
                bResult = CreateProcessAsUser(hUserTokenDup,          // client's access token
                                                null,                   // file to execute
                                                CommandLine,            // command line
                                                ref sa,                 // pointer to process SECURITY_ATTRIBUTES
                                                ref sa,                 // pointer to thread SECURITY_ATTRIBUTES
                                                false,                  // handles are not inheritable
                                                (int)dwCreationFlags,   // creation flags
                                                pEnv,                   // pointer to new environment block 
                                                null,                   // name of current directory 
                                                ref si,                 // pointer to STARTUPINFO structure
                                                out pi                  // receives information about new process
                                                );
                // End impersonation of client.

                //GetLastError should be 0
                int iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();

                //Close handles task
                CloseHandle(hProcess);
                CloseHandle(hUserTokenDup);
                CloseHandle(hPToken);

                return (iResultOfCreateProcessAsUser == 0) ? true : false;
            }
            else
            {
                ProcessStartInfo proc = new ProcessStartInfo
                {
                    UseShellExecute = true,
                    FileName = CommandLine,
                    Verb = "runas",
                };
                Process.Start(proc);
                return true;
            }
        }
    }
    public class ProcessWMI
    {
        public List<ProcessInfo> GetProcessList()
        {
            var list = new List<ProcessInfo>();
            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher("root\\CIMV2",
                    "SELECT Caption, ExecutablePath, ProcessId, SessionId FROM Win32_Process");

                foreach (ManagementObject queryObj in searcher.Get())
                {
                    try
                    {
                        var Caption = queryObj["Caption"].ToString();
                        var ExecutablePath = queryObj["ExecutablePath"].ToString();
                        var SessionId = Convert.ToInt32(queryObj["SessionId"]);

                        if (ExecutablePath.Length != 0)
                        {
                            var pi = new ProcessInfo();
                            pi.ProcessNameWithExtension = Caption;
                            pi.ProcessPath = ExecutablePath;
                            pi.SessionId = SessionId;
                            list.Add(pi);
                        }
                    }
                    catch { }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            return list;
        }
    }

}
