using System;
using System.Collections.Generic;
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
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }
        #endregion
        public void Privilege_Up()
        {
            bool ok;
            TokPriv1Luid tp;
            IntPtr htok = IntPtr.Zero;
            ok = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);

            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;

            ok = LookupPrivilegeValue(null, SE_DEBUG_NAME, ref tp.Luid);
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

                        if (ExecutablePath.Length != 0)
                        {
                            var pi = new ProcessInfo();
                            pi.ProcessNameWithExtension = Caption;
                            pi.ProcessPath = ExecutablePath;
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
