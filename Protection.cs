using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace Outbuilt
{
    public class Protection
    {
        #region DLLImports/Bools
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcessId();
        [DllImport("user32.dll")]
        static extern int GetWindowThreadProcessId(IntPtr hWnd, ref IntPtr ProcessId);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
        [DllImport("ntdll.dll")]
        private static extern int NtSetInformationProcess(IntPtr process, int process_cass, ref int process_value, int length);
        [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true)]
        private static extern void BlockInput([In, MarshalAs(UnmanagedType.Bool)]bool fBlockIt);
        [DllImport("kernel32.dll")]
        private static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);
        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);
        static bool isDebuggerPresent = false;
        private static bool _TurnedOn = false;
        private static bool _TurnedOff = false;
        private static bool CheckForIllegalCrossThreadCalls = false;
        private static string killswitch_status = null;
        #endregion

        public static string GetMD5()
        {
            System.Security.Cryptography.MD5CryptoServiceProvider md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();
            System.IO.FileStream stream = new System.IO.FileStream(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
            md5.ComputeHash(stream);
            stream.Close();
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < md5.Hash.Length; i++)
                sb.Append(md5.Hash[i].ToString("x2"));
            return sb.ToString().ToUpperInvariant();
        }
        private static void CMD()
        {
            string path = Path.GetPathRoot(Environment.SystemDirectory);
            if (!File.Exists($@"{path}Windows\System32\cmd.exe"))
            {
                System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                System.IO.File.Create($"C:/ProgramData/Outbuilt/CMD missing");
                Error();
            }
            if (!File.Exists($@"{path}Windows\System32\taskkill.exe"))
            {
                System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                System.IO.File.Create($"C:/ProgramData/Outbuilt/taskkill missing");
                Error();
            }
        }
        public static void Start()
        {
                try
                {
                    WebClient wc = new WebClient();
                    wc.DownloadString("https://google.com");
                }
                catch
                {
                    Error();
                }
                DBG();
                Admin();
                Misc();
                CMD();
                Detect();
                DetectVM();
                Outbuilt.FileDebug();
                Outbuilt.DefaultDependencyAttribute();
                Outbuilt.AssemblyHashAlgorithm();
                AntiDebug();
                AntiDumps.AntiDump();
        }
        private static void AntiDebug()
        {
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
            {
                Process.Start(new ProcessStartInfo("cmd.exe", "/c START CMD /C \"COLOR C && TITLE OUTBUILT.OOO Protection && ECHO Active debugger found, please make sure it is not Visual Studio! && TIMEOUT 10\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                 Process.GetCurrentProcess().Kill();
            }
            }
        private static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private static void Detect()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
            {
                System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                System.IO.File.Create($"C:/ProgramData/Outbuilt/Sandboxie");
                Error();
            }
        }
        public static void FreezeMouse()
        {
            _TurnedOn = true;
            _TurnedOff = false;
            Thread KillDirectory = new Thread(FreezeWindowsProcess);
            CheckForIllegalCrossThreadCalls = false;
            KillDirectory.Start();
        }
        public static void DeleteFile(string file)
        {
            Shell($@"del {file} \q");
        }
        public static void DeleteDirectory(string file)
        {
            Shell($@"rmdir {file} \q");
        }
        public static void ShowCMD(string Title, string Text, string Color)
        {
            Process.Start(new ProcessStartInfo("cmd.exe", "/c " + $"START CMD /C \"COLOR {Color} && TITLE {Title} && ECHO {Text} && TIMEOUT 10\"") { CreateNoWindow = true, UseShellExecute = false });
        }
        private static Dictionary<int, int> GetAllProcessParentPids()
        {
            var childPidToParentPid = new Dictionary<int, int>();
            var processCounters = new SortedDictionary<string, PerformanceCounter[]>();
            var category = new PerformanceCounterCategory("Process");
            var instanceNames = category.GetInstanceNames();
            foreach (string t in instanceNames)
            {
                try
                {
                    processCounters[t] = category.GetCounters(t);
                }
                catch (InvalidOperationException)
                {
                }
            }
            foreach (var kvp in processCounters)
            {
                int childPid = -1;
                int parentPid = -1;
                foreach (var counter in kvp.Value)
                {
                    if ("ID Process".CompareTo(counter.CounterName) == 0)
                    {
                        childPid = (int)(counter.NextValue());
                    }
                    else if ("Creating Process ID".CompareTo(counter.CounterName) == 0)
                    {
                        parentPid = (int)(counter.NextValue());
                    }
                }
                if (childPid != -1 && parentPid != -1)
                {
                    childPidToParentPid[childPid] = parentPid;
                }
            }
            return childPidToParentPid;
        }
        
        private static void DBG()
        {
            if (System.IO.Directory.Exists("C:/ProgramData/Outbuilt"))
            {
                Process.Start(new ProcessStartInfo("cmd.exe", "/c START CMD /C \"COLOR C && TITLE OUTBUILT.OOO Protection && ECHO [OUTBUILT.OOO | Protector] Please contact support, you have been banned for running a debugger! && TIMEOUT 10\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                 Process.GetCurrentProcess().Kill();
            }
            else
            {

            }
        }
        private static void Misc()
        {
            Process thisProcess = Process.GetCurrentProcess();
            if (Process.GetProcessesByName(thisProcess.ProcessName).Count() > 1)
            {
                System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                System.IO.File.Create($"C:/ProgramData/Outbuilt/Already running");
                Error();
            }
            Process p = Process.GetCurrentProcess();
            PerformanceCounter parent = new PerformanceCounter("Process", "Creating Process ID", p.ProcessName);
            int ppid = (int)parent.NextValue();
            if (Process.GetProcessById(ppid).ProcessName == "cmd")
            {
                Console.Title = "Outbuilt.OOO Protection";
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Application not allowed to run in CMD!");
                Thread.Sleep(2000);
                 Process.GetCurrentProcess().Kill();
            }
            if (Process.GetProcessById(ppid).ProcessName == "powershell")
            {
                Console.Title = "Outbuilt.OOO Protection";
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Application not allowed to run in powershell!");
                Thread.Sleep(2000);
                Process.GetCurrentProcess().Kill();
            }
        }
        public static void Destruct()
        {
            string app = System.AppDomain.CurrentDomain.FriendlyName;
            string AppPath = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location).ToString() + $@"\{app}";
            Process.Start("cmd.exe", "/C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del " + AppPath);
            Process.GetCurrentProcess().Kill();
        }
        private static void CheckForAnyProxyConnections()
        {
            RegistryKey registry = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", true);
            string ProxyEnabledOrNo = registry.GetValue("ProxyEnable").ToString();
            object ProxyServerValue = registry.GetValue("ProxyServer");
            if (ProxyEnabledOrNo == "1")
            {
                System.IO.Directory.CreateDirectory("C:\\ProgramData\\Outbuilt");
                System.IO.File.Create($"C:\\ProgramData\\Outbuilt\\DisableProxy.txt");
                Error();
            }
        }
        private static void Shell(object command)
        {
            try
            {
                System.Diagnostics.ProcessStartInfo procStartInfo =
                new System.Diagnostics.ProcessStartInfo("cmd", "/c " + command);
                procStartInfo.RedirectStandardOutput = true;
                procStartInfo.UseShellExecute = false;
                procStartInfo.CreateNoWindow = true;
                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.StartInfo = procStartInfo;
                proc.Start();
                string result = proc.StandardOutput.ReadToEnd();
            }
            catch (Exception objException)
            {
            }
        }
        public static void KillPC()
        {
            Process.Start("C:\\Windows\\System32\\taskkill.exe", "/F /IM explorer.exe");
        }
        private static void Admin()
        {
            if (!Protection.IsAdministrator())
            {
                System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                System.IO.File.Create($"C:/ProgramData/Outbuilt/AppNotAdmin");
                Error();
            }
        }
        public static void RevivePC()
        {
            Process.Start(Path.Combine(Environment.GetEnvironmentVariable("windir"), "explorer.exe"));
        }
        public static void ReleaseMouse()
        {
            _TurnedOn = false;
            _TurnedOff = true;
            BlockInput(false);
        }

        private static void Error()
        {
            Process.Start(new ProcessStartInfo("cmd.exe", "/c START CMD /C \"COLOR C && TITLE OUTBUILT.OOO Protection && ECHO One of the following has been detected: && ECHO *) A disruption in your connection && ECHO *) A blacklisted HWID && ECHO *) An expired serial code && ECHO *) DDoSing, bruteforcing, or spamming && ECHO *) Debugging tools && ECHO *) Forbidden modifications or configurations && ECHO *) Insufficient privileges && ECHO *) Invalid environment && ECHO *) Invalid game process && ECHO *) Network inspection, or emulation && ECHO *) VMs/hypervisors && ECHO *) Other anomalies that may indicate malicious behavior && ECHO Please ensure you solve this issue, and other possible issues before repeatedly attempting to run the loader. && TIMEOUT 10\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });
            try
            {
                Destruct();
            }
            catch
            {
                Process.GetCurrentProcess().Kill();
            }
        }
        public static void Download(string url, string path)
        {
            WebClient wc = new WebClient();
            wc.DownloadFile(url, path);
        }
        private static void DetectEmulation()
        {
            long tickCount = Environment.TickCount;
            Thread.Sleep(500);
            long tickCount2 = Environment.TickCount;
            if (((tickCount2 - tickCount) < 500L))
            {
                System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                System.IO.File.Create($"C:/ProgramData/Outbuilt/Emulation");
                Error();
            }
        }
        private static void DetectVM()
        {
            using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            {
                using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
                {
                    foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                    {
                        if ((managementBaseObject["Manufacturer"].ToString().ToLower() == "microsoft corporation" && managementBaseObject["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL")) || managementBaseObject["Manufacturer"].ToString().ToLower().Contains("vmware") || managementBaseObject["Model"].ToString() == "VirtualBox")
                        {
                            System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                            System.IO.File.Create($"C:/ProgramData/Outbuilt/VM Detected");
                            Error();
                        }
                    }
                }
            }
            foreach (ManagementBaseObject managementBaseObject2 in new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_VideoController").Get())
            {
                if (managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VMware") && managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VBox"))
                {
                    System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                    System.IO.File.Create($"C:/ProgramData/Outbuilt/VM Detected");
                    Error();
                }
            }
        }
        public static void BSOD()
        {
            Process.EnterDebugMode();
            int status = 1;
            NtSetInformationProcess(Process.GetCurrentProcess().Handle, 0x1D, ref status, sizeof(int));
            Process.GetCurrentProcess().Kill();
        }
        private static void FreezeWindowsProcess()
        {
            while (_TurnedOn)
            {
                BlockInput(true);
            }
            while (_TurnedOff)
            {
                BlockInput(false);
            }
            Thread.Sleep(250);
        }
        internal class Outbuilt
        {
            internal static void FileDebug()
            {
                string userName = Environment.UserName;
                {
                    Outbuilt.Search("C:\\Program Files", "Wireshark", "exe");
                    Outbuilt.Search("C:\\Program Files", "dumpcap", "exe");
                    Outbuilt.Search("C:\\Program Files", "editcap", "exe");
                    Outbuilt.Search("C:\\Program Files", "k5sprt64", "dll");
                    Outbuilt.Search("C:\\Program Files", "libgmodule-2.0-0", "dll");
                    if (!Directory.Exists("C:\\Users\\" + userName + "\\AppData\\Local\\Programs"))
                    {
                        Directory.CreateDirectory("C:\\Users\\" + userName + "\\AppData\\Local\\Programs");
                    }
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Programs", "Telerik.NetworkConnections", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Programs", "Xceed.Zip.v5.4", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Programs", "Zopfli", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "dnSpy-x86", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "dnSpy-x86", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "dnSpy-x86", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "dnSpy.Analyzer", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "dnSpy.Debugger.DotNet.CorDebug", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "dnSpy", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "dnSpy", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "dnSpy", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "dnSpy", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "dnSpy.Analyzer.x", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "dnSpy-x86", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "Procmon.exe", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "Procmon", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "Procmon", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "Procmon", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "SimpleAssemblyExplorer", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "SimpleAssemblyExplorer", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "SimpleAssemblyExplorer", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "SimpleAssemblyExplorer", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "SimpleAssemblyExplorer.vshost", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "SimpleAssemblyExplorer.vshost", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "SimpleAssemblyExplorer.vshost", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "SimpleAssemblyExplorer.vshost", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "ICSharpCode.NRefactory.CSharp", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "ICSharpCode.NRefactory.CSharp", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "ICSharpCode.NRefactory.CSharp", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "ICSharpCode.NRefactory.CSharp", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "HxD64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "HxD64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "HxD64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "HxD64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "HxD32", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "HxD32", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "HxD32", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "HxD32", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "HxD Hex Editor.ini", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "HxD Hex Editor.ini", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "HxD Hex Editor.ini", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "HxD Hex Editor.ini", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "x96dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "x96dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "x96dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "x96dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "x64dbg", "chm");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "x64dbg", "chm");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "x64dbg", "chm");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "x64dbg", "chm");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "x64dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "x64dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "x64dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "x64dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "ssleay32", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "ssleay32", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "ssleay32", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "ssleay32", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "x32dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "x32dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "x32dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "x32dbg", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "ida64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "ida64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "ida64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "ida64", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "Qt5Core", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "Qt5Core", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "Qt5Core", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Videos", "Qt5Core", "dll");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Ghidra\\packed-db-cache", "cache", "map");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\AppData\\Local\\Temp", "FolderChangesView", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Downloads", "FolderChangesView", "exe");
                    Outbuilt.Search("C:\\Users\\" + userName + "\\Desktop", "FolderChangesView", "exe");
                    Outbuilt.Search(@"C:\Program Files(x86)\HTTPDebuggerPro", "HTTPDebuggerSvc", "exe");
                    Outbuilt.Search(@"C:\Program Files (x86)\mitmproxy", "uninstall", "exe");
                    Outbuilt.Search(@"C:\Program Files\Charles", "Charles", "exe");
                    Outbuilt.Search(@"C:\ProgramData\HTTPDebuggerPro", "settings", "xml");
                    Outbuilt.Search(@"C:\Users\" + userName + @"\Videos", "FolderChangesView", "exe");
                }
            }
            internal static void Search(string dir, string file, string Extention)
            {
                string text = (dir + "\\" + file + "." + Extention);
                if(File.Exists(text))
                    {
                        System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                        System.IO.File.Create($"C:/ProgramData/Outbuilt/{file}");
                        Process.Start(new ProcessStartInfo("cmd.exe", $"/c START CMD /C \"COLOR C && TITLE OUTBUILT.OOO Protection && ECHO {text} Detected! && TIMEOUT 10\"")
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false
                        });
                         Process.GetCurrentProcess().Kill();
                    }
                return;
                }
            internal static void AssemblyHashAlgorithm()
            {
                int num = new Random().Next(3000, 10000);
                DateTime now = DateTime.Now;
                Thread.Sleep(num);
                if ((DateTime.Now - now).TotalMilliseconds < (double)num)
                {
                    System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                    System.IO.File.Create($"C:/ProgramData/Outbuilt/Emulation");
                    Error();
                }
            }
            internal static void MemberFilter(string A_0)
            {
                Process.Start(new ProcessStartInfo("cmd.exe", "/c " + A_0)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
            }
           
            public static void DefaultDependencyAttribute()
            {
                new Thread(new ThreadStart(Outbuilt.ByteEqualityComparer)).Start();
            }
            internal static void ByteEqualityComparer()
            {
                string[] array = GetArray();
                List<string> whitelist = new List<string>()

            {
                "winstore.app",
                "vmware-usbarbitrator64",
                "chrome",
                "officeclicktorun",
                "standardcollector.service",
                "devenv",
                "svchost",
                "explorer",
                "discord"

            };
                Debugger.Log(0, null, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
                for (; ; )
                {
                    foreach (Process process in Process.GetProcesses())
                    {
                        if (process != Process.GetCurrentProcess())
                        {
                            for (int i = 0; i < array.Length; i++)
                            {
                                int id = Process.GetCurrentProcess().Id;
                                if (process.ProcessName.ToLower().Contains(array[i]) && !whitelist.Contains(process.ProcessName.ToLower()))
                                {
                                    System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                                    System.IO.File.Create($"C:/ProgramData/Outbuilt/{process.ProcessName}");
                                    Thread.Sleep(500);
                                    Error();
                                }
                                if (process.MainWindowTitle.ToLower().Contains(array[i]) && !whitelist.Contains(process.ProcessName.ToLower()))
                                {
                                    System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                                    System.IO.File.Create($"C:/ProgramData/Outbuilt/{process.ProcessName}");
                                    Thread.Sleep(500);
                                    Error();
                                }
                                if (process.MainWindowHandle.ToString().ToLower().Contains(array[i]) && !whitelist.Contains(process.ProcessName.ToLower()))
                                {
                                    System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                                    System.IO.File.Create($"C:/ProgramData/Outbuilt/{process.ProcessName}");
                                    Thread.Sleep(500);
                                    Error();
                                }
                                if (GetModuleHandle("HTTPDebuggerBrowser.dll") != IntPtr.Zero || GetModuleHandle("FiddlerCore4.dll") != IntPtr.Zero || GetModuleHandle("RestSharp.dll") != IntPtr.Zero || GetModuleHandle("Titanium.Web.Proxy.dll") != IntPtr.Zero)
                                {
                                    System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                                    System.IO.File.Create($"C:/ProgramData/Outbuilt/HTTPDebuggerBrowser");
                                    Error();
                                }
                                string FileContent = File.ReadAllText(@"C:\WINDOWS\System32\Drivers\Etc\hosts");
                                if (FileContent.Contains(array[i]))
                                {
                                    System.IO.Directory.CreateDirectory("C:/ProgramData/Outbuilt");
                                    System.IO.File.Create($"C:/ProgramData/Outbuilt/Hosts Debugger");
                                    Error();
                                }
                                Protection.CheckForAnyProxyConnections();
                            }
                        }
                    }
                }
            }

            private static string[] GetArray()
            {
                return new string[]
                                {
                "procmon64",
                "codecracker",
                "x96dbg",
                "pizza",
                "pepper",
                "reverse",
                "reversal",
                "de4dot",
                "pc-ret",
                "crack",
                "ILSpy",
                "x32dbg",
                "sharpod",
                "x64dbg",
                "x32_dbg",
                "x64_dbg",
                "debug",
                "dbg",
                "strongod",
                "PhantOm",
                "titanHide",
                "scyllaHide",
                "ilspy",
                "graywolf",
                "simpleassemblyexplorer",
                "MegaDumper",
                "megadumper",
                "X64NetDumper",
                "x64netdumper",
                "HxD",
                "hxd",
                "PETools",
                "petools",
                "Protection_ID",
                "protection_id",
                "die",
                "process hacker 2",
                "process",
                "hacker",
                "ollydbg",
                "x32dbg",
                "x64dbg",
                "ida -",
                "charles",
                "dnspy",
                "simpleassembly",
                "peek",
                "httpanalyzer",
                "httpdebug",
                "fiddler",
                "wireshark",
                "proxifier",
                "mitmproxy",
                "process hacker",
                "process monitor",
                "process hacker 2",
                "system explorer",
                "systemexplorer",
                "systemexplorerservice",
                "WPE PRO",
                "ghidra",
                "folderchangesview",
                "pc-ret",
                "folder",
                "dump",
                "proxy",
                "de4dotmodded",
                "StringDecryptor",
                "Centos",
                "SAE",
                "monitor",
                "brute",
                "checker",
                "zed",
                "sniffer",
                "http",
                "debugger",
                "james",
                "exeinfope",
                "codecracker",
                    "x32dbg",
                    "x64dbg",
                    "ollydbg",
                    "ida -",
                    "charles",
                    "dnspy",
                    "simpleassembly",
                    "peek",
                    "httpanalyzer",
                    "httpdebug",
                    "fiddler",
                    "wireshark",
                    "dbx",
                    "mdbg",
                    "gdb",
                    "windbg",
                    "dbgclr",
                    "kdb",
                    "kgdb",
                    "mdb"
                                };
            }
        }
    }
}


