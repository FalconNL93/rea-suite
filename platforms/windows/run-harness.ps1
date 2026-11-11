<#
.SYNOPSIS
    The engine of `rea-suite run`: one bounded, observed run of a Windows program from a plan
    (plan.json, written by common/rea_suite/run_harness.py). Windows only.
.DESCRIPTION
    Starts the program suspended in a job object (or attaches to a running one), runs the plan's
    steps (wait, at, wait-window, focus, key, text, click, move, pad, capture, close), keeps the
    window in front, captures it, answers its message boxes, samples its process tree's modules
    and endpoints, and ends it: WM_CLOSE, then after the grace the job and every process seen is
    killed. Writes events.jsonl, samples.jsonl, captures\, pad.jsonl and engine.json into the
    plan's out folder; run_harness.py turns engine.json into report.json. Run it through
    `rea-suite run` rather than by hand.
.EXAMPLE
    pwsh -NoProfile -File platforms\windows\run-harness.ps1 -Plan work\run\20261111-120000\plan.json
.NOTES
    Input goes out only while the program's window is verified in front (GetForegroundWindow), so
    a key never lands in another program (an overlay, a Game Bar bar, a terminal). The process is
    per-monitor DPI aware, so client coordinates are the pixels of a capture.
#>
#Requires -Version 7
param([Parameter(Mandatory)][string]$Plan)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public static class RunHarness {
    // --- processes ------------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO { public int cb; public string reserved, desktop, title; public int x, y, w, h, xChars, yChars, fill, flags; public short show, reserved2; public IntPtr reserved3, stdIn, stdOut, stdErr; }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr process, thread; public int pid, tid; }
    [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_BASIC_LIMIT_INFORMATION { public long perProcessTime, perJobTime; public uint flags; public UIntPtr minWs, maxWs; public uint activeProcesses; public UIntPtr affinity; public uint priority, scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong a, b, c, d, e, f; }
    [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION { public JOBOBJECT_BASIC_LIMIT_INFORMATION basic; public IO_COUNTERS io; public UIntPtr processMemory, jobMemory, peakProcess, peakJob; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PROCESSENTRY32 { public int size, usage, pid; public IntPtr heap; public int module, threads, parent, priority, flags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string exe; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateJobObjectW(IntPtr sa, IntPtr name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int cls, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr job, int cls, IntPtr info, int size, IntPtr ret);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, int pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32 e);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32 e);
    [DllImport("psapi.dll", SetLastError = true)] static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, int size, out int needed, uint filter);
    [DllImport("psapi.dll", CharSet = CharSet.Unicode)] static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder name, int size);

    public static IntPtr Handle = IntPtr.Zero, Job = IntPtr.Zero;
    public static int Pid;

    // Starts the program suspended, puts it in a job that kills everything in it when the job
    // closes (also when this engine dies), then lets it run: nothing it starts escapes.
    public static string Launch(string commandLine, string cwd, IDictionary<string, string> env) {
        var vars = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables()) vars[(string)e.Key] = (string)e.Value;
        foreach (var e in env) vars[e.Key] = e.Value;
        var block = new StringBuilder();
        foreach (var e in vars) block.Append(e.Key).Append('=').Append(e.Value).Append('\0');
        block.Append('\0');
        IntPtr envPtr = Marshal.StringToHGlobalUni(block.ToString());
        try {
            var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;
            const uint CREATE_SUSPENDED = 0x4, CREATE_UNICODE_ENVIRONMENT = 0x400;
            if (!CreateProcessW(null, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, envPtr, cwd, ref si, out pi))
                throw new Exception("CreateProcess failed (error " + Marshal.GetLastWin32Error() + "): " + commandLine);
            Handle = pi.process; Pid = pi.pid;
            string jobNote = null;
            Job = CreateJobObjectW(IntPtr.Zero, IntPtr.Zero);
            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if (Job == IntPtr.Zero || !SetInformationJobObject(Job, 9, ref info, Marshal.SizeOf(info)) || !AssignProcessToJobObject(Job, Handle)) {
                jobNote = "no job object (" + Marshal.GetLastWin32Error() + "): only the processes seen are ended";
                if (Job != IntPtr.Zero) { CloseHandle(Job); Job = IntPtr.Zero; }
            }
            ResumeThread(pi.thread); CloseHandle(pi.thread);
            return jobNote;
        } finally { Marshal.FreeHGlobal(envPtr); }
    }

    public static void Attach(int pid) {
        Handle = OpenProcess(0x00100000 | 0x1000 | 0x0001, false, pid); // SYNCHRONIZE | QUERY_LIMITED | TERMINATE
        if (Handle == IntPtr.Zero) throw new Exception("OpenProcess " + pid + " failed (error " + Marshal.GetLastWin32Error() + ")");
        Pid = pid;
    }

    public static bool Exited() { return Handle == IntPtr.Zero || WaitForSingleObject(Handle, 0) == 0; }
    public static long? ExitCode() { uint code; return Exited() && GetExitCodeProcess(Handle, out code) ? (long?)code : null; }
    public static void KillJob() { if (Job != IntPtr.Zero) TerminateJobObject(Job, 1); }

    public static int[] JobPids() {
        if (Job == IntPtr.Zero) return new int[0];
        int size = 8 + 8 * 4096; IntPtr buf = Marshal.AllocHGlobal(size);
        try {
            if (!QueryInformationJobObject(Job, 3, buf, size, IntPtr.Zero)) return new int[0];
            int count = Marshal.ReadInt32(buf, 4); var pids = new int[count];
            for (int i = 0; i < count; i++) pids[i] = (int)Marshal.ReadIntPtr(buf, 8 + i * IntPtr.Size).ToInt64();
            return pids;
        } finally { Marshal.FreeHGlobal(buf); }
    }

    public class Proc { public int pid, parent; public string name; }

    public static List<Proc> Processes() {
        var list = new List<Proc>();
        IntPtr snap = CreateToolhelp32Snapshot(2, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return list;
        try {
            var e = new PROCESSENTRY32(); e.size = Marshal.SizeOf(e);
            for (bool ok = Process32FirstW(snap, ref e); ok; ok = Process32NextW(snap, ref e))
                list.Add(new Proc { pid = e.pid, parent = e.parent, name = e.exe });
        } finally { CloseHandle(snap); }
        return list;
    }

    // The program and everything below it: its descendants by parent id, and the job's members
    // (a grandchild whose parent already ended is still in the job).
    public static List<Proc> Tree() {
        var all = Processes(); var tree = new List<Proc>();
        var ids = new HashSet<int>(JobPids()); ids.Add(Pid);
        bool grew = true;
        while (grew) { grew = false; foreach (var p in all) if (!ids.Contains(p.pid) && ids.Contains(p.parent) && p.pid != p.parent) { ids.Add(p.pid); grew = true; } }
        foreach (var p in all) if (ids.Contains(p.pid)) tree.Add(p);
        return tree;
    }

    public static List<string> Modules(int pid) {
        var list = new List<string>();
        IntPtr h = OpenProcess(0x0400 | 0x0010, false, pid); // QUERY_INFORMATION | VM_READ
        if (h == IntPtr.Zero) return list;
        try {
            var mods = new IntPtr[2048]; int needed;
            // LIST_MODULES_ALL: a 32-bit game's own modules too, not only its WOW64 layer
            if (!EnumProcessModulesEx(h, mods, mods.Length * IntPtr.Size, out needed, 3)) return list;
            var name = new StringBuilder(1024);
            for (int i = 0; i < Math.Min(mods.Length, needed / IntPtr.Size); i++) {
                name.Length = 0;
                if (GetModuleFileNameExW(h, mods[i], name, name.Capacity) > 0) list.Add(name.ToString());
            }
        } finally { CloseHandle(h); }
        return list;
    }

    // --- network endpoints ----------------------------------------------------------------
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int cls, int reserved);
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int af, int cls, int reserved);
    static readonly string[] TcpStates = { "?", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB" };

    static int Port(IntPtr row, int offset) { uint p = (uint)Marshal.ReadInt32(row, offset); return (int)(((p & 0xff) << 8) | ((p >> 8) & 0xff)); }
    static string Address(IntPtr row, int offset, bool v6) {
        var bytes = new byte[v6 ? 16 : 4]; Marshal.Copy(row + offset, bytes, 0, bytes.Length);
        var text = new System.Net.IPAddress(bytes).ToString();
        return v6 ? "[" + text + "]" : text;
    }

    static List<string> Table(bool tcp, bool v6, HashSet<int> pids) {
        var list = new List<string>(); int size = 0; int af = v6 ? 23 : 2;
        Func<IntPtr, uint> get = t => tcp ? GetExtendedTcpTable(t, ref size, false, af, 5, 0) : GetExtendedUdpTable(t, ref size, false, af, 1, 0);
        get(IntPtr.Zero);
        for (int attempt = 0; attempt < 3; attempt++) {
            size += 4096; IntPtr buf = Marshal.AllocHGlobal(size);
            try {
                if (get(buf) != 0) continue;
                int count = Marshal.ReadInt32(buf); int rowSize = tcp ? (v6 ? 56 : 24) : (v6 ? 28 : 12);
                for (int i = 0; i < count; i++) {
                    IntPtr row = buf + 4 + i * rowSize;
                    if (tcp && !v6) {
                        int pid = Marshal.ReadInt32(row, 20); if (!pids.Contains(pid)) continue;
                        list.Add(string.Format("{0} {1}:{2} -> {3}:{4} {5}", pid, Address(row, 4, false), Port(row, 8), Address(row, 12, false), Port(row, 16), TcpStates[Math.Min(12, Marshal.ReadInt32(row, 0))]));
                    } else if (tcp) {
                        int pid = Marshal.ReadInt32(row, 52); if (!pids.Contains(pid)) continue;
                        list.Add(string.Format("{0} {1}:{2} -> {3}:{4} {5}", pid, Address(row, 0, true), Port(row, 20), Address(row, 24, true), Port(row, 44), TcpStates[Math.Min(12, Marshal.ReadInt32(row, 48))]));
                    } else if (!v6) {
                        int pid = Marshal.ReadInt32(row, 8); if (!pids.Contains(pid)) continue;
                        list.Add(string.Format("{0} {1}:{2}", pid, Address(row, 0, false), Port(row, 4)));
                    } else {
                        int pid = Marshal.ReadInt32(row, 24); if (!pids.Contains(pid)) continue;
                        list.Add(string.Format("{0} {1}:{2}", pid, Address(row, 0, true), Port(row, 20)));
                    }
                }
                return list;
            } finally { Marshal.FreeHGlobal(buf); }
        }
        return list;
    }

    public static List<string> Tcp(int[] pids) { var set = new HashSet<int>(pids); var l = Table(true, false, set); l.AddRange(Table(true, true, set)); return l; }
    public static List<string> Udp(int[] pids) { var set = new HashSet<int>(pids); var l = Table(false, false, set); l.AddRange(Table(false, true, set)); return l; }

    // --- windows --------------------------------------------------------------------------
    public delegate bool EnumProc(IntPtr h, IntPtr p);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc f, IntPtr p);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc f, IntPtr p);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out int pid);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsHungAppWindow(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr h, uint cmd);
    [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool BringWindowToTop(IntPtr h);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] static extern bool AttachThreadInput(uint a, uint b, bool attach);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X, Y; }
    [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool ClientToScreen(IntPtr h, ref POINT p);
    [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(POINT p);
    [DllImport("user32.dll")] static extern IntPtr GetAncestor(IntPtr h, uint flags);
    [DllImport("user32.dll")] static extern bool SetProcessDpiAwarenessContext(IntPtr ctx);

    public static void DpiAware() { try { SetProcessDpiAwarenessContext(new IntPtr(-4)); } catch { } }

    static string Text(IntPtr h) { var s = new StringBuilder(1024); GetWindowTextW(h, s, s.Capacity); return s.ToString(); }
    static string Class(IntPtr h) { var s = new StringBuilder(256); GetClassNameW(h, s, s.Capacity); return s.ToString(); }
    static int Owner(IntPtr h) { int pid; GetWindowThreadProcessId(h, out pid); return pid; }

    public class Win { public long handle; public string title, cls, process; public int pid; }

    public static Win Describe(IntPtr h) {
        if (h == IntPtr.Zero) return new Win { handle = 0, title = "", cls = "", process = "(none)", pid = 0 };
        int pid = Owner(h); string name = "?";
        try { name = System.Diagnostics.Process.GetProcessById(pid).ProcessName; } catch { }
        return new Win { handle = h.ToInt64(), title = Text(h), cls = Class(h), process = name, pid = pid };
    }

    public static Win Foreground() { return Describe(GetForegroundWindow()); }

    // The program's window: visible, unowned, of a process in its tree; one of the program's own
    // first, a matching title when asked, then the largest. A dialog only when nothing else.
    public static IntPtr MainWindow(int[] pids, string titleRegex) {
        var set = new HashSet<int>(pids); var re = string.IsNullOrEmpty(titleRegex) ? null : new Regex(titleRegex);
        IntPtr best = IntPtr.Zero; long bestScore = -1;
        EnumWindows((h, p) => {
            int pid = Owner(h);
            if (!set.Contains(pid) || !IsWindowVisible(h) || GetWindow(h, 4) != IntPtr.Zero) return true;
            if (re != null && !re.IsMatch(Text(h))) return true;
            RECT r; GetClientRect(h, out r);
            long score = (long)Math.Max(0, r.Right) * Math.Max(0, r.Bottom) + 1;
            if (Class(h) != "#32770") score += 1L << 40;
            if (pid == Pid) score += 1L << 41;
            if (score > bestScore) { best = h; bestScore = score; }
            return true;
        }, IntPtr.Zero);
        return best;
    }

    public static bool IsFront(IntPtr h) { return h != IntPtr.Zero && GetForegroundWindow() == h && !IsIconic(h); }

    // Windows lets a process take the foreground when it sent the last input: a mouse move of
    // nothing is that input, and reaches no window. AttachThreadInput is the second way.
    public static bool Focus(IntPtr h) {
        if (h == IntPtr.Zero || !IsWindow(h)) return false;
        if (IsIconic(h)) ShowWindow(h, 9);
        SendMouse(0, 0, 0x0001, 0);
        SetForegroundWindow(h);
        Thread.Sleep(100);
        if (IsFront(h)) return true;
        uint self = GetCurrentThreadId(), front = GetWindowThreadProcessId(GetForegroundWindow(), IntPtr.Zero), target = GetWindowThreadProcessId(h, IntPtr.Zero);
        bool a = front != self && AttachThreadInput(self, front, true), b = target != self && AttachThreadInput(self, target, true);
        try { BringWindowToTop(h); SetForegroundWindow(h); }
        finally { if (b) AttachThreadInput(self, target, false); if (a) AttachThreadInput(self, front, false); }
        Thread.Sleep(200);
        return IsFront(h);
    }

    public static void Close(IntPtr h) { if (h != IntPtr.Zero) PostMessageW(h, 0x0010, IntPtr.Zero, IntPtr.Zero); }

    // --- input ----------------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT { public int dx, dy; public uint data, flags, time; public IntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct KEYBDINPUT { public ushort vk, scan; public uint flags, time; public IntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] struct INPUT { public uint type; public INPUTUNION u; }
    [DllImport("user32.dll", SetLastError = true)] static extern uint SendInput(uint n, INPUT[] inputs, int size);
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int index);

    static bool Send(INPUT input) { return SendInput(1, new[] { input }, Marshal.SizeOf(typeof(INPUT))) == 1; }

    // A key by its scan code, as a keyboard sends it: games reading raw input or DirectInput see
    // it, which a virtual-key-only or posted key does not reliably reach.
    public static bool Key(int scan, bool extended, bool up) {
        var i = new INPUT { type = 1 };
        i.u.ki.scan = (ushort)scan;
        i.u.ki.flags = 0x0008 | (extended ? 0x0001u : 0) | (up ? 0x0002u : 0);
        return Send(i);
    }

    public static bool Char(char c, bool up) {
        var i = new INPUT { type = 1 };
        i.u.ki.scan = c; i.u.ki.flags = 0x0004 | (up ? 0x0002u : 0);
        return Send(i);
    }

    static bool SendMouse(int dx, int dy, uint flags, uint data) {
        var i = new INPUT { type = 0 };
        i.u.mi.dx = dx; i.u.mi.dy = dy; i.u.mi.flags = flags; i.u.mi.data = data;
        return Send(i);
    }

    public static bool MoveTo(int x, int y) {
        int left = GetSystemMetrics(76), top = GetSystemMetrics(77), width = GetSystemMetrics(78), height = GetSystemMetrics(79);
        int dx = (int)Math.Round((x - left) * 65535.0 / Math.Max(1, width - 1)), dy = (int)Math.Round((y - top) * 65535.0 / Math.Max(1, height - 1));
        return SendMouse(dx, dy, 0x0001 | 0x8000 | 0x4000, 0); // MOVE | ABSOLUTE | VIRTUALDESK
    }

    public static bool Button(string button, bool up) {
        uint flags = button == "right" ? (up ? 0x0010u : 0x0008u) : button == "middle" ? (up ? 0x0040u : 0x0020u) : (up ? 0x0004u : 0x0002u);
        return SendMouse(0, 0, flags, 0);
    }

    // Client coordinates to the screen; null when the point is outside the client area or another
    // window covers it there.
    public static int[] ScreenPoint(IntPtr h, int x, int y, out string reason) {
        reason = null; RECT r;
        if (!GetClientRect(h, out r) || x >= r.Right || y >= r.Bottom) { reason = string.Format("({0}, {1}) is outside the client area {2}x{3}", x, y, r.Right, r.Bottom); return null; }
        var p = new POINT { X = x, Y = y }; ClientToScreen(h, ref p);
        IntPtr at = GetAncestor(WindowFromPoint(p), 2);
        if (at != h) { reason = "another window is at that point: " + Describe(at).process + " (" + Text(at) + ")"; return null; }
        return new[] { p.X, p.Y };
    }

    // --- captures -------------------------------------------------------------------------
    // Plain GDI and a small PNG writer, so nothing depends on System.Drawing's assemblies, which
    // move between PowerShell versions.
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr h);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr h, IntPtr dc);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int w, int h);
    [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")] static extern bool BitBlt(IntPtr dst, int x, int y, int w, int h, IntPtr src, int sx, int sy, uint rop);
    [StructLayout(LayoutKind.Sequential)] struct BITMAPINFOHEADER { public int size, width, height; public short planes, bits; public int compression, imageSize, xppm, yppm, used, important; }
    [DllImport("gdi32.dll")] static extern int GetDIBits(IntPtr dc, IntPtr bmp, uint start, uint lines, byte[] bits, ref BITMAPINFOHEADER info, uint usage);
    static Thread stuck;

    public class Shot { public string method, reason; public bool black, saved; public int width, height; }

    // Draws into a memory bitmap with `draw` and returns its pixels, BGRA top-down; null on failure.
    static byte[] Grab(int w, int h, Func<IntPtr, bool> draw) {
        IntPtr screen = GetDC(IntPtr.Zero), dc = CreateCompatibleDC(screen), bmp = CreateCompatibleBitmap(screen, w, h);
        IntPtr old = SelectObject(dc, bmp);
        try {
            if (!draw(dc)) return null;
            var info = new BITMAPINFOHEADER { size = 40, width = w, height = -h, planes = 1, bits = 32 };
            var pixels = new byte[w * h * 4];
            SelectObject(dc, old); old = IntPtr.Zero;
            return GetDIBits(dc, bmp, 0, (uint)h, pixels, ref info, 0) == h ? pixels : null;
        } finally {
            if (old != IntPtr.Zero) SelectObject(dc, old);
            DeleteObject(bmp); DeleteDC(dc); ReleaseDC(IntPtr.Zero, screen);
        }
    }

    static bool Black(byte[] px, int w, int h) {
        int sy = Math.Max(1, h / 12), sx = Math.Max(1, w / 12);
        for (int y = sy / 2; y < h; y += sy) for (int x = sx / 2; x < w; x += sx) { int i = (y * w + x) * 4; if (px[i] + px[i + 1] + px[i + 2] > 24) return false; }
        return true;
    }

    static uint[] crcTable;
    static uint Crc(byte[] data, int start, int count) {
        if (crcTable == null) { crcTable = new uint[256]; for (uint n = 0; n < 256; n++) { uint c = n; for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1; crcTable[n] = c; } }
        uint crc = 0xFFFFFFFFu;
        for (int i = start; i < start + count; i++) crc = crcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }

    static void Chunk(System.IO.Stream s, string type, byte[] data) {
        var buf = new byte[data.Length + 4];
        Encoding.ASCII.GetBytes(type, 0, 4, buf, 0); Buffer.BlockCopy(data, 0, buf, 4, data.Length);
        var len = BitConverter.GetBytes(data.Length); Array.Reverse(len); s.Write(len, 0, 4);
        s.Write(buf, 0, buf.Length);
        var crc = BitConverter.GetBytes(Crc(buf, 0, buf.Length)); Array.Reverse(crc); s.Write(crc, 0, 4);
    }

    static void SavePng(string path, byte[] px, int w, int h) {
        var raw = new System.IO.MemoryStream();
        using (var z = new System.IO.Compression.ZLibStream(raw, System.IO.Compression.CompressionLevel.Fastest, true)) {
            var row = new byte[1 + w * 3];
            for (int y = 0; y < h; y++) {
                for (int x = 0; x < w; x++) { int i = (y * w + x) * 4, o = 1 + x * 3; row[o] = px[i + 2]; row[o + 1] = px[i + 1]; row[o + 2] = px[i]; }
                z.Write(row, 0, row.Length);
            }
        }
        var header = new byte[13];
        var wb = BitConverter.GetBytes(w); Array.Reverse(wb); Buffer.BlockCopy(wb, 0, header, 0, 4);
        var hb = BitConverter.GetBytes(h); Array.Reverse(hb); Buffer.BlockCopy(hb, 0, header, 4, 4);
        header[8] = 8; header[9] = 2; // 8 bits, RGB
        using (var f = System.IO.File.Create(path)) {
            f.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }, 0, 8);
            Chunk(f, "IHDR", header); Chunk(f, "IDAT", raw.ToArray()); Chunk(f, "IEND", new byte[0]);
        }
    }

    // PrintWindow (PW_CLIENTONLY | PW_RENDERFULLCONTENT) first: only the window, whatever covers
    // it. It blocks while some games load, so it runs on its own thread with a deadline; when it
    // blocks, fails or comes out black, the window's area of the screen, if the window is in front.
    public static Shot Capture(IntPtr h, string path, int timeoutMs) {
        var shot = new Shot(); RECT r;
        if (h == IntPtr.Zero || !GetClientRect(h, out r) || r.Right <= 0 || r.Bottom <= 0) { shot.reason = "no window, or an empty client area"; return shot; }
        if (IsIconic(h)) { shot.reason = "minimized"; return shot; }
        int w = r.Right, ht = r.Bottom; shot.width = w; shot.height = ht;
        byte[] printed = null; string why = null;
        if (stuck != null && stuck.IsAlive) why = "an earlier PrintWindow is still blocked";
        else if (IsHungAppWindow(h)) why = "the window is not responding";
        else {
            byte[] px = null;
            var t = new Thread(() => { px = Grab(w, ht, dc => PrintWindow(h, dc, 3)); });
            t.IsBackground = true; t.Start();
            if (!t.Join(timeoutMs)) { stuck = t; why = "PrintWindow blocked for " + timeoutMs + " ms"; }
            else if (px == null) why = "PrintWindow failed";
            else if (Black(px, w, ht)) { printed = px; why = "PrintWindow came out black"; }
            else { SavePng(path, px, w, ht); shot.method = "printwindow"; shot.saved = true; return shot; }
        }
        if (IsFront(h)) {
            var p = new POINT(); ClientToScreen(h, ref p);
            IntPtr screen = GetDC(IntPtr.Zero);
            try {
                var px = Grab(w, ht, dc => BitBlt(dc, 0, 0, w, ht, screen, p.X, p.Y, 0x40CC0020)); // SRCCOPY | CAPTUREBLT
                if (px != null) { shot.black = Black(px, w, ht); SavePng(path, px, w, ht); shot.method = "screen"; shot.saved = true; shot.reason = why; return shot; }
            } finally { ReleaseDC(IntPtr.Zero, screen); }
            why += "; the screen capture failed";
        } else why += "; the window was not in front for a screen capture";
        if (printed != null) { SavePng(path, printed, w, ht); shot.method = "printwindow"; shot.saved = true; shot.black = true; }
        shot.reason = why;
        return shot;
    }

    // --- message boxes --------------------------------------------------------------------
    public class Dialog { public long handle; public int pid; public string title, text; public List<string> buttons = new List<string>(); public bool task; }
    static readonly Dictionary<string, int> Standard = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) {
        { "OK", 1 }, { "Cancel", 2 }, { "Abort", 3 }, { "Retry", 4 }, { "Ignore", 5 }, { "Yes", 6 }, { "No", 7 }, { "Close", 8 }, { "Help", 9 }, { "Try Again", 10 }, { "TryAgain", 10 }, { "Continue", 11 } };

    public static List<Dialog> Dialogs(int[] pids) {
        var set = new HashSet<int>(pids); var list = new List<Dialog>();
        EnumWindows((h, p) => {
            int pid = Owner(h);
            if (!set.Contains(pid) || !IsWindowVisible(h) || Class(h) != "#32770") return true;
            var d = new Dialog { handle = h.ToInt64(), pid = pid, title = Text(h) }; var text = new List<string>();
            EnumChildWindows(h, (c, q) => {
                string cls = Class(c), t = Text(c);
                if (cls == "Static" && t.Length > 0) text.Add(t);
                else if (cls == "Button" && t.Length > 0) d.buttons.Add(t.Replace("&", ""));
                else if (cls == "DirectUIHWND") d.task = true;
                return true;
            }, IntPtr.Zero);
            d.text = string.Join("\n", text);
            list.Add(d);
            return true;
        }, IntPtr.Zero);
        return list;
    }

    // Clicks a button by its text (without &) or a standard name (OK, Cancel, Yes, No, ...): a
    // BN_CLICKED to the dialog, posted, so a hung dialog cannot block the engine. A task dialog's
    // buttons are not windows: it gets TDM_CLICK_BUTTON with the standard id.
    public static string Answer(long handle, string button) {
        var h = new IntPtr(handle); IntPtr found = IntPtr.Zero; bool task = false;
        EnumChildWindows(h, (c, q) => {
            string cls = Class(c);
            if (cls == "DirectUIHWND") task = true;
            if (cls == "Button" && string.Equals(Text(c).Replace("&", "").Trim(), button.Trim(), StringComparison.OrdinalIgnoreCase)) { found = c; return false; }
            return true;
        }, IntPtr.Zero);
        if (found != IntPtr.Zero) {
            int id = GetDlgCtrlID(found);
            PostMessageW(h, 0x0111, new IntPtr(id & 0xffff), found);
            return "button " + button + " (id " + id + ")";
        }
        int standard;
        if (!Standard.TryGetValue(button.Trim(), out standard)) return null;
        if (task) PostMessageW(h, 0x0400 + 102, new IntPtr(standard), IntPtr.Zero);
        else PostMessageW(h, 0x0111, new IntPtr(standard), IntPtr.Zero);
        return (task ? "task dialog id " : "id ") + standard;
    }
}
'@

# --- the plan and the log ---------------------------------------------------------------
$p = Get-Content -Raw -LiteralPath $Plan | ConvertFrom-Json -AsHashtable
$Out = $p.out
$Shots = Join-Path $Out 'captures'
New-Item -ItemType Directory -Force -Path $Shots | Out-Null
$EventsFile = Join-Path $Out 'events.jsonl'
$SamplesFile = Join-Path $Out 'samples.jsonl'
$Clock = [Diagnostics.Stopwatch]::new()
function List { , [Collections.Generic.List[object]]::new() }
function Result([string]$status, $detail) { [pscustomobject]@{ status = $status; detail = $detail } }
function Now { [math]::Round($Clock.Elapsed.TotalSeconds, 3) }
function Log([string]$event, [Collections.IDictionary]$fields = @{}) {
    $line = [ordered]@{ t = (Now); event = $event }
    foreach ($k in $fields.Keys) { $line[$k] = $fields[$k] }
    ($line | ConvertTo-Json -Compress -Depth 6) | Add-Content -LiteralPath $EventsFile -Encoding utf8
}

$engine = [ordered]@{
    error = $null; launched = $false; pid = $null; job = $null; started = (Get-Date).ToUniversalTime().ToString('o')
    window = [ordered]@{ first_seen = $null; titles = @() }
    end = $null; steps = (List); captures = (List); dialogs = (List); focus = (List)
    seen = [ordered]@{ processes = @(); modules = @(); tcp = @(); udp = @() }
    left_running = (List); pad = $null
}
$seenProcesses = @{}; $seenModules = [Collections.Generic.HashSet[string]]::new()
$seenTcp = [Collections.Generic.HashSet[string]]::new(); $seenUdp = [Collections.Generic.HashSet[string]]::new()
$titles = [Collections.Generic.List[string]]::new()
$lastModules = [Collections.Generic.HashSet[string]]::new()
$dialogsSeen = @{}
$hwnd = [IntPtr]::Zero
$pids = @()
$pad = $null; $padOut = $null; $padCopy = $null; $padErr = $null
$closeStep = $false

function Refresh {
    $tree = [RunHarness]::Tree()
    $script:pids = @($tree | ForEach-Object { $_.pid })
    foreach ($proc in $tree) {
        if (-not $seenProcesses.ContainsKey($proc.pid)) {
            # The start time tells this process from a later one that reuses its pid.
            $start = try { (Get-Process -Id $proc.pid -ErrorAction Stop).StartTime } catch { $null }
            $seenProcesses[$proc.pid] = [ordered]@{ pid = $proc.pid; parent = $proc.parent; name = $proc.name; first_seen = (Now); start = $start }
        }
    }
    $script:hwnd = [RunHarness]::MainWindow([int[]]$script:pids, $p.window_title)
    if ($script:hwnd -ne [IntPtr]::Zero) {
        if ($null -eq $engine.window.first_seen) { $engine.window.first_seen = (Now); Log 'window' @{ handle = $script:hwnd.ToInt64() } }
        $title = [RunHarness]::Describe($script:hwnd).title
        if ($title -and -not $titles.Contains($title)) { $titles.Add($title); Log 'title' @{ title = $title } }
    }
}

# A capture of the window, logged; $null without a window unless a step asked for it.
function Capture([string]$name, [string]$why, [switch]$Always) {
    if ($script:hwnd -eq [IntPtr]::Zero -and -not $Always) { return $null }
    $file = Join-Path $Shots "$name.png"
    $shot = [RunHarness]::Capture($script:hwnd, $file, [int]($p.capture_timeout * 1000))
    $entry = [ordered]@{ name = $name; file = $(if ($shot.saved) { "captures/$name.png" } else { $null }); t = (Now); why = $why
        method = $shot.method; black = $shot.black; width = $shot.width; height = $shot.height; reason = $shot.reason }
    $engine.captures.Add($entry)
    Log 'capture' $entry
    return $entry
}

function Sample {
    $current = [Collections.Generic.HashSet[string]]::new()
    foreach ($id in $script:pids) {
        $name = if ($seenProcesses.ContainsKey($id)) { $seenProcesses[$id].name } else { "$id" }
        foreach ($m in [RunHarness]::Modules($id)) { [void]$current.Add("${name}: $m") }
    }
    $added = @($current | Where-Object { -not $lastModules.Contains($_) } | Sort-Object)
    $removed = @($lastModules | Where-Object { -not $current.Contains($_) } | Sort-Object)
    foreach ($m in $added) { [void]$seenModules.Add($m) }
    $script:lastModules = $current
    $tcp = @([RunHarness]::Tcp([int[]]$script:pids)); $udp = @([RunHarness]::Udp([int[]]$script:pids))
    foreach ($x in $tcp) { [void]$seenTcp.Add($x) }; foreach ($x in $udp) { [void]$seenUdp.Add($x) }
    $line = [ordered]@{ t = (Now); processes = @($script:pids | ForEach-Object { "$_ $($seenProcesses[$_].name)" })
        modules_added = $added; modules_removed = $removed; tcp = $tcp; udp = $udp }
    ($line | ConvertTo-Json -Compress -Depth 4) | Add-Content -LiteralPath $SamplesFile -Encoding utf8
}

function Watch-Dialogs {
    foreach ($d in [RunHarness]::Dialogs([int[]]$script:pids)) {
        if ($dialogsSeen.ContainsKey($d.handle)) { continue }
        $entry = [ordered]@{ t = (Now); pid = $d.pid; title = $d.title; text = $d.text; buttons = @($d.buttons); task_dialog = $d.task; answered = $null; rule = $null }
        if ($d.task -and -not $d.text) { $entry.text = '(a task dialog: its text is not readable from outside)' }
        foreach ($rule in $p.answers) {
            if ($rule.pattern -and -not ("$($d.title)`n$($d.text)" -match $rule.pattern)) { continue }
            $entry.rule = $(if ($rule.pattern) { "$($rule.pattern)=$($rule.button)" } else { $rule.button })
            $entry.answered = [RunHarness]::Answer($d.handle, $rule.button)
            if (-not $entry.answered) { $entry.answered = $null; $entry.rule += ' (no such button)' }
            break
        }
        $dialogsSeen[$d.handle] = $entry
        $engine.dialogs.Add($entry)
        Log 'dialog' $entry
    }
}

$lastForeground = 0; $lastFocusTry = -10.0; $lostFocus = $false
function Keep-Front {
    if ($script:hwnd -eq [IntPtr]::Zero) { return }
    if ([RunHarness]::IsFront($script:hwnd)) {
        if ($script:lostFocus) { $script:lostFocus = $false; $engine.focus.Add([ordered]@{ t = (Now); event = 'regained' }); Log 'focus-regained' }
        return
    }
    $fg = [RunHarness]::Foreground()
    if ($script:pids -contains $fg.pid) { return }   # the program's own dialog or second window
    if ($fg.handle -ne $script:lastForeground) {
        $script:lastForeground = $fg.handle; $script:lostFocus = $true
        $entry = [ordered]@{ t = (Now); event = 'lost'; window = [ordered]@{ title = $fg.title; class = $fg.cls; process = $fg.process; pid = $fg.pid } }
        $engine.focus.Add($entry); Log 'focus-lost' @{ window = $entry.window }
    }
    if ((Now) - $script:lastFocusTry -ge 1) { $script:lastFocusTry = (Now); [void][RunHarness]::Focus($script:hwnd) }
}

# Null when input may go out now; else why not. One focus attempt first.
function Not-Ready {
    if ($script:hwnd -eq [IntPtr]::Zero) { return 'the program has no window' }
    if (-not [RunHarness]::IsFront($script:hwnd)) { [void][RunHarness]::Focus($script:hwnd) }
    if ([RunHarness]::IsFront($script:hwnd)) { return $null }
    $fg = [RunHarness]::Foreground()
    return "the program's window is not in front: $($fg.process) ($($fg.title), class $($fg.cls))"
}

function Pad-Plugged {
    if (-not $script:pad) { return $false }
    try {
        $stream = [IO.File]::Open($script:padPath, 'Open', 'Read', 'ReadWrite')
        try { $text = [IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
        return $text -match '"event": "plugged"'
    } catch { return $false }
}

# Runs one step; returns @(status, detail) once it is over, or $null while it is still waiting.
function Run-Step($s, [double]$since) {
    switch ($s.op) {
        'wait' { if ((Now) - $since -ge $s.seconds) { return (Result 'done' $null) }; return $null }
        'at' { if ((Now) -ge $s.seconds) { return (Result 'done' $null) }; return $null }
        'wait-window' {
            if ($script:hwnd -ne [IntPtr]::Zero) { return (Result 'done' "after $([math]::Round((Now) - $since, 1)) s") }
            if ((Now) - $since -ge $s.seconds) { return (Result 'failed' "no window within $($s.seconds) s") }
            return $null
        }
        'focus' { $why = Not-Ready; if ($why) { return (Result 'failed' $why) }; return (Result 'done' $null) }
        'capture' {
            $name = if ($s.name) { $s.name } else { 'step-{0:000}' -f $s.line }
            $shot = Capture $name "line $($s.line)" -Always
            if (-not $shot.file) { return (Result 'failed' $shot.reason) }
            return (Result 'done' $shot.file)
        }
        'close' { $script:closeStep = $true; return (Result 'done' $null) }
        'key' {
            $down = [Collections.Generic.List[object]]::new()
            try {
                foreach ($k in $s.chord) {
                    $why = Not-Ready; if ($why) { return (Result 'refused' $why) }
                    if (-not [RunHarness]::Key($k.scan, $k.extended, $false)) { return (Result 'failed' "SendInput refused $($k.name)") }
                    $down.Insert(0, $k)
                }
                Start-Sleep -Milliseconds ([int]($s.hold * 1000))
            } finally { foreach ($k in $down) { [void][RunHarness]::Key($k.scan, $k.extended, $true) } }
            return (Result 'done' $null)
        }
        'text' {
            foreach ($c in $s.text.ToCharArray()) {
                $why = Not-Ready; if ($why) { return (Result 'refused' $why) }
                [void][RunHarness]::Char($c, $false); [void][RunHarness]::Char($c, $true)
                Start-Sleep -Milliseconds 20
            }
            return (Result 'done' $null)
        }
        { $_ -in 'move', 'click' } {
            $why = Not-Ready; if ($why) { return (Result 'refused' $why) }
            $reason = $null
            $point = [RunHarness]::ScreenPoint($script:hwnd, $s.x, $s.y, [ref]$reason)
            if (-not $point) { return (Result 'refused' $reason) }
            [void][RunHarness]::MoveTo($point[0], $point[1])
            if ($s.op -eq 'move') { return (Result 'done' "screen $($point[0]),$($point[1])") }
            Start-Sleep -Milliseconds 50
            $why = Not-Ready; if ($why) { return (Result 'refused' $why) }
            [void][RunHarness]::Button($s.button, $false)
            try { Start-Sleep -Milliseconds ([int]($s.hold * 1000)) } finally { [void][RunHarness]::Button($s.button, $true) }
            return (Result 'done' "screen $($point[0]),$($point[1])")
        }
        'pad' {
            if (-not $script:pad -or $script:pad.HasExited) { return (Result 'failed' 'the pad is not running (pad.err)') }
            $wait = [Diagnostics.Stopwatch]::StartNew()
            while (-not (Pad-Plugged) -and $wait.Elapsed.TotalSeconds -lt 5 -and -not $script:pad.HasExited) { Start-Sleep -Milliseconds 50 }
            if (-not (Pad-Plugged)) { return (Result 'failed' 'the pad did not plug in (pad.err)') }
            $why = Not-Ready; if ($why) { return (Result 'refused' $why) }
            $script:pad.StandardInput.WriteLine(('{0}:{1}' -f $s.press, $s.hold.ToString([Globalization.CultureInfo]::InvariantCulture)))
            Start-Sleep -Milliseconds ([int]($s.hold * 1000) + 50)
            return (Result 'done' $null)
        }
        default { return (Result 'failed' "unknown step $($s.op)") }
    }
}

# --- the run ----------------------------------------------------------------------------
[RunHarness]::DpiAware()
$endReason = $null
try {
    if ($p.attach) {
        $target = "$($p.attach.target)"; $wait = [Diagnostics.Stopwatch]::StartNew(); $found = $null
        while (-not $found -and $wait.Elapsed.TotalSeconds -lt $p.attach.wait) {
            $found = if ($target -match '^\d+$') { Get-Process -Id ([int]$target) -ErrorAction SilentlyContinue }
                     else { Get-Process -Name ($target -replace '\.exe$', '') -ErrorAction SilentlyContinue | Sort-Object StartTime | Select-Object -First 1 }
            if (-not $found) { Start-Sleep -Milliseconds 500 }
        }
        if (-not $found) { throw "no process '$target' within $($p.attach.wait) s" }
        [RunHarness]::Attach($found.Id)
    } else {
        $cwd = if ($p.cwd) { $p.cwd } elseif ([IO.Path]::IsPathRooted($p.program)) { Split-Path -Parent $p.program } else { $null }
        $vars = [Collections.Generic.Dictionary[string, string]]::new()
        foreach ($k in $p.env.Keys) { $vars[$k] = [string]$p.env[$k] }
        $engine.job = [RunHarness]::Launch($p.command_line, $cwd, $vars)
        $engine.launched = $true
    }
    $Clock.Start()
    $engine.pid = [RunHarness]::Pid
    Log 'start' @{ pid = [RunHarness]::Pid; launched = $engine.launched; job = $engine.job }

    if ($p.pad) {
        $info = [Diagnostics.ProcessStartInfo]::new($p.pad[0])
        foreach ($a in ($p.pad | Select-Object -Skip 1)) { $info.ArgumentList.Add($a) }
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $padPath = Join-Path $Out 'pad.jsonl'
        $padOut = [IO.FileStream]::new($padPath, 'Create', 'Write', 'ReadWrite')
        $padErr = [IO.FileStream]::new((Join-Path $Out 'pad.err'), 'Create', 'Write', 'ReadWrite')
        $pad = [Diagnostics.Process]::Start($info)
        $pad.StandardInput.AutoFlush = $true
        $padCopy = @($pad.StandardOutput.BaseStream.CopyToAsync($padOut), $pad.StandardError.BaseStream.CopyToAsync($padErr))
        Log 'pad-start' @{ pid = $pad.Id }
    }

    $stepIndex = 0; $stepSince = $null
    $nextSample = 0.0; $nextShot = if ($p.capture_every -gt 0) { $p.capture_every } else { [double]::MaxValue }; $nextFront = 0.0
    while ($true) {
        $t = Now
        if ([RunHarness]::Exited()) { $endReason = 'exited'; break }
        if ($t -ge $p.seconds) { $endReason = 'timeout'; break }
        if ($closeStep) { $endReason = 'close-step'; break }
        Refresh
        Watch-Dialogs
        if ($p.keep_front -and $t -ge $nextFront) { Keep-Front; $nextFront = $t + 0.5 }
        if ($p.sample_every -gt 0 -and $t -ge $nextSample) { Sample; $nextSample = $t + $p.sample_every }
        if ($t -ge $nextShot) { [void](Capture ('every-{0:0000}s' -f [int]$t) 'every'); $nextShot += $p.capture_every }
        if ($stepIndex -lt $p.steps.Count) {
            $s = $p.steps[$stepIndex]
            if ($null -eq $stepSince) { $stepSince = $t; Log 'step' @{ line = $s.line; source = $s.source } }
            $result = @(Run-Step $s $stepSince | Where-Object { $_ -is [pscustomobject] })
            if ($result.Count) {
                $result = $result[-1]
                $engine.steps.Add([ordered]@{ line = $s.line; source = $s.source; op = $s.op; t = $stepSince; ended = (Now); status = $result.status; detail = $result.detail })
                Log ('step-' + $result.status) @{ line = $s.line; detail = $result.detail }
                $stepIndex++; $stepSince = $null
                continue
            }
        }
        Start-Sleep -Milliseconds 100
    }
    for ($i = $stepIndex; $i -lt $p.steps.Count; $i++) {
        $s = $p.steps[$i]
        $engine.steps.Add([ordered]@{ line = $s.line; source = $s.source; op = $s.op; t = $null; ended = $null; status = 'not-run'; detail = "the run ended first ($endReason)" })
    }
} catch {
    $engine.error = $_.Exception.Message
    if (-not $endReason) { $endReason = 'error' }
} finally {
    # --- the end: WM_CLOSE first, then the kill; nothing of the run left behind --------------
    $endedBy = 'exit'
    try {
        if ([RunHarness]::Pid) {
            Refresh
            if (-not [RunHarness]::Exited()) { [void](Capture 'final' 'end'); Sample }
            $ours = $engine.launched -or ($p.attach -and $p.attach.close)
            if (-not [RunHarness]::Exited()) {
                if ($ours -and $hwnd -ne [IntPtr]::Zero) {
                    # The player's way out first, so the program and its services end as they would.
                    [RunHarness]::Close($hwnd); Log 'wm-close' @{ handle = $hwnd.ToInt64() }
                    $endedBy = 'wm_close'
                    $grace = [Diagnostics.Stopwatch]::StartNew()
                    while (-not [RunHarness]::Exited() -and $grace.Elapsed.TotalSeconds -lt $p.close_grace) { Refresh; Watch-Dialogs; Start-Sleep -Milliseconds 200 }
                    if (-not [RunHarness]::Exited()) { $endedBy = 'killed' }
                } elseif ($ours) { $endedBy = 'killed'; Log 'no-window-to-close' }
                else { $endedBy = 'left-running' }
            }
            if ($ours) {
                [RunHarness]::KillJob()
                foreach ($proc in $seenProcesses.Values) {
                    if ($proc.start) { Get-Process -Id $proc.pid -ErrorAction SilentlyContinue | Where-Object StartTime -EQ $proc.start | Stop-Process -Force -ErrorAction SilentlyContinue }
                }
                Start-Sleep -Milliseconds 500
                foreach ($proc in $seenProcesses.Values) {
                    if ($proc.start -and (Get-Process -Id $proc.pid -ErrorAction SilentlyContinue | Where-Object StartTime -EQ $proc.start)) {
                        $engine.left_running.Add([ordered]@{ pid = $proc.pid; name = $proc.name })
                    }
                }
            }
            $engine.end = [ordered]@{ t = (Now); reason = $endReason; ended_by = $endedBy; exit_code = [RunHarness]::ExitCode() }
            Log 'end' $engine.end
        }
    } catch { if (-not $engine.error) { $engine.error = "ending the run: $($_.Exception.Message)" } }
    if ($pad) {
        try { $pad.StandardInput.Close(); if (-not $pad.WaitForExit(5000)) { $pad.Kill($true) } } catch { }
        try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$padCopy, 3000) } catch { }
        $padOut.Dispose(); $padErr.Dispose()
        $engine.pad = [ordered]@{ exit_code = $(if ($pad.HasExited) { $pad.ExitCode } else { $null }); log = 'pad.jsonl' }
    }
    $engine.window.titles = @($titles)
    $engine.seen.processes = @($seenProcesses.Values | Sort-Object { $_.first_seen } | ForEach-Object { [ordered]@{ pid = $_.pid; parent = $_.parent; name = $_.name; first_seen = $_.first_seen } })
    $engine.seen.modules = @($seenModules | Sort-Object); $engine.seen.tcp = @($seenTcp | Sort-Object); $engine.seen.udp = @($seenUdp | Sort-Object)
    $engine | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $Out 'engine.json') -Encoding utf8
}
if ($engine.error) { exit 1 }
