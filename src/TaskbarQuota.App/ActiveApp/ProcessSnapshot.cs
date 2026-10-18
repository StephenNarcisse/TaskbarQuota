using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;

namespace TaskbarQuota.ActiveApp
{
    internal readonly record struct ProcessEntry(int Pid, int ParentPid, string ExeName);

    /// <summary>
    /// Cheap process enumeration shared by the foreground detector and the activity scanner.
    /// A ToolHelp snapshot replaces <c>Process.GetProcesses()</c> (one managed Process object per running
    /// process) and the unfiltered-by-cost WMI <c>Win32_Process</c> queries. Start times and command
    /// lines of a live process never change, so they are cached per PID and only fetched once.
    /// </summary>
    internal static class ProcessSnapshot
    {
        // A snapshot is ~1 ms; this TTL only lets the detector and scanner share one within a tick.
        private static readonly TimeSpan SnapshotTtl = TimeSpan.FromMilliseconds(200);
        private static readonly object Gate = new();

        private static IReadOnlyList<ProcessEntry> _entries = Array.Empty<ProcessEntry>();
        private static long _capturedAtTicks;

        // Keyed by pid and validated against the parent pid so a recycled pid is re-read.
        private static readonly Dictionary<int, (int ParentPid, DateTime Started)> StartCache = new();
        private static readonly Dictionary<int, (int ParentPid, string Name, string CommandLine)> CommandLineCache = new();

        public static IReadOnlyList<ProcessEntry> Capture()
        {
            lock (Gate)
            {
                var now = Environment.TickCount64;
                if (_capturedAtTicks != 0 && now - _capturedAtTicks < SnapshotTtl.TotalMilliseconds)
                    return _entries;

                var list = new List<ProcessEntry>(256);
                var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
                if (snapshot == InvalidHandle)
                    return _entries;

                try
                {
                    var entry = new ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<ProcessEntry32>() };
                    if (Process32FirstW(snapshot, ref entry))
                    {
                        do
                        {
                            list.Add(new ProcessEntry((int)entry.th32ProcessID, (int)entry.th32ParentProcessID, entry.szExeFile));
                        }
                        while (Process32NextW(snapshot, ref entry));
                    }
                }
                finally
                {
                    CloseHandle(snapshot);
                }

                _entries = list;
                _capturedAtTicks = now;
                Prune(list);
                return _entries;
            }
        }

        /// <summary>Process creation time (local), or <see cref="DateTime.MinValue"/> when unreadable.</summary>
        public static DateTime GetStartTime(int pid, int parentPid)
        {
            lock (Gate)
            {
                if (StartCache.TryGetValue(pid, out var cached) && cached.ParentPid == parentPid)
                    return cached.Started;

                var started = ReadStartTime(pid);
                StartCache[pid] = (parentPid, started);
                return started;
            }
        }

        /// <summary>
        /// Name + command line for each pid, reading WMI only for pids not seen before.
        /// <paramref name="pids"/> pairs a pid with its current parent pid for cache validation.
        /// </summary>
        public static Dictionary<int, (string Name, string CommandLine)> GetCommandLines(
            IEnumerable<(int Pid, int ParentPid)> pids)
        {
            var result = new Dictionary<int, (string Name, string CommandLine)>();
            var missing = new List<(int Pid, int ParentPid)>();
            lock (Gate)
            {
                foreach (var (pid, parentPid) in pids)
                {
                    if (result.ContainsKey(pid)) continue;
                    if (CommandLineCache.TryGetValue(pid, out var cached) && cached.ParentPid == parentPid)
                        result[pid] = (cached.Name, cached.CommandLine);
                    else
                        missing.Add((pid, parentPid));
                }
            }

            const int chunkSize = 60;
            for (int i = 0; i < missing.Count; i += chunkSize)
            {
                var chunk = missing.GetRange(i, Math.Min(chunkSize, missing.Count - i));
                var where = string.Join(" OR ", chunk.ConvertAll(p => "ProcessId = " + p.Pid));
                var parents = new Dictionary<int, int>();
                foreach (var (pid, parentPid) in chunk) parents[pid] = parentPid;
                try
                {
                    using var searcher = new ManagementObjectSearcher(
                        "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE " + where);
                    using var processes = searcher.Get();
                    foreach (ManagementObject mo in processes)
                    {
                        using (mo)
                        {
                            if (!int.TryParse(mo["ProcessId"]?.ToString(), out var pid)) continue;
                            var name = mo["Name"] as string ?? "";
                            var commandLine = mo["CommandLine"] as string ?? "";
                            result[pid] = (name, commandLine);
                            if (parents.TryGetValue(pid, out var parentPid))
                            {
                                lock (Gate)
                                    CommandLineCache[pid] = (parentPid, name, commandLine);
                            }
                        }
                    }
                }
                catch (ManagementException) { }
                catch (UnauthorizedAccessException) { }
            }

            return result;
        }

        /// <summary>
        /// Base name (no extension) of a live process, equal to <c>Process.ProcessName</c>. Reads the
        /// image path through a limited handle (no managed Process object); falls back to the managed
        /// lookup for processes whose path cannot be queried (protected / access denied).
        /// </summary>
        public static string? TryGetProcessName(int pid)
        {
            if (pid <= 0) return null;
            var handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
            if (handle != IntPtr.Zero)
            {
                try
                {
                    var buffer = new char[1024];
                    uint size = (uint)buffer.Length;
                    if (QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0)
                    {
                        var path = new string(buffer, 0, (int)size);
                        var name = System.IO.Path.GetFileNameWithoutExtension(path);
                        if (!string.IsNullOrEmpty(name)) return name;
                    }
                }
                finally
                {
                    CloseHandle(handle);
                }
            }

            try
            {
                using var process = System.Diagnostics.Process.GetProcessById(pid);
                return process.ProcessName;
            }
            catch
            {
                return null;
            }
        }

        private static void Prune(List<ProcessEntry> live)
        {
            if (StartCache.Count == 0 && CommandLineCache.Count == 0) return;
            var alive = new HashSet<int>(live.Count);
            foreach (var e in live) alive.Add(e.Pid);

            List<int>? stale = null;
            foreach (var pid in StartCache.Keys)
                if (!alive.Contains(pid)) (stale ??= new()).Add(pid);
            if (stale != null) foreach (var pid in stale) StartCache.Remove(pid);

            stale = null;
            foreach (var pid in CommandLineCache.Keys)
                if (!alive.Contains(pid)) (stale ??= new()).Add(pid);
            if (stale != null) foreach (var pid in stale) CommandLineCache.Remove(pid);
        }

        private static DateTime ReadStartTime(int pid)
        {
            var handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
            if (handle == IntPtr.Zero) return DateTime.MinValue;
            try
            {
                if (!GetProcessTimes(handle, out var creation, out _, out _, out _)) return DateTime.MinValue;
                var fileTime = ((long)creation.dwHighDateTime << 32) | (uint)creation.dwLowDateTime;
                return fileTime > 0 ? DateTime.FromFileTime(fileTime) : DateTime.MinValue;
            }
            catch (ArgumentOutOfRangeException)
            {
                return DateTime.MinValue;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private const uint Th32csSnapProcess = 0x00000002;
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private static readonly IntPtr InvalidHandle = new(-1);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProcessEntry32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public UIntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            IntPtr process,
            out System.Runtime.InteropServices.ComTypes.FILETIME creation,
            out System.Runtime.InteropServices.ComTypes.FILETIME exit,
            out System.Runtime.InteropServices.ComTypes.FILETIME kernel,
            out System.Runtime.InteropServices.ComTypes.FILETIME user);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, [Out] char[] exeName, ref uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
