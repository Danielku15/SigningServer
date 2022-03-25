using System;
using System.Runtime.InteropServices;

namespace SigningServer.Server.SigningTool
{
    public sealed class UnmanagedStruct<T> : IDisposable
        where T : struct
    {
        public IntPtr Pointer { get; private set; }

        public UnmanagedStruct()
        {
            Pointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        }

        public void Fill(T value)
        {
            Marshal.StructureToPtr(value, Pointer, false);
        }

        public UnmanagedStruct(T v)
        {
            Pointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(v, Pointer, false);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(Pointer);
        }
    }
}