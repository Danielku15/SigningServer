using System;
using System.Runtime.InteropServices;

namespace SigningServer.MsSign;

internal sealed class UnmanagedStruct<T> : IDisposable
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

    public UnmanagedStruct(T v) : this()
    {
        Marshal.StructureToPtr(v, Pointer, false);
    }

    public void Dispose()
    {
        if (Pointer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(Pointer);
            Pointer = IntPtr.Zero;
        }
    }
}