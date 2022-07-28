using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int randombytes_SEEDBYTES = 32;
    
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe void randombytes_buf(byte* buffer, int size);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe void randombytes_buf_deterministic(byte* buffer, int size, byte* seed);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int randombytes_uniform(int upperBound);
    }
}