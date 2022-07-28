using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_memcmp(byte* a, byte* b, int length);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe void sodium_increment(byte* buffer, int bufferLength);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe void sodium_add(byte* a, byte* b, int length);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe void sodium_sub(byte* a, byte* b, int length);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_compare(byte* a, byte* b, int length);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_is_zero(byte* buffer, int bufferLength);
    }
}