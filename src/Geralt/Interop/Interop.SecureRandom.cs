using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    // Unused constants/functions have been omitted
    internal static partial class Libsodium
    {
        internal const int randombytes_SEEDBYTES = 32;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint randombytes_seedbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void randombytes_buf(Span<byte> buffer, nuint bufferSize);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void randombytes_buf_deterministic(Span<byte> buffer, nuint bufferSize, ReadOnlySpan<byte> seed);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int randombytes_uniform(uint upperBound);
    }
}
