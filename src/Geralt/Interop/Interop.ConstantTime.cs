using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_memcmp(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, nuint length);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void sodium_increment(Span<byte> buffer, nuint bufferLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void sodium_add(Span<byte> a, ReadOnlySpan<byte> b, nuint length);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial void sodium_sub(Span<byte> a, ReadOnlySpan<byte> b, nuint length);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_compare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, nuint length);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_is_zero(ReadOnlySpan<byte> buffer, nuint bufferLength);
    }
}
