using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_pad(out nuint paddedBufferLength, Span<byte> buffer, nuint unpaddedBufferLength, nuint blockSize, nuint maxBufferLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_unpad(out nuint unpaddedBufferLength, ReadOnlySpan<byte> paddedBuffer, nuint paddedBufferLength, nuint blockSize);
    }
}
