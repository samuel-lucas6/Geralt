using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_onetimeauth_poly1305_statebytes = 256;
        internal const int crypto_onetimeauth_poly1305_statebytes_CRYPTO_ALIGN = 16;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_onetimeauth_poly1305_init(void* state, ReadOnlySpan<byte> oneTimeKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_onetimeauth_poly1305_update(void* state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_onetimeauth_poly1305_final(void* state, Span<byte> tag);
    }
}
