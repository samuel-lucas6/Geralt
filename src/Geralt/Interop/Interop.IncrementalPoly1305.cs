using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_onetimeauth_poly1305_statebytes = 256;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_poly1305_init(ref crypto_onetimeauth_poly1305_state state, ReadOnlySpan<byte> oneTimeKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_poly1305_update(ref crypto_onetimeauth_poly1305_state state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_poly1305_final(ref crypto_onetimeauth_poly1305_state state, Span<byte> tag);

        [StructLayout(LayoutKind.Explicit, Size = crypto_onetimeauth_poly1305_statebytes)]
        internal struct crypto_onetimeauth_poly1305_state;
    }
}
