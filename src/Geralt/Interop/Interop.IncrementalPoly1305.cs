using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_poly1305_init(ref crypto_onetimeauth_poly1305_state state, ReadOnlySpan<byte> oneTimeKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_poly1305_update(ref crypto_onetimeauth_poly1305_state state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_poly1305_final(ref crypto_onetimeauth_poly1305_state state, Span<byte> tag);

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        internal struct crypto_onetimeauth_poly1305_state;
    }
}
