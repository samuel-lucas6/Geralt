using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_onetimeauth_KEYBYTES = 32;
        internal const int crypto_onetimeauth_BYTES  = 16;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth(Span<byte> tag, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> oneTimeKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_verify(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> oneTimeKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_init(ref crypto_onetimeauth_state state, ReadOnlySpan<byte> oneTimeKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_update(ref crypto_onetimeauth_state state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_onetimeauth_final(ref crypto_onetimeauth_state state, Span<byte> tag);

        [StructLayout(LayoutKind.Explicit, Size = 256)]
        internal struct crypto_onetimeauth_state;
    }
}
