using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_core_hchacha20_KEYBYTES = 32;
        internal const int crypto_core_hchacha20_INPUTBYTES = 16;
        internal const int crypto_core_hchacha20_CONSTBYTES = 16;
        internal const int crypto_core_hchacha20_OUTPUTBYTES = 32;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_core_hchacha20(Span<byte> output, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> constant);
    }
}
