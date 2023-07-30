using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_core_hchacha20_KEYBYTES = 32;
        internal const int crypto_core_hchacha20_INPUTBYTES = 16;
        internal const int crypto_core_hchacha20_CONSTBYTES = 16;
        internal const int crypto_core_hchacha20_OUTPUTBYTES = 32;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_core_hchacha20(byte* output, byte* nonce, byte* key, byte* constant);
    }
}
