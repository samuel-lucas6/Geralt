using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_chacha20_ietf_KEYBYTES = 32;
        internal const int crypto_stream_chacha20_ietf_NONCEBYTES = 12;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_stream_chacha20_ietf(byte* ciphertext, ulong ciphertextLength, byte* nonce, byte* key);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_stream_chacha20_ietf_xor_ic(byte* ciphertext, byte* plaintext, ulong plaintextLength, byte* nonce, uint counter, byte* key);
    }
}
