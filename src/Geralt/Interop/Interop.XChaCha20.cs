using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_xchacha20_KEYBYTES = 32;
        internal const int crypto_stream_xchacha20_NONCEBYTES = 24;
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_stream_xchacha20(byte* ciphertext, ulong ciphertextLength, byte* nonce, byte* key);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_stream_xchacha20_xor_ic(byte* ciphertext, byte* plaintext, ulong plaintextLength, byte* nonce, ulong counter, byte* key);
    }
}