using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_chacha20poly1305_IETF_KEYBYTES = 32;
        internal const int crypto_aead_chacha20poly1305_IETF_NPUBBYTES = 12;
        internal const int crypto_aead_chacha20poly1305_IETF_ABYTES = 16;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_aead_chacha20poly1305_ietf_encrypt(byte* ciphertext, out ulong ciphertextLength, byte* plaintext, ulong plaintextLength, byte* associatedData, ulong associatedDataLength, byte* nsec, byte* nonce, byte* key);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_aead_chacha20poly1305_ietf_decrypt(byte* plaintext, out ulong plaintextLength, byte* nsec, byte* ciphertext, ulong ciphertextLength, byte* associatedData, ulong associatedDataLength, byte* nonce, byte* key);
    }
}
