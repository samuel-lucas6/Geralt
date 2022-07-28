using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_chacha20poly1305_IETF_KEYBYTES = 32;
        internal const int crypto_aead_chacha20poly1305_IETF_NPUBBYTES = 12;
        internal const int crypto_aead_chacha20poly1305_IETF_ABYTES = 16;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_aead_chacha20poly1305_ietf_encrypt(byte* ciphertext, out long ciphertextLength, byte* plaintext, long plaintextLength, byte* associatedData, long associatedDataLength, byte* nsec, byte* nonce, byte* key);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_aead_chacha20poly1305_ietf_decrypt(byte* plaintext, out long plaintextLength, byte* nsec, byte* ciphertext, long ciphertextLength, byte* associatedData, long associatedDataLength, byte* nonce, byte* key);
    }
}