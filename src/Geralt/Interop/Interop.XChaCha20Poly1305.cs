using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32;
        internal const int crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24;
        internal const int crypto_aead_xchacha20poly1305_ietf_ABYTES = 16;

        internal const int crypto_secretstream_xchacha20poly1305_ABYTES = 17;
        internal const int crypto_secretstream_xchacha20poly1305_HEADERBYTES = 24;
        internal const int crypto_secretstream_xchacha20poly1305_KEYBYTES = 32;

        internal const byte crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = 0x00;
        internal const byte crypto_secretstream_xchacha20poly1305_TAG_PUSH = 0x01;
        internal const byte crypto_secretstream_xchacha20poly1305_TAG_REKEY = 0x02;
        internal const byte crypto_secretstream_xchacha20poly1305_TAG_FINAL = 0x03;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_aead_xchacha20poly1305_ietf_encrypt(byte* ciphertext, out ulong ciphertextLength, byte* plaintext, ulong plaintextLength, byte* associatedData, ulong associatedDataLength, byte* nsec, byte* nonce, byte* key);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_aead_xchacha20poly1305_ietf_decrypt(byte* plaintext, out ulong plaintextLength, byte* nsec, byte* ciphertext, ulong ciphertextLength, byte* associatedData, ulong associatedDataLength, byte* nonce, byte* key);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_secretstream_xchacha20poly1305_init_push(ref crypto_secretstream_xchacha20poly1305_state state, byte* header, byte* key);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_secretstream_xchacha20poly1305_init_pull(ref crypto_secretstream_xchacha20poly1305_state state, byte* header, byte* key);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_secretstream_xchacha20poly1305_push(ref crypto_secretstream_xchacha20poly1305_state state, byte* ciphertextChunk, out ulong ciphertextChunkLength, byte* plaintextChunk, ulong plaintextChunkLength, byte* associatedData, ulong associatedDataLength, byte tag);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_secretstream_xchacha20poly1305_pull(ref crypto_secretstream_xchacha20poly1305_state state, byte* plaintext, out ulong plaintextLength, ref byte tag, byte* ciphertextChunk, ulong ciphertextChunkLength, byte* associatedData, ulong associatedDataLength);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe void crypto_secretstream_xchacha20poly1305_rekey(ref crypto_secretstream_xchacha20poly1305_state state);

        [StructLayout(LayoutKind.Explicit, Size = 52)]
        internal struct crypto_secretstream_xchacha20poly1305_state
        {
        }
    }
}