using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_chacha20poly1305_IETF_KEYBYTES = 32;
        internal const int crypto_aead_chacha20poly1305_IETF_NPUBBYTES = 12;
        internal const int crypto_aead_chacha20poly1305_IETF_ABYTES = 16;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_aead_chacha20poly1305_ietf_encrypt(Span<byte> ciphertext, out ulong ciphertextLength, ReadOnlySpan<byte> plaintext, ulong plaintextLength, ReadOnlySpan<byte> associatedData, ulong associatedDataLength, ReadOnlySpan<byte> nsec, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_aead_chacha20poly1305_ietf_decrypt(Span<byte> plaintext, out ulong plaintextLength, ReadOnlySpan<byte> nsec, ReadOnlySpan<byte> ciphertext, ulong ciphertextLength, ReadOnlySpan<byte> associatedData, ulong associatedDataLength, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);
    }
}
