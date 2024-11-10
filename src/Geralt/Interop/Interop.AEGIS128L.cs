using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_aead_aegis128l_KEYBYTES = 16;
        internal const int crypto_aead_aegis128l_NPUBBYTES = 16;
        internal const int crypto_aead_aegis128l_ABYTES = 32;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_aead_aegis128l_encrypt(Span<byte> ciphertext, out ulong ciphertextLength, ReadOnlySpan<byte> plaintext, ulong plaintextLength, ReadOnlySpan<byte> associatedData, ulong associatedDataLength, ReadOnlySpan<byte> nsec, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_aead_aegis128l_decrypt(Span<byte> plaintext, out ulong plaintextLength, ReadOnlySpan<byte> nsec, ReadOnlySpan<byte> ciphertext, ulong ciphertextLength, ReadOnlySpan<byte> associatedData, ulong associatedDataLength, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);
    }
}
