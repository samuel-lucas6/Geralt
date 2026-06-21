using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    // Unused constants/functions have been omitted
    internal static partial class Libsodium
    {
        internal const int crypto_kem_xwing_PUBLICKEYBYTES = 1216;
        internal const int crypto_kem_xwing_SECRETKEYBYTES = 32;
        internal const int crypto_kem_xwing_CIPHERTEXTBYTES = 1120;
        internal const int crypto_kem_xwing_SHAREDSECRETBYTES = 32;
        internal const int crypto_kem_xwing_SEEDBYTES = 32;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_xwing_publickeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_xwing_secretkeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_xwing_ciphertextbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_xwing_sharedsecretbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_xwing_seedbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_xwing_keypair(Span<byte> publicKey, Span<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_xwing_seed_keypair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_xwing_enc(Span<byte> ciphertext, Span<byte> sharedSecret, ReadOnlySpan<byte> recipientPublicKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_xwing_dec(Span<byte> sharedSecret, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> recipientPrivateKey);
    }
}
