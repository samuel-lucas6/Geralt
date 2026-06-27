using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    // Unused functions have been omitted
    internal static partial class Libsodium
    {
        internal const int crypto_kem_mlkem768_PUBLICKEYBYTES = 1184;
        internal const int crypto_kem_mlkem768_SECRETKEYBYTES = 2400;
        internal const int crypto_kem_mlkem768_CIPHERTEXTBYTES = 1088;
        internal const int crypto_kem_mlkem768_SHAREDSECRETBYTES = 32;
        internal const int crypto_kem_mlkem768_SEEDBYTES = 64;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_mlkem768_publickeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_mlkem768_secretkeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_mlkem768_ciphertextbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_mlkem768_sharedsecretbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kem_mlkem768_seedbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_mlkem768_keypair(Span<byte> publicKey, Span<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_mlkem768_seed_keypair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_mlkem768_enc(Span<byte> ciphertext, Span<byte> sharedSecret, ReadOnlySpan<byte> recipientPublicKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kem_mlkem768_dec(Span<byte> sharedSecret, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> recipientPrivateKey);
    }
}
