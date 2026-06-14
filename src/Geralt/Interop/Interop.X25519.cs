using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    // Unused constants/functions have been omitted
    internal static partial class Libsodium
    {
        internal const int crypto_kx_PUBLICKEYBYTES = 32;
        internal const int crypto_kx_SECRETKEYBYTES = 32;
        internal const int crypto_kx_SEEDBYTES = 32;
        internal const int crypto_kx_SESSIONKEYBYTES = 32;
        internal const int crypto_scalarmult_curve25519_BYTES = 32;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kx_publickeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kx_secretkeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kx_seedbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_kx_sessionkeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_scalarmult_curve25519_bytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kx_keypair(Span<byte> publicKey, Span<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_kx_seed_keypair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_scalarmult_curve25519_base(Span<byte> publicKey, ReadOnlySpan<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_scalarmult_curve25519(Span<byte> sharedSecret, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> recipientPublicKey);
    }
}
