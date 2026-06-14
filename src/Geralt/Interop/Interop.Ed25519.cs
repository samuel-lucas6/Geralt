using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    // Unused constants/functions have been omitted
    internal static partial class Libsodium
    {
        internal const int crypto_sign_ed25519_PUBLICKEYBYTES = 32;
        internal const int crypto_sign_ed25519_SECRETKEYBYTES = 64;
        internal const int crypto_sign_ed25519_SEEDBYTES = 32;
        internal const int crypto_sign_ed25519_BYTES = 64;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_publickeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_secretkeybytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_seedbytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_sign_ed25519_bytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_keypair(Span<byte> publicKey, Span<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_seed_keypair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_sk_to_seed(Span<byte> seed, ReadOnlySpan<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_sk_to_pk(Span<byte> publicKey, ReadOnlySpan<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_pk_to_curve25519(Span<byte> x25519PublicKey, ReadOnlySpan<byte> ed25519PublicKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_sk_to_curve25519(Span<byte> x25519PrivateKey, ReadOnlySpan<byte> ed25519PrivateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_detached(Span<byte> signature, out ulong signatureLength, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_ed25519_verify_detached(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> publicKey);
    }
}
