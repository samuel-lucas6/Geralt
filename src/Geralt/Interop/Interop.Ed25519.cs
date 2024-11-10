using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_sign_PUBLICKEYBYTES = 32;
        internal const int crypto_sign_SECRETKEYBYTES = 64;
        internal const int crypto_sign_SEEDBYTES = 32;
        internal const int crypto_sign_BYTES = 64;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_keypair(Span<byte> publicKey, Span<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_seed_keypair(Span<byte> publicKey, Span<byte> privateKey, ReadOnlySpan<byte> seed);

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
        internal static partial int crypto_sign_detached(Span<byte> signature, out ulong signatureLength, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_verify_detached(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> publicKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_init(ref crypto_sign_state state);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_update(ref crypto_sign_state state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_final_create(ref crypto_sign_state state, Span<byte> signature, out ulong signatureLength, ReadOnlySpan<byte> privateKey);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_sign_final_verify(ref crypto_sign_state state, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey);

        [StructLayout(LayoutKind.Explicit, Size = 208)]
        internal struct crypto_sign_state;
    }
}
