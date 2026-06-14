using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_generichash_blake2b_STATEBYTES = 384;
        internal const int crypto_generichash_blake2b_STATEBYTES_CRYPTO_ALIGN = 64;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_generichash_blake2b_statebytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_generichash_blake2b_init(void* state, ReadOnlySpan<byte> key, nuint keyLength, nuint hashLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_generichash_blake2b_init_salt_personal(void* state, ReadOnlySpan<byte> key, nuint keyLength, nuint hashLength, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> personalization);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_generichash_blake2b_update(void* state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_generichash_blake2b_final(void* state, Span<byte> hash, nuint hashLength);
    }
}
