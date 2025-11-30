using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_generichash_blake2b_BYTES_MIN = 16;
        internal const int crypto_generichash_blake2b_BYTES = 32;
        internal const int crypto_generichash_blake2b_BYTES_MAX = 64;
        internal const int crypto_generichash_blake2b_KEYBYTES_MIN = 16;
        internal const int crypto_generichash_blake2b_KEYBYTES = 32;
        internal const int crypto_generichash_blake2b_KEYBYTES_MAX = 64;
        internal const int crypto_generichash_blake2b_SALTBYTES = 16;
        internal const int crypto_generichash_blake2b_PERSONALBYTES = 16;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_blake2b(Span<byte> hash, nuint hashLength, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> key, nuint keyLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_blake2b_salt_personal(Span<byte> hash, nuint hashLength, ReadOnlySpan<byte> message, ulong messageLength, ReadOnlySpan<byte> key, nuint keyLength, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> personalization);
    }
}
