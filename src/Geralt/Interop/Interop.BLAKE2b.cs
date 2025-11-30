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

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_init(ref crypto_generichash_blake2b_state state, ReadOnlySpan<byte> key, nuint keyLength, nuint hashLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_update(ref crypto_generichash_blake2b_state state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_final(ref crypto_generichash_blake2b_state state, Span<byte> hash, nuint hashLength);

        [StructLayout(LayoutKind.Explicit, Size = 384)]
        internal struct crypto_generichash_blake2b_state;
    }
}
