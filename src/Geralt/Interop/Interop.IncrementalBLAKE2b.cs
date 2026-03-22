using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_generichash_blake2b_statebytes = 384;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_blake2b_init(ref crypto_generichash_blake2b_state state, ReadOnlySpan<byte> key, nuint keyLength, nuint hashLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_blake2b_init_salt_personal(ref crypto_generichash_blake2b_state state, ReadOnlySpan<byte> key, nuint keyLength, nuint hashLength, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> personalization);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_blake2b_update(ref crypto_generichash_blake2b_state state, ReadOnlySpan<byte> message, ulong messageLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_generichash_blake2b_final(ref crypto_generichash_blake2b_state state, Span<byte> hash, nuint hashLength);

        [StructLayout(LayoutKind.Explicit, Size = crypto_generichash_blake2b_statebytes)]
        internal struct crypto_generichash_blake2b_state;
    }
}
