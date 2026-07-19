using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_core_keccak1600_STATEBYTES = 224;
        internal const int crypto_core_keccak1600_state_CRYPTO_ALIGN = 16;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint crypto_core_keccak1600_statebytes();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial void crypto_core_keccak1600_init(void* state);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial void crypto_core_keccak1600_xor_bytes(void* state, ReadOnlySpan<byte> bytes, nuint offset, nuint bytesLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial void crypto_core_keccak1600_extract_bytes(void* state, Span<byte> bytes, nuint offset, nuint bytesLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial void crypto_core_keccak1600_permute_24(void* state);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial void crypto_core_keccak1600_permute_12(void* state);
    }
}
