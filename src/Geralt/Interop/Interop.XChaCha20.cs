using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_stream_xchacha20_KEYBYTES = 32;
        internal const int crypto_stream_xchacha20_NONCEBYTES = 24;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_stream_xchacha20(Span<byte> ciphertext, ulong ciphertextLength, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_stream_xchacha20_xor_ic(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ulong plaintextLength, ReadOnlySpan<byte> nonce, ulong counter, ReadOnlySpan<byte> key);
    }
}
