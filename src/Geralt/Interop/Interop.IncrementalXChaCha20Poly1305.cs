using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_secretstream_xchacha20poly1305_KEYBYTES = 32;
        internal const int crypto_secretstream_xchacha20poly1305_HEADERBYTES = 24;
        internal const int crypto_secretstream_xchacha20poly1305_ABYTES = 17;
        internal const byte crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = 0x00;
        internal const byte crypto_secretstream_xchacha20poly1305_TAG_PUSH = 0x01;
        internal const byte crypto_secretstream_xchacha20poly1305_TAG_REKEY = 0x02;
        internal const byte crypto_secretstream_xchacha20poly1305_TAG_FINAL = 0x03;
        internal const int crypto_secretstream_xchacha20poly1305_statebytes = 52;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_secretstream_xchacha20poly1305_init_push(void* state, Span<byte> header, ReadOnlySpan<byte> key);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_secretstream_xchacha20poly1305_init_pull(void* state, ReadOnlySpan<byte> header, ReadOnlySpan<byte> key);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_secretstream_xchacha20poly1305_push(void* state, Span<byte> ciphertextChunk, out ulong ciphertextChunkLength, ReadOnlySpan<byte> plaintextChunk, ulong plaintextChunkLength, ReadOnlySpan<byte> associatedData, ulong associatedDataLength, byte chunkFlag);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int crypto_secretstream_xchacha20poly1305_pull(void* state, Span<byte> plaintextChunk, out ulong plaintextChunkLength, out byte chunkFlag, ReadOnlySpan<byte> ciphertextChunk, ulong ciphertextChunkLength, ReadOnlySpan<byte> associatedData, ulong associatedDataLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial void crypto_secretstream_xchacha20poly1305_rekey(void* state);
    }
}
