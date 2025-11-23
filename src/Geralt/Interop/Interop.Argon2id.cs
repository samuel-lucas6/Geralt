using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_argon2id_BYTES_MIN = 16;
        internal const int crypto_pwhash_argon2id_SALTBYTES = 16;
        internal const int crypto_pwhash_argon2id_OPSLIMIT_MIN = 1;
        internal const int crypto_pwhash_argon2id_MEMLIMIT_MIN = 8192;
        internal const int crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2;
        internal const int crypto_pwhash_argon2id_STRBYTES = 128;
        internal const string crypto_pwhash_argon2id_STRPREFIX = "$argon2id$";

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash(Span<byte> hash, ulong hashLength, ReadOnlySpan<byte> password, ulong passwordLength, ReadOnlySpan<byte> salt, ulong iterations, nuint memorySize, int algorithm);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash_str_alg(Span<byte> hash, ReadOnlySpan<byte> password, ulong passwordLength, ulong iterations, nuint memorySize, int algorithm);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash_str_verify(Span<byte> hash, ReadOnlySpan<byte> password, ulong passwordLength);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int crypto_pwhash_str_needs_rehash(Span<byte> hash, ulong iterations, nuint memorySize);
    }
}
