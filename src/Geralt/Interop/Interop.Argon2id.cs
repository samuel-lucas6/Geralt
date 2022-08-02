using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_argon2i_ALG_ARGON2I13 = 1;
        internal const int crypto_pwhash_argon2id_ALG_ARGON2ID13 = 2;
        internal const int crypto_pwhash_BYTES_MIN = 16;
        internal const int crypto_pwhash_STRBYTES = 128;
        internal const int crypto_pwhash_STR_HASHBYTES = 32;
        internal const string crypto_pwhash_argon2id_STRPREFIX = "$argon2id$";
        internal const int crypto_pwhash_MEMLIMIT_MIN = 8192;
        internal const long crypto_pwhash_OPSLIMIT_MAX = 4294967295;
        internal const int crypto_pwhash_argon2id_OPSLIMIT_MIN = 1;
        internal const int crypto_pwhash_argon2i_OPSLIMIT_MIN = 3;
        internal const int crypto_pwhash_SALTBYTES = 16;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_pwhash(byte* hash, ulong hashLength, byte* password, ulong passwordLength, byte* salt, ulong iterations, nuint memorySize, int algorithm);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_pwhash_str_alg(byte* hash, byte* password, ulong passwordLength, ulong iterations, nuint memorySize, int algorithm);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_pwhash_str_verify(byte* hash, byte* password, ulong passwordLength);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_pwhash_str_needs_rehash(byte* hash, ulong iterations, nuint memorySize);
    }
}