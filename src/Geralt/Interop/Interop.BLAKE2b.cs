using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_generichash_BYTES_MIN = 16;
        internal const int crypto_generichash_BYTES = 32;
        internal const int crypto_generichash_BYTES_MAX = 64;
        internal const int crypto_generichash_KEYBYTES_MIN = 16;
        internal const int crypto_generichash_KEYBYTES = 32;
        internal const int crypto_generichash_KEYBYTES_MAX = 64;
        internal const int crypto_generichash_blake2b_SALTBYTES = 16;
        internal const int crypto_generichash_blake2b_PERSONALBYTES = 16;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_generichash_blake2b(byte* hash, nuint hashLength, byte* message, ulong messageLength, byte* key, nuint keyLength);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_generichash_blake2b_salt_personal(byte* hash, nuint hashLength, byte* message, ulong messageLength, byte* key, nuint keyLength, byte* salt, byte* personal);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int crypto_generichash_init(IntPtr state, byte[]? key, nuint keyLength, nuint outputLength);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int crypto_generichash_update(IntPtr state, byte[] message, ulong messageLength);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int crypto_generichash_final(IntPtr state, byte[] hash, nuint hashLength);
        
        [StructLayout(LayoutKind.Explicit, Size = 384)]
        internal struct crypto_generichash_blake2b_state
        {
        }
    }
}