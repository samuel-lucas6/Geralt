using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_onetimeauth_KEYBYTES = 32;
        internal const int crypto_onetimeauth_BYTES  = 16;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_onetimeauth(byte* tag, byte* message, ulong messageLength, byte* oneTimeKey);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int crypto_onetimeauth_verify(byte* tag, byte* message, ulong messageLength, byte* oneTimeKey);
    }
}