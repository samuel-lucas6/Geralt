using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe IntPtr sodium_bin2hex(byte* hex, long hexMaxLength, byte* binary, long binaryLength);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_hex2bin(byte[] binary, long binaryMaxLength, string hex, long hexLength, string ignoreChars, out long binaryLength, string? hexEnd);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_base64_encoded_len(long binaryLength, int variant);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe IntPtr sodium_bin2base64(byte* base64, long base64MaxLength, byte* binary, long binaryLength, int variant);
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_base642bin(byte[] binary, long binaryMaxLength, string base64, long base64Length, string ignoreChars, out long binaryLength, string? base64End, int variant);
    }
}