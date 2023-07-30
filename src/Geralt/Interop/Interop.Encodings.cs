using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe IntPtr sodium_bin2hex(byte* hex, nuint hexMaxLength, byte* binary, nuint binaryLength);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_hex2bin(byte[] binary, nuint binaryMaxLength, string hex, nuint hexLength, string ignoreChars, out nuint binaryLength, string? hexEnd);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_base64_encoded_len(nuint binaryLength, int variant);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe IntPtr sodium_bin2base64(byte* base64, nuint base64MaxLength, byte* binary, nuint binaryLength, int variant);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_base642bin(byte[] binary, nuint binaryMaxLength, string base64, nuint base64Length, string ignoreChars, out nuint binaryLength, string? base64End, int variant);
    }
}
