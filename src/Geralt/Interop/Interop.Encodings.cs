using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int sodium_base64_VARIANT_ORIGINAL = 1;
        internal const int sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3;
        internal const int sodium_base64_VARIANT_URLSAFE = 5;
        internal const int sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7;

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial IntPtr sodium_bin2hex(Span<byte> hex, nuint hexMaxLength, ReadOnlySpan<byte> binary, nuint binaryLength);

        [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_hex2bin(Span<byte> binary, nuint binaryMaxLength, ReadOnlySpan<byte> hex, nuint hexLength, string ignoreChars, out nuint binaryLength, string? hexEnd);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial nuint sodium_base64_encoded_len(nuint binaryLength, int variant);

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial IntPtr sodium_bin2base64(Span<byte> base64, nuint base64MaxLength, ReadOnlySpan<byte> binary, nuint binaryLength, int variant);

        [LibraryImport(DllName, StringMarshalling = StringMarshalling.Utf8)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_base642bin(Span<byte> binary, nuint binaryMaxLength, ReadOnlySpan<byte> base64, nuint base64Length, string ignoreChars, out nuint binaryLength, string? base64End, int variant);
    }
}
