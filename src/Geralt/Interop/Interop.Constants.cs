using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        private const string DllName = "libsodium";
        private const CallingConvention Convention = CallingConvention.Cdecl;
    }
}