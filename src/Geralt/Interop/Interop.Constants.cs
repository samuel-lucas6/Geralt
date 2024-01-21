using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
#if IOS
        private const string DllName = "__Internal";
#else
        private const string DllName = "libsodium";
#endif
        private const CallingConvention Convention = CallingConvention.Cdecl;
    }
}
