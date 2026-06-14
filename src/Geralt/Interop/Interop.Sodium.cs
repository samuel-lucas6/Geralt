using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    // Unused constants/functions have been omitted
    internal static partial class Libsodium
    {
        internal const string SODIUM_VERSION_STRING = "1.0.22";

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial IntPtr sodium_version_string();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static partial int sodium_init();

        [LibraryImport(DllName)]
        [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
        internal static unsafe partial int sodium_set_misuse_handler(delegate* unmanaged[Cdecl]<void> handler);
    }
}
