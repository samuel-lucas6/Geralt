using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const string SODIUM_VERSION_STRING = "1.0.20";
        internal const int SODIUM_LIBRARY_VERSION_MAJOR = 26;
        internal const int SODIUM_LIBRARY_VERSION_MINOR = 2;

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_init();

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern unsafe int sodium_set_misuse_handler(delegate* unmanaged[Cdecl]<void> handler);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_library_version_major();

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_library_version_minor();

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern IntPtr sodium_version_string();
    }
}
