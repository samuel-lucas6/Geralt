using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const string SODIUM_VERSION_STRING = "1.0.18";
        internal const int SODIUM_LIBRARY_VERSION_MAJOR = 10;
        internal const int SODIUM_LIBRARY_VERSION_MINOR = 3;
        
        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_init();

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_set_misuse_handler(Action handler);

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_library_version_major();

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern int sodium_library_version_minor();

        [DllImport(DllName, CallingConvention = Convention)]
        internal static extern IntPtr sodium_version_string();
    }
}