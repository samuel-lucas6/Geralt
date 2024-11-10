internal static partial class Interop
{
    internal static partial class Libsodium
    {
#if IOS || TVOS || MACCATALYST
        private const string DllName = "__Internal";
#elif ANDROID
        private const string DllName = "libsodium.so";
#else
        private const string DllName = "libsodium";
#endif
    }
}
