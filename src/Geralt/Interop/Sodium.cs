using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

internal static class Sodium
{
    private static int _initialized;
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Initialize()
    {
        if (_initialized == 0) {
            Init();
        }
    }
    
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static unsafe void Init()
    {
        try
        {
            if (sodium_library_version_major() != SODIUM_LIBRARY_VERSION_MAJOR || sodium_library_version_minor() != SODIUM_LIBRARY_VERSION_MINOR) {
                string? version = Marshal.PtrToStringAnsi(sodium_version_string());
                if (version != null && version != SODIUM_VERSION_STRING) {
                    throw new NotSupportedException($"libsodium v{SODIUM_VERSION_STRING} is required.");
                }
                throw new NotSupportedException($"libsodium v{SODIUM_LIBRARY_VERSION_MAJOR}.{SODIUM_LIBRARY_VERSION_MINOR} is required.");
            }
            
            if (sodium_set_misuse_handler(&MisuseHandlerError) != 0) {
                throw new InvalidOperationException("libsodium set misuse handler error.");
            }
            
            if (sodium_init() < 0) {
                throw new InvalidOperationException("Unable to initialise libsodium.");
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException)
        {
            throw new PlatformNotSupportedException("Unable to access the libsodium DLL. Geralt may not be supported on this platform, or this machine may be missing the Visual C++ Redistributable on Windows.", ex);
        }
        
        Interlocked.Exchange(ref _initialized, value: 1);
    }
    
    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void MisuseHandlerError()
    {
        throw new InvalidOperationException("libsodium misuse error.");
    }
}