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
        try {
            // libsodium uses a two-tier versioning system:
            // 1. Point releases (e.g., 1.0.21) - new features/significant changes
            // 2. Stable releases (e.g., 26.3) - no new features/breaking changes
            string? pointRelease = Marshal.PtrToStringAnsi(sodium_version_string());
            if (pointRelease == null) {
                throw new InvalidOperationException("Unable to retrieve libsodium version.");
            }
            if (pointRelease != SODIUM_VERSION_STRING) {
                throw new NotSupportedException($"libsodium v{SODIUM_VERSION_STRING} is required for this version of Geralt.");
            }
            // If a function is used incorrectly, sodium_misuse() is called to abort the execution
            // This never happens unless there's a bug in the application/binding (e.g., an output buffer that would cause an overflow)
            // sodium_set_misuse_handler() defines what to do on a panic
            if (sodium_set_misuse_handler(&MisuseHandlerError) != 0) {
                throw new InvalidOperationException("Unable to set libsodium misuse handler.");
            }
            // sodium_init() must be called before any other function
            // It picks the best implementations for the current platform, initializes the random number generator, and generates the canary for guarded heap allocations
            // It returns 0 on success, -1 on failure, and 1 if the library has already been initialized
            if (sodium_init() < 0) {
                throw new InvalidOperationException("Unable to initialize libsodium.");
            }
            Interlocked.Exchange(ref _initialized, value: 1);
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException) {
            throw new PlatformNotSupportedException("Unable to access the libsodium shared library file. Geralt may not be supported on this platform, or this machine may be missing the Visual C++ Redistributable on Windows.", ex);
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void MisuseHandlerError()
    {
        throw new InvalidOperationException("libsodium misuse error. Please create a bug issue on GitHub.");
    }
}
