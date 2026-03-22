using System.Runtime.CompilerServices;
using static Interop.Libsodium;

namespace Geralt;

public static class SecureMemory
{
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static unsafe void ZeroMemory(Span<byte> buffer)
    {
        Sodium.Initialize();
        fixed (byte* b = buffer) {
            sodium_memzero(new IntPtr(b), (nuint)buffer.Length);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static unsafe void ZeroMemory(ReadOnlySpan<char> buffer)
    {
        Sodium.Initialize();
        fixed (char* b = buffer) {
            // sizeof(char) because .NET uses UTF-16
            sodium_memzero(new IntPtr(b), (nuint)buffer.Length * sizeof(char));
        }
    }
}
