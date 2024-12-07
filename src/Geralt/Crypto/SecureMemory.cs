using static Interop.Libsodium;

namespace Geralt;

public static class SecureMemory
{
    public static readonly int PageSize = Environment.SystemPageSize;

    public static unsafe void ZeroMemory(Span<byte> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Sodium.Initialize();
        fixed (byte* b = buffer) {
            sodium_memzero(new IntPtr(b), (nuint)buffer.Length);
        }
    }

    public static unsafe void ZeroMemory(ReadOnlySpan<char> buffer)
    {
        Validation.NotEmpty(nameof(buffer), buffer.Length);
        Sodium.Initialize();
        fixed (char* b = buffer) {
            // sizeof(char) because .NET uses UTF-16
            sodium_memzero(new IntPtr(b), (nuint)buffer.Length * sizeof(char));
        }
    }

    public static unsafe void LockMemory(ReadOnlySpan<byte> buffer)
    {
        Validation.MultipleOfSize(nameof(buffer), buffer.Length, PageSize);
        Sodium.Initialize();
        fixed (byte* b = buffer) {
            int ret = sodium_mlock(new IntPtr(b), (nuint)buffer.Length);
            if (ret != 0) { throw new OutOfMemoryException("Unable to lock memory."); }
        }
    }

    public static unsafe void UnlockAndZeroMemory(Span<byte> buffer)
    {
        Validation.MultipleOfSize(nameof(buffer), buffer.Length, PageSize);
        Sodium.Initialize();
        fixed (byte* b = buffer) {
            int ret = sodium_munlock(new IntPtr(b), (nuint)buffer.Length);
            if (ret != 0) { throw new InvalidOperationException("Unable to unlock memory."); }
        }
    }
}
