using static Interop.Libsodium;

namespace Geralt;

public sealed class GuardedHeapAllocation : IDisposable
{
    // A canary is placed before the data. However, this max size is artificial to limit memory usage
    public static readonly int MaxSize = Environment.SystemPageSize - CANARY_SIZE;
    private IntPtr _pointer;
    private int _size;
    private bool _disposed;

    public GuardedHeapAllocation(int size)
    {
        Validation.SizeBetween(nameof(size), size, 1, MaxSize);
        Sodium.Initialize();
        _pointer = sodium_malloc((nuint)size);
        if (_pointer == IntPtr.Zero) { throw new OutOfMemoryException("Unable to allocate memory."); }
        _size = size;
    }

    public unsafe Span<byte> AsSpan()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        return new Span<byte>((void*)_pointer, _size);
    }

    public void NoAccess()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        int ret = sodium_mprotect_noaccess(_pointer);
        if (ret != 0) { throw new InvalidOperationException("Unable to make memory inaccessible."); }
    }

    public void ReadOnly()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        int ret = sodium_mprotect_readonly(_pointer);
        if (ret != 0) { throw new InvalidOperationException("Unable to make memory read-only."); }
    }

    public void ReadWrite()
    {
        if (_disposed) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        int ret = sodium_mprotect_readwrite(_pointer);
        if (ret != 0) { throw new InvalidOperationException("Unable to make memory readable and writable."); }
    }

    public void Dispose()
    {
        if (_disposed) { return; }
        // This calls sodium_mprotect_readwrite internally
        sodium_free(_pointer);
        _pointer = IntPtr.Zero;
        _size = 0;
        _disposed = true;
    }
}
