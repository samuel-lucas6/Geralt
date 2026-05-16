using static Interop.Libsodium;

namespace Geralt;

public sealed class GuardedHeapAllocation : IDisposable
{
    // A canary is placed before the data. However, this max size is artificial to limit memory usage
    public static readonly int MaxSize = Environment.SystemPageSize - CANARY_SIZE;
    private IntPtr _pointer;
    private int _size;
    private int _disposed;

    public GuardedHeapAllocation(int size)
    {
        Validation.BetweenOrEqualTo(nameof(size), size, 1, MaxSize);
        Sodium.Initialize();
        _pointer = sodium_malloc((nuint)size);
        if (_pointer == IntPtr.Zero) { throw new InsufficientMemoryException("Insufficient memory for guarded heap allocation."); }
        _size = size;
    }

    public unsafe Span<byte> AsSpan()
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        return new Span<byte>((void*)_pointer, _size);
    }

    public void NoAccess()
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        int ret = sodium_mprotect_noaccess(_pointer);
        if (ret != 0) { throw new InvalidOperationException("Error marking memory as inaccessible."); }
    }

    public void ReadOnly()
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        int ret = sodium_mprotect_readonly(_pointer);
        if (ret != 0) { throw new InvalidOperationException("Error marking memory as read-only."); }
    }

    public void ReadWrite()
    {
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 1) != 0) { throw new ObjectDisposedException(nameof(GuardedHeapAllocation)); }
        int ret = sodium_mprotect_readwrite(_pointer);
        if (ret != 0) { throw new InvalidOperationException("Error marking memory as readable and writable."); }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        // If _disposed is 0, set to 1
        if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 0) != 0) { return; }
        if (_pointer != IntPtr.Zero) {
            // This calls sodium_mprotect_readwrite internally
            sodium_free(_pointer);
            _pointer = IntPtr.Zero;
            _size = 0;
        }
    }

    ~GuardedHeapAllocation()
    {
        Dispose(false);
    }
}
