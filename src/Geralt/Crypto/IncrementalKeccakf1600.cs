using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Interop.Libsodium;

namespace Geralt;

// The API is done this way to:
// 1. Provide full access to the state (e.g., algorithms like Ascon modify the capacity)
// 2. Support sponge and duplex constructions as well as state feed-forwards
// 3. Aid domain separation (e.g., XOR one byte)
// libsodium doesn't have a function for overwrite mode, but this is uncommon anyway
public sealed class IncrementalKeccakf1600 : IDisposable
{
    public const int StateSize = 200;

    internal const int InternalStateSize = crypto_core_keccak1600_STATEBYTES;
    internal const int AlignmentSize = crypto_core_keccak1600_state_CRYPTO_ALIGN;

    private unsafe void* _state;
    private int _locked;
    private int _disposed;

    public IncrementalKeccakf1600()
    {
        Sodium.Initialize();
        Reinitialize();
    }

    public unsafe void Reinitialize()
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot reinitialize from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalKeccakf1600)); }
            if (_state == null) {
                _state = NativeMemory.AlignedAlloc(InternalStateSize, AlignmentSize);
            }
            crypto_core_keccak1600_init(_state);
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe void XorBytes(ReadOnlySpan<byte> bytes, int offset = 0)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot XOR bytes from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalKeccakf1600)); }
            Validation.BetweenOrEqualTo($"{nameof(offset)}", offset, 0, StateSize - 1);
            Validation.LessThanOrEqualTo($"{nameof(bytes)}.{nameof(bytes.Length)} + {nameof(offset)}", bytes.Length + offset, StateSize);
            crypto_core_keccak1600_xor_bytes(_state, bytes, (nuint)offset, (nuint)bytes.Length);
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe void ExtractBytes(Span<byte> bytes, int offset = 0)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot extract bytes from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalKeccakf1600)); }
            Validation.BetweenOrEqualTo($"{nameof(offset)}", offset, 0, StateSize - 1);
            Validation.LessThanOrEqualTo($"{nameof(bytes)}.{nameof(bytes.Length)} + {nameof(offset)}", bytes.Length + offset, StateSize);
            crypto_core_keccak1600_extract_bytes(_state, bytes, (nuint)offset, (nuint)bytes.Length);
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe void Permute12()
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot permute from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalKeccakf1600)); }
            crypto_core_keccak1600_permute_12(_state);
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe void Permute24()
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot permute from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalKeccakf1600)); }
            crypto_core_keccak1600_permute_24(_state);
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private unsafe void Dispose(bool disposing)
    {
        // Skip for finalizer because finalizers must not throw exceptions
        if (disposing && Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot dispose when another method is locked.");
        }
        try {
            // Only dispose once
            if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 0) != 0) { return; }
            if (_state != null) {
                SecureMemory.ZeroMemory(new Span<byte>(_state, InternalStateSize));
                NativeMemory.AlignedFree(_state);
                _state = null;
            }
        }
        finally {
            if (disposing) {
                Interlocked.Exchange(ref _locked, value: 0);
            }
        }
    }

    ~IncrementalKeccakf1600()
    {
        Dispose(false);
    }
}
