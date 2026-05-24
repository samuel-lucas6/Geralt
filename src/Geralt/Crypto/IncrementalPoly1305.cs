using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Interop.Libsodium;

namespace Geralt;

public sealed class IncrementalPoly1305 : IDisposable
{
    public const int KeySize = Poly1305.KeySize;
    public const int TagSize = Poly1305.TagSize;
    public const int BlockSize = Poly1305.BlockSize;

    private unsafe void* _state;
    private int _locked;
    private int _finalized;
    private int _disposed;

    public IncrementalPoly1305(ReadOnlySpan<byte> oneTimeKey)
    {
        Sodium.Initialize();
        Reinitialize(oneTimeKey);
    }

    public unsafe void Reinitialize(ReadOnlySpan<byte> oneTimeKey)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot reinitialize from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
            Validation.EqualTo($"{nameof(oneTimeKey)}.{nameof(oneTimeKey.Length)}", oneTimeKey.Length, KeySize);
            if (_state == null) {
                _state = NativeMemory.AlignedAlloc(crypto_onetimeauth_poly1305_statebytes, alignment: crypto_onetimeauth_poly1305_statebytes_CRYPTO_ALIGN);
            }
            int ret = crypto_onetimeauth_poly1305_init(_state, oneTimeKey);
            if (ret != 0) { throw new CryptographicException("Error initializing message authentication code state."); }
            _finalized = 0;
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public unsafe void Update(ReadOnlySpan<byte> message)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot update from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
            if (_finalized != 0) { throw new InvalidOperationException("Cannot update after finalizing without reinitializing."); }
            int ret = crypto_onetimeauth_poly1305_update(_state, message, (ulong)message.Length);
            if (ret != 0) { throw new CryptographicException("Error updating message authentication code state."); }
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    public void Finalize(Span<byte> tag)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot finalize from multiple threads simultaneously.");
        }
        try {
            FinalizeInternal(tag);
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    // This method is required to avoid the lock throwing an exception in FinalizeAndVerify()
    private unsafe void FinalizeInternal(Span<byte> tag)
    {
        if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
        if (_finalized != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
        Validation.EqualTo($"{nameof(tag)}.{nameof(tag.Length)}", tag.Length, TagSize);
        int ret = crypto_onetimeauth_poly1305_final(_state, tag);
        if (ret != 0) { throw new CryptographicException("Error finalizing message authentication code."); }
        _finalized = 1;
    }

    public bool FinalizeAndVerify(ReadOnlySpan<byte> tag)
    {
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot finalize and verify from multiple threads simultaneously.");
        }
        try {
            if (_disposed != 0) { throw new ObjectDisposedException(nameof(IncrementalPoly1305)); }
            if (_finalized != 0) { throw new InvalidOperationException("Cannot finalize twice without reinitializing."); }
            Validation.EqualTo($"{nameof(tag)}.{nameof(tag.Length)}", tag.Length, TagSize);
            Span<byte> computedTag = stackalloc byte[TagSize];
            try {
                FinalizeInternal(computedTag);
                return ConstantTime.Equals(tag, computedTag);
            }
            finally {
                SecureMemory.ZeroMemory(computedTag);
            }
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
        if (Interlocked.CompareExchange(ref _locked, value: 1, comparand: 0) != 0) {
            throw new InvalidOperationException("Cannot dispose when another method is locked.");
        }
        try {
            // Only dispose once
            if (Interlocked.CompareExchange(ref _disposed, value: 1, comparand: 0) != 0) { return; }
            if (_state != null) {
                SecureMemory.ZeroMemory(new Span<byte>(_state, crypto_onetimeauth_poly1305_statebytes));
                NativeMemory.AlignedFree(_state);
                _state = null;
            }
        }
        finally {
            Interlocked.Exchange(ref _locked, value: 0);
        }
    }

    ~IncrementalPoly1305()
    {
        Dispose(false);
    }
}
